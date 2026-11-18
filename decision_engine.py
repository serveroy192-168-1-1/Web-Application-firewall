"""
WAF Decision Engine.

Combines the Rule-based Engine (regex / OWASP patterns) and the ML Anomaly Detector
(Random Forest / Isolation Forest) into a unified decision pipeline as defined
in WAF_Lab_Architecture.md.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from waf.ml.detector import MLAnomalyDetector, MLVerdict
from waf.rules.cmdi_rules import match_cmdi
from waf.rules.sqli_rules import match_sqli
from waf.rules.traversal_rules import match_traversal
from waf.rules.xss_rules import match_xss


@dataclass
class InspectionResult:
    """Unified WAF Decision Verdict."""
    action: str                     # "BLOCK" | "ALLOW" | "CHALLENGE"
    status_code: int                # 403 if blocked, 200/forward if allowed
    detection_source: str           # "rule" | "ml" | "both" | "none"
    attack_type: str                # e.g., "SQLi", "XSS", "Anomaly", "Benign"
    rule_matches: List[str] = field(default_factory=list)
    ml_score: float = 0.0
    ml_verdict: Optional[MLVerdict] = None
    reason: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "status_code": self.status_code,
            "detection_source": self.detection_source,
            "attack_type": self.attack_type,
            "rule_matches": self.rule_matches,
            "ml_score": round(self.ml_score, 4),
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 3),
        }


class WAFDecisionEngine:
    """
    Coordinating decision engine combining signature rules and ML anomaly scoring.
    Supports operating modes: 'BLOCK', 'DETECT_ONLY', 'CHALLENGE'.
    """

    def __init__(self, mode: str = "BLOCK", ml_threshold: float = 0.50):
        self.mode = mode.upper()
        self.ml_threshold = ml_threshold
        self.ml_detector = MLAnomalyDetector(threshold=ml_threshold)

    def inspect_request(self, req: Dict[str, Any]) -> InspectionResult:
        """
        Inspect incoming request dictionary containing:
        {
            'path': str,
            'method': str,
            'params': dict or list,
            'body': str,
            'headers': dict
        }
        """
        t_start = time.perf_counter()

        # 1. Extract raw combined text for rule engine matching
        path = req.get("path", "")
        params = req.get("params", {})
        body = req.get("body", "")

        param_str = " ".join([f"{k}={v}" for k, v in params.items()]) if isinstance(params, dict) else str(params)
        full_payload = f"{path} {param_str} {body}".strip()

        # 2. Run Rule-Based Engine
        rule_hits = []
        attack_types = []

        sqli_hits = match_sqli(full_payload)
        if sqli_hits:
            rule_hits.extend(sqli_hits)
            attack_types.append("SQLi")

        xss_hits = match_xss(full_payload)
        if xss_hits:
            rule_hits.extend(xss_hits)
            attack_types.append("XSS")

        trav_hits = match_traversal(full_payload)
        if trav_hits:
            rule_hits.extend(trav_hits)
            attack_types.append("PathTraversal")

        cmdi_hits = match_cmdi(full_payload)
        if cmdi_hits:
            rule_hits.extend(cmdi_hits)
            attack_types.append("CMDi/SSRF")

        rule_matched = len(rule_hits) > 0

        # 3. Run ML Anomaly Detector
        ml_verdict = self.ml_detector.inspect(req)
        ml_flagged = ml_verdict.is_anomaly
        ml_score = ml_verdict.score

        # 4. Synthesize Decision
        detection_source = "none"
        reason_parts = []
        is_attack = False

        if rule_matched and ml_flagged:
            detection_source = "both"
            is_attack = True
            reason_parts.append(f"Matched rules: {', '.join(rule_hits[:3])}")
            reason_parts.append(f"ML anomaly score: {ml_score:.2f}")
        elif rule_matched:
            detection_source = "rule"
            is_attack = True
            reason_parts.append(f"Matched rules: {', '.join(rule_hits[:3])}")
        elif ml_flagged:
            detection_source = "ml"
            is_attack = True
            attack_types.append("Anomaly")
            reason_parts.append(f"High ML anomaly probability: {ml_score:.2f}")
            if ml_verdict.top_signals:
                reason_parts.append(f"Signals: {'; '.join(ml_verdict.top_signals[:2])}")
        else:
            detection_source = "none"
            attack_types.append("Benign")
            reason_parts.append("Normal traffic verified")

        attack_type = "/".join(attack_types) if attack_types else "Benign"
        reason = " | ".join(reason_parts)

        # Apply Operating Mode Policy
        if is_attack:
            if self.mode == "BLOCK":
                action = "BLOCK"
                status_code = 403
            elif self.mode == "CHALLENGE":
                action = "CHALLENGE"
                status_code = 401
            else:  # DETECT_ONLY
                action = "ALLOW"
                status_code = 200
        else:
            action = "ALLOW"
            status_code = 200

        total_latency_ms = (time.perf_counter() - t_start) * 1000.0

        return InspectionResult(
            action=action,
            status_code=status_code,
            detection_source=detection_source,
            attack_type=attack_type,
            rule_matches=rule_hits,
            ml_score=ml_score,
            ml_verdict=ml_verdict,
            reason=reason,
            latency_ms=total_latency_ms
        )
