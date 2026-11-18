"""
Runtime ML Anomaly Detector for WAF.

Loads the serialized model bundle (model.joblib) and inspects incoming HTTP
requests in real time with sub-millisecond latency.
"""

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
import joblib
import numpy as np

# Handle path resolution
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
WAF_ROOT = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT = os.path.dirname(WAF_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from waf.ml.feature_extractor import FEATURE_NAMES, FeatureExtractor

DEFAULT_MODEL_PATH = os.path.join(CURRENT_DIR, "model.joblib")


@dataclass
class MLVerdict:
    """Detailed verdict returned by the ML Anomaly Detector."""
    is_anomaly: bool
    score: float
    threshold: float
    decision: str
    latency_ms: float
    isolation_forest_outlier: bool
    top_signals: List[str] = field(default_factory=list)
    feature_values: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_anomaly": self.is_anomaly,
            "score": round(self.score, 4),
            "threshold": self.threshold,
            "decision": self.decision,
            "latency_ms": round(self.latency_ms, 3),
            "isolation_forest_outlier": self.isolation_forest_outlier,
            "top_signals": self.top_signals,
            "feature_values": self.feature_values,
        }


class MLAnomalyDetector:
    """
    Production-ready WAF ML Anomaly Detector.
    Integrates directly with the reverse proxy or decision engine.
    """

    def __init__(self, model_path: Optional[str] = None, threshold: Optional[float] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.extractor = FeatureExtractor()
        self._load_bundle()

        if threshold is not None:
            self.threshold = threshold

    def _load_bundle(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model bundle not found at '{self.model_path}'. "
                f"Please run 'python waf/ml/train_model.py' first to train and serialize the model."
            )

        bundle = joblib.load(self.model_path)
        self.model = bundle["model"]
        self.scaler = bundle.get("scaler")
        self.iso_forest = bundle.get("isolation_forest")

        # Configure single-thread inference to eliminate multiprocessing pool spin-up latency on individual requests
        if hasattr(self.model, "n_jobs"):
            self.model.n_jobs = 1
        if self.iso_forest is not None and hasattr(self.iso_forest, "n_jobs"):
            self.iso_forest.n_jobs = 1

        self.feature_names = bundle.get("feature_names", FEATURE_NAMES)
        self.threshold = bundle.get("threshold", 0.50)
        self.feature_importances = bundle.get("feature_importances", {})
        self.metrics = bundle.get("metrics", {})

    def inspect(self, request_input: Union[str, Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> MLVerdict:
        """
        Inspect an incoming HTTP request or payload.

        Args:
            request_input: Raw string payload OR dict with keys 'path', 'method', 'params', 'body', 'headers'.
            context: Optional context dictionary (headers, param counts).

        Returns:
            MLVerdict containing the anomaly score, decision, latency, and explanation signals.
        """
        t_start = time.perf_counter()

        # Extract features
        if isinstance(request_input, dict) and ("path" in request_input or "headers" in request_input or "params" in request_input):
            feat_dict = self.extractor.extract_from_request_dict(request_input)
        else:
            feat_dict = self.extractor.extract_from_payload(str(request_input), context)

        # Build feature vector
        vector = np.array([[feat_dict[k] for k in self.feature_names]], dtype=np.float32)

        # Supervised probability score (Random Forest)
        proba = self.model.predict_proba(vector)[0]
        # Class 1 is malicious/anomaly
        anomaly_score = float(proba[1]) if len(proba) > 1 else float(proba[0])

        # Isolation forest unsupervised check
        iso_outlier = False
        if self.iso_forest is not None and self.scaler is not None:
            vector_scaled = self.scaler.transform(vector)
            iso_pred = self.iso_forest.predict(vector_scaled)[0]
            iso_outlier = (iso_pred == -1)

        is_anomaly = anomaly_score >= self.threshold or (anomaly_score >= 0.40 and iso_outlier)
        decision = "ANOMALY" if is_anomaly else "BENIGN"

        # Explainability signals
        signals = []
        if feat_dict.get("sqli_pattern_matches", 0) > 0 or feat_dict.get("sqli_keyword_count", 0) >= 2:
            signals.append("High SQL Injection pattern correlation")
        if feat_dict.get("xss_pattern_matches", 0) > 0 or feat_dict.get("xss_keyword_count", 0) >= 2:
            signals.append("High Cross-Site Scripting (XSS) pattern correlation")
        if feat_dict.get("traversal_pattern_matches", 0) > 0 or feat_dict.get("traversal_keyword_count", 0) > 0:
            signals.append("Path Traversal / LFI pattern correlation")
        if feat_dict.get("cmdi_pattern_matches", 0) > 0 or feat_dict.get("cmdi_keyword_count", 0) >= 2:
            signals.append("OS Command Injection / SSRF pattern correlation")
        if feat_dict.get("special_char_ratio", 0) > 0.25:
            signals.append(f"Abnormal special character density ({feat_dict['special_char_ratio'] * 100:.1f}%)")
        if feat_dict.get("shannon_entropy", 0) > 4.2:
            signals.append(f"High information entropy ({feat_dict['shannon_entropy']:.2f})")
        if feat_dict.get("is_double_encoded", 0) == 1.0:
            signals.append("Double URL-encoding evasion technique detected")
        if feat_dict.get("has_null_byte", 0) == 1.0:
            signals.append("Null-byte (%00) evasion pattern detected")
        if feat_dict.get("suspicious_user_agent", 0) == 1.0:
            signals.append("Automated scanner / attack tool User-Agent signature")
        if iso_outlier and not signals:
            signals.append("Unsupervised statistical outlier (Isolation Forest)")

        latency_ms = (time.perf_counter() - t_start) * 1000.0

        return MLVerdict(
            is_anomaly=is_anomaly,
            score=anomaly_score,
            threshold=self.threshold,
            decision=decision,
            latency_ms=latency_ms,
            isolation_forest_outlier=iso_outlier,
            top_signals=signals,
            feature_values=feat_dict
        )
