"""
Feature Extractor for WAF ML Anomaly Detection.

Extracts statistical, character-distribution, payload entropy,
security pattern, and header anomaly features from incoming HTTP requests.
"""

import math
import re
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional, Union
import numpy as np

# Import rule patterns
try:
    from waf.rules.sqli_rules import match_sqli, count_sqli_keywords
    from waf.rules.xss_rules import match_xss, count_xss_keywords
    from waf.rules.traversal_rules import match_traversal, count_traversal_keywords
    from waf.rules.cmdi_rules import match_cmdi, count_cmdi_keywords
except ImportError:
    from ..rules.sqli_rules import match_sqli, count_sqli_keywords
    from ..rules.xss_rules import match_xss, count_xss_keywords
    from ..rules.traversal_rules import match_traversal, count_traversal_keywords
    from ..rules.cmdi_rules import match_cmdi, count_cmdi_keywords

# Common security sensitive punctuation characters
SECURITY_PUNCTUATION = set("'\";<>()=-/\\|&$%{}[]*!^#+`~@:")

# Known automated security scanner / exploit User-Agent signatures
SCANNER_UA_SUBSTRINGS = [
    "sqlmap", "nikto", "wpscan", "zaproxy", "zap", "nmap",
    "masscan", "gobuster", "dirbuster", "burpcollaborator",
    "burp", "acunetix", "nessus", "openvas", "havij",
    "python-requests", "curl/", "libwww-perl", "scrapy"
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per symbol) of a string."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def recursive_url_decode(s: str, max_depth: int = 3) -> str:
    """Recursively decode URL-encoded strings to defeat double-encoding evasion."""
    current = s
    for _ in range(max_depth):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


FEATURE_NAMES = [
    "length_raw",
    "length_decoded",
    "param_count",
    "max_param_length",
    "special_char_ratio",
    "punctuation_count",
    "digit_ratio",
    "shannon_entropy",
    "sqli_keyword_count",
    "sqli_pattern_matches",
    "xss_keyword_count",
    "xss_pattern_matches",
    "traversal_keyword_count",
    "traversal_pattern_matches",
    "cmdi_keyword_count",
    "cmdi_pattern_matches",
    "has_sql_or_js_flag",
    "is_double_encoded",
    "has_null_byte",
    "suspicious_user_agent",
    "missing_standard_headers",
    "non_ascii_count",
]


class FeatureExtractor:
    """
    Extracts security and statistical features from HTTP requests or payloads.
    """

    def __init__(self):
        self.feature_names = FEATURE_NAMES

    def extract_from_payload(self, payload: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
        """
        Extract features from a single payload or query string, optionally
        supplemented by request context (e.g. headers, method, param count).
        """
        if payload is None:
            payload = ""

        context = context or {}
        headers = context.get("headers", {})
        param_count = float(context.get("param_count", 1 if payload else 0))
        max_param_len = float(context.get("max_param_length", len(payload)))

        raw_str = str(payload)
        is_double_encoded = 1.0 if "%25" in raw_str.lower() else 0.0
        has_null_byte = 1.0 if ("%00" in raw_str.lower() or "\x00" in raw_str) else 0.0

        decoded_str = recursive_url_decode(raw_str)
        lower_str = decoded_str.lower()

        len_raw = len(raw_str)
        len_decoded = len(decoded_str)

        # Character distributions
        if len_decoded > 0:
            special_count = sum(1 for c in decoded_str if not c.isalnum() and not c.isspace())
            special_ratio = round(special_count / len_decoded, 4)
            digit_count = sum(1 for c in decoded_str if c.isdigit())
            digit_ratio = round(digit_count / len_decoded, 4)
            punct_count = sum(1 for c in decoded_str if c in SECURITY_PUNCTUATION)
            non_ascii = sum(1 for c in decoded_str if ord(c) > 127)
        else:
            special_ratio = 0.0
            digit_ratio = 0.0
            punct_count = 0
            non_ascii = 0

        entropy = shannon_entropy(decoded_str)

        # Rule and keyword hits
        sqli_kw = count_sqli_keywords(lower_str)
        sqli_patterns = len(match_sqli(decoded_str))

        xss_kw = count_xss_keywords(lower_str)
        xss_patterns = len(match_xss(decoded_str))

        trav_kw = count_traversal_keywords(lower_str)
        trav_patterns = len(match_traversal(decoded_str))

        cmdi_kw = count_cmdi_keywords(lower_str)
        cmdi_patterns = len(match_cmdi(decoded_str))

        has_sql_or_js = 1.0 if (sqli_kw > 0 or sqli_patterns > 0 or xss_kw > 0 or xss_patterns > 0) else 0.0

        # Header analysis
        user_agent = ""
        for k, v in headers.items():
            if k.lower() == "user-agent":
                user_agent = str(v).lower()
                break

        suspicious_ua = 0.0
        for sig in SCANNER_UA_SUBSTRINGS:
            if sig in user_agent:
                suspicious_ua = 1.0
                break

        # Check standard headers (Host, User-Agent, Accept)
        std_headers = {"host", "user-agent", "accept"}
        present_headers = {k.lower() for k in headers.keys()} if headers else std_headers
        missing_headers_count = len(std_headers - present_headers)

        features = {
            "length_raw": float(len_raw),
            "length_decoded": float(len_decoded),
            "param_count": param_count,
            "max_param_length": max_param_len,
            "special_char_ratio": special_ratio,
            "punctuation_count": float(punct_count),
            "digit_ratio": digit_ratio,
            "shannon_entropy": entropy,
            "sqli_keyword_count": float(sqli_kw),
            "sqli_pattern_matches": float(sqli_patterns),
            "xss_keyword_count": float(xss_kw),
            "xss_pattern_matches": float(xss_patterns),
            "traversal_keyword_count": float(trav_kw),
            "traversal_pattern_matches": float(trav_patterns),
            "cmdi_keyword_count": float(cmdi_kw),
            "cmdi_pattern_matches": float(cmdi_patterns),
            "has_sql_or_js_flag": has_sql_or_js,
            "is_double_encoded": is_double_encoded,
            "has_null_byte": has_null_byte,
            "suspicious_user_agent": suspicious_ua,
            "missing_standard_headers": float(missing_headers_count),
            "non_ascii_count": float(non_ascii),
        }
        return features

    def extract_from_request_dict(self, req: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract features from a normalized request dictionary:
        {
            'path': str,
            'method': str,
            'params': dict or list,
            'body': str,
            'headers': dict
        }
        """
        path = req.get("path", "")
        params = req.get("params", {})
        body = req.get("body", "")
        headers = req.get("headers", {})

        # Flatten query parameters and body values into combined inspection payload
        parts = [path]
        param_values = []

        if isinstance(params, dict):
            for k, v in params.items():
                val_str = str(v)
                parts.append(f"{k}={val_str}")
                param_values.append(val_str)
            param_count = len(params)
        elif isinstance(params, list):
            for item in params:
                val_str = str(item)
                parts.append(val_str)
                param_values.append(val_str)
            param_count = len(params)
        else:
            param_str = str(params)
            parts.append(param_str)
            param_values.append(param_str)
            param_count = 1 if param_str else 0

        if body:
            body_str = str(body)
            parts.append(body_str)
            param_values.append(body_str)

        combined_payload = " ".join(parts)
        max_param_length = max([len(p) for p in param_values]) if param_values else len(path)

        context = {
            "headers": headers,
            "param_count": param_count,
            "max_param_length": max_param_length,
        }

        return self.extract_from_payload(combined_payload, context)

    def extract_vector(self, payload_or_req: Union[str, Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """
        Returns feature vector as 1D numpy array aligned with FEATURE_NAMES.
        """
        if isinstance(payload_or_req, dict) and ("path" in payload_or_req or "headers" in payload_or_req or "params" in payload_or_req):
            feat_dict = self.extract_from_request_dict(payload_or_req)
        else:
            feat_dict = self.extract_from_payload(str(payload_or_req), context)

        return np.array([feat_dict[name] for name in self.feature_names], dtype=np.float32)
