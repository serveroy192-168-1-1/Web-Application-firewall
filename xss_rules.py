"""
Cross-Site Scripting (XSS) Detection Rules and Patterns.
Used for rule-based matching and ML feature extraction.
"""

import re
from typing import List, Tuple

# Common XSS regex patterns
XSS_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("xss_script_tag", re.compile(r"(?i)<script\b[^>]*>(.*?)</script>|<script\b")),
    ("xss_event_handler", re.compile(r"(?i)\bon(load|error|click|mouseover|focus|blur|change|submit|keydown|keyup|mouseenter)\s*=")),
    ("xss_javascript_pseudo", re.compile(r"(?i)javascript:\s*")),
    ("xss_vbscript_pseudo", re.compile(r"(?i)vbscript:\s*")),
    ("xss_data_uri_html", re.compile(r"(?i)data:\s*text/html")),
    ("xss_img_onerror", re.compile(r"(?i)<img\b[^>]*\bonerror\s*=")),
    ("xss_svg_onload", re.compile(r"(?i)<svg\b[^>]*\bonload\s*=")),
    ("xss_iframe_src", re.compile(r"(?i)<(iframe|frame|object|embed)\b")),
    ("xss_eval_expression", re.compile(r"(?i)\b(eval|alert|prompt|confirm|document\.cookie|window\.location)\s*\(")),
    ("xss_expression_attr", re.compile(r"(?i)style\s*=\s*['\"][^'\"]*expression\s*\(")),
]

# Common XSS / HTML / JS keyword checklist
XSS_KEYWORDS = [
    "<script>", "</script>", "javascript:", "onerror", "onload",
    "alert(", "prompt(", "confirm(", "document.cookie", "eval(",
    "<img", "<svg", "<iframe", "src=", "href=", "style="
]


def match_xss(payload: str) -> List[str]:
    """Check if the payload matches any XSS regex patterns."""
    matches = []
    for rule_name, pattern in XSS_PATTERNS:
        if pattern.search(payload):
            matches.append(rule_name)
    return matches


def count_xss_keywords(payload_lower: str) -> int:
    """Count occurrences of XSS keywords in lowercase payload."""
    count = 0
    for kw in XSS_KEYWORDS:
        if kw in payload_lower:
            count += 1
    return count
