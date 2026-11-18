"""
Path Traversal and Local/Remote File Inclusion (LFI/RFI) Rules and Patterns.
Used for rule-based matching and ML feature extraction.
"""

import re
from typing import List, Tuple

TRAVERSAL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("traversal_dot_dot_slash", re.compile(r"(\.\./|\.\.\\)")),
    ("traversal_url_encoded_dot_dot", re.compile(r"(%2e%2e[%2f%5c]|\.\.%2f|\.\.%5c|%2e%2e/)")),
    ("traversal_double_encoded", re.compile(r"(%252e%252e|%252f|%255c)")),
    ("traversal_etc_passwd", re.compile(r"(?i)(/etc/(passwd|shadow|hosts|group|issue))")),
    ("traversal_proc_self", re.compile(r"(?i)/proc/(self|version|cpuinfo|environ|cmdline)")),
    ("traversal_windows_sys", re.compile(r"(?i)(windows[\\/]system32|boot\.ini|win\.ini)")),
    ("traversal_null_byte", re.compile(r"(%00|\\x00)")),
]

TRAVERSAL_KEYWORDS = [
    "../", "..\\", "/etc/passwd", "/etc/shadow", "win.ini",
    "boot.ini", "system32", "%2e%2e", "%252e", "/proc/self"
]


def match_traversal(payload: str) -> List[str]:
    """Check if the payload matches any Path Traversal regex patterns."""
    matches = []
    for rule_name, pattern in TRAVERSAL_PATTERNS:
        if pattern.search(payload):
            matches.append(rule_name)
    return matches


def count_traversal_keywords(payload_lower: str) -> int:
    """Count occurrences of path traversal keywords in lowercase payload."""
    count = 0
    for kw in TRAVERSAL_KEYWORDS:
        if kw in payload_lower:
            count += 1
    return count
