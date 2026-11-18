"""
OS Command Injection, SSRF, and XXE Rules and Patterns.
Used for rule-based matching and ML feature extraction.
"""

import re
from typing import List, Tuple

CMDI_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("cmdi_pipe_chain", re.compile(r"([;|`]|&&|\|\|)\s*(cat|ls|dir|whoami|id|uname|nc|netcat|bash|sh|powershell|cmd|curl|wget)\b")),
    ("cmdi_subshell", re.compile(r"\$\([^\)]+\)")),
    ("cmdi_backticks", re.compile(r"`[^`]+`")),
    ("cmdi_redirection", re.compile(r"(>|>>|<|<<)\s*/(dev/tcp|dev/udp|tmp|etc)")),
    ("ssrf_cloud_metadata", re.compile(r"(?i)https?://(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost)")),
    ("ssrf_file_scheme", re.compile(r"(?i)(file|gopher|dict|ldap)://")),
    ("xxe_doctype_entity", re.compile(r"(?i)(<!doctype|<!entity\s+.*system)")),
]

CMDI_KEYWORDS = [
    "whoami", "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
    "cat /etc", "169.254.169.254", "file://", "<!entity",
    "&&", "||", "|", ";", "$(id)", "$(whoami)"
]


def match_cmdi(payload: str) -> List[str]:
    """Check if the payload matches any Command Injection or SSRF/XXE patterns."""
    matches = []
    for rule_name, pattern in CMDI_PATTERNS:
        if pattern.search(payload):
            matches.append(rule_name)
    return matches


def count_cmdi_keywords(payload_lower: str) -> int:
    """Count occurrences of command injection/SSRF keywords in lowercase payload."""
    count = 0
    for kw in CMDI_KEYWORDS:
        if kw in payload_lower:
            count += 1
    return count
