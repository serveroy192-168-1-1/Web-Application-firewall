"""
SQL Injection Detection Rules and Patterns.
Used for rule-based matching and ML feature extraction.
"""

import re
from typing import List, Tuple

# Common SQL injection regex patterns
SQLI_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("sqli_union_select", re.compile(r"(?i)\bunion\s+(all\s+)?select\b")),
    ("sqli_boolean_or", re.compile(r"(?i)('\s*or\s*['\d\w]+\s*=\s*['\d\w]+|\b(or|and)\s+\d+=\d+)")),
    ("sqli_comment_dash", re.compile(r"(--|#|/\*.*?\*/)")),
    ("sqli_sleep_benchmark", re.compile(r"(?i)\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(")),
    ("sqli_stacked_queries", re.compile(r"(?i);\s*(drop|insert|update|delete|create|alter|truncate)\b")),
    ("sqli_error_based", re.compile(r"(?i)\b(extractvalue|updatexml|floor\s*\(\s*rand|exp\s*\(|geometrycollection)\b")),
    ("sqli_information_schema", re.compile(r"(?i)\b(information_schema|sys\.tables|sqlite_master|v\$session)\b")),
    ("sqli_tautology", re.compile(r"(?i)\b(1=1|'1'='1'|\"1\"=\"1\"|'a'='a'|true\b)")),
    ("sqli_concat_hex", re.compile(r"(?i)\b(0x[0-9a-f]+|char\s*\(\s*\d+|concat\s*\()")),
    ("sqli_order_by_num", re.compile(r"(?i)\border\s+by\s+\d{1,4}\b")),
]

# Quick keyword checklist for token-level checks
SQLI_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop",
    "table", "from", "where", "information_schema", "sleep",
    "benchmark", "waitfor", "delay", "order by", "group by",
    "having", "exec", "declare", "cast", "convert"
]


def match_sqli(payload: str) -> List[str]:
    """Check if the payload matches any SQLi regex patterns."""
    matches = []
    for rule_name, pattern in SQLI_PATTERNS:
        if pattern.search(payload):
            matches.append(rule_name)
    return matches


def count_sqli_keywords(payload_lower: str) -> int:
    """Count occurrences of SQL injection keywords in lowercase payload."""
    count = 0
    for kw in SQLI_KEYWORDS:
        if kw in payload_lower:
            count += 1
    return count
