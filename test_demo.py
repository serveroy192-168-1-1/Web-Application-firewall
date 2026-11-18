import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from waf.decision_engine import WAFDecisionEngine

def run_tests():
    engine = WAFDecisionEngine(mode="BLOCK", ml_threshold=0.50)

    test_cases = [
        {
            "name": "Benign Search Request",
            "req": {
                "path": "/products/search",
                "method": "GET",
                "params": {"query": "wireless keyboard", "page": "1"},
                "headers": {"User-Agent": "Mozilla/5.0"}
            }
        },
        {
            "name": "SQL Injection Attack",
            "req": {
                "path": "/vulnerabilities/sqli/",
                "method": "GET",
                "params": {"id": "1' UNION SELECT null, username, password FROM users--"},
                "headers": {"User-Agent": "Mozilla/5.0"}
            }
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "req": {
                "path": "/comment",
                "method": "POST",
                "body": "comment=<script>alert('XSS')</script>",
                "headers": {"User-Agent": "Mozilla/5.0"}
            }
        },
        {
            "name": "Path Traversal / LFI",
            "req": {
                "path": "/download.php",
                "method": "GET",
                "params": {"file": "../../../../etc/passwd"},
                "headers": {"User-Agent": "Mozilla/5.0"}
            }
        },
        {
            "name": "Automated Scanner (sqlmap)",
            "req": {
                "path": "/api/users",
                "method": "GET",
                "params": {"id": "1 AND 1=1"},
                "headers": {"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}
            }
        }
    ]

    print("=" * 70)
    print("      END-TO-END WAF DECISION & ML MODEL VERIFICATION")
    print("=" * 70)

    for case in test_cases:
        result = engine.inspect_request(case["req"])
        print(f"\n[Test] {case['name']}")
        print(f"  Target:    {case['req']['path']}")
        print(f"  Action:    {result.action} (HTTP {result.status_code})")
        print(f"  Detection: {result.detection_source} | Attack Type: {result.attack_type}")
        print(f"  ML Score:  {result.ml_score:.4f} | Latency: {result.latency_ms:.3f} ms")
        print(f"  Reason:    {result.reason}")

if __name__ == "__main__":
    run_tests()
