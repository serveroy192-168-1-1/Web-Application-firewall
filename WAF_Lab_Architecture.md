# Web Application Firewall Lab — Complete Architecture

**Author:** Arindam | MBA-Tech Computer Engineering, N-232
**Tech stack:** Linux, Python, OWASP, Docker, Flask, scikit-learn

---

## 1. Objective

Build a reverse-proxy Web Application Firewall (WAF) that inspects incoming HTTP requests in real time, detects common web attacks (SQL Injection, XSS, path traversal, command injection, SSRF/XXE), blocks or logs them per policy, and exposes the results through a monitoring dashboard — evaluated against a deliberately vulnerable target app using real attack-testing tools.

---

## 2. System Architecture Overview

```
                         ┌────────────────────────┐
                         │      Traffic sources     │
                         │  Browser | sqlmap | ZAP   │
                         │  XSStrike | curl scripts  │
                         └────────────┬─────────────┘
                                      │ HTTP/HTTPS
                                      ▼
                    ┌───────────────────────────────────┐
                    │        WAF Reverse Proxy           │
                    │   (Nginx / mitmproxy + Python)     │
                    │                                     │
                    │  ┌───────────────┐ ┌──────────────┐ │
                    │  │ Rule-based    │ │ ML anomaly   │ │
                    │  │ engine        │ │ detector     │ │
                    │  │ (regex/CRS)   │ │ (sklearn)    │ │
                    │  └───────┬───────┘ └──────┬───────┘ │
                    │          └───────┬─────────┘         │
                    │            Decision engine           │
                    └────────┬──────────────────┬──────────┘
                              │                   │
                    Block (403 + log)      Forward request
                              │                   │
                              ▼                   ▼
                    ┌─────────────────┐  ┌──────────────────┐
                    │  Blocked page /  │  │   Backend app     │
                    │  alert trigger   │  │ (DVWA/Juice Shop) │
                    └────────┬─────────┘  └─────────┬────────┘
                              │                       │
                              └──────────┬────────────┘
                                         ▼
                          ┌───────────────────────────┐
                          │  Logging & analytics store  │
                          │     (SQLite / JSON logs)    │
                          └──────────────┬──────────────┘
                                         ▼
                          ┌───────────────────────────┐
                          │  Dashboard + alerting        │
                          │  (Flask/Streamlit, Slack)    │
                          └───────────────────────────┘
```

**Design principle:** the WAF sits as a transparent reverse proxy in front of the vulnerable app — every request the client sends hits the WAF first, never the app directly. This mirrors real-world deployment (Cloudflare, AWS WAF, ModSecurity + Nginx).

---

## 3. Component Breakdown

### 3.1 Reverse Proxy Layer

| Aspect | Detail |
|---|---|
| Options | Nginx + Lua/ngx_http_python, or a pure-Python `mitmproxy` addon, or Flask/FastAPI acting as proxy with `requests`/`httpx` forwarding |
| Recommended for a lab | **Python (Flask/FastAPI) reverse proxy** — full control over request inspection logic, easiest to instrument and extend with ML |
| Responsibilities | Accept inbound request → strip/inspect headers, query params, body → pass to detection engine → forward or block → return response |

```python
# Simplified proxy skeleton
from flask import Flask, request, Response
import requests

app = Flask(__name__)
BACKEND = "http://backend-app:80"

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    verdict, reason = inspect_request(request)
    if verdict == "BLOCK":
        log_event(request, reason, action="blocked")
        return Response("Request blocked by WAF", status=403)
    log_event(request, reason, action="allowed")
    resp = requests.request(
        method=request.method,
        url=f"{BACKEND}/{path}",
        headers={k: v for k, v in request.headers if k != "Host"},
        params=request.args,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
    )
    return Response(resp.content, resp.status_code, resp.headers.items())
```

### 3.2 Detection Engine (two layers, run in parallel, combined score)

**A. Rule-based / signature engine**

- Regex + keyword rule sets per attack class:
  - **SQLi:** `UNION SELECT`, `' OR '1'='1`, `--`, `;--`, `SLEEP(`, stacked queries
  - **XSS:** `<script>`, `onerror=`, `javascript:`, `<img src=x onerror=`
  - **Path traversal:** `../`, `..%2f`, `/etc/passwd`
  - **Command injection:** `;`, `|`, `` ` ``, `$(`, `&&`
  - **XXE/SSRF:** `<!ENTITY`, `file://`, `http://169.254.169.254`
- Optionally load actual **OWASP Core Rule Set (CRS)** rules and adapt them to Python, or run ModSecurity + CRS side-by-side as a benchmark
- Normalize input first: URL-decode (including double-encoding), lowercase, strip whitespace/comments — this is where most naive WAFs fail

**B. ML-based anomaly detector**

- Feature extraction per request:
  - Request length, param count, special-char ratio, entropy of payload
  - Presence of SQL/JS keywords (binary flags, reused from rule engine)
  - Header anomalies (unusual User-Agent, missing headers)
- Model: start with **Logistic Regression** or **Random Forest** (interpretable, fast) — optionally compare with **Isolation Forest** for unsupervised anomaly detection
- Training data: generate synthetic malicious requests (via sqlmap/XSStrike payload lists) + benign traffic (normal app usage) — label and train offline, load the serialized model (`joblib`) into the proxy at runtime

**C. Decision engine**

- Combine both signals: rule match = high-confidence block; ML score above threshold with no rule match = "suspicious" (log + optional block based on mode)
- Configurable operating modes: `DETECT_ONLY`, `BLOCK`, `CHALLENGE`

### 3.3 Backend Target Application

- Deploy a deliberately vulnerable app behind the WAF so attacks have something real to hit:
  - **DVWA** (Damn Vulnerable Web Application) or **OWASP Juice Shop**
- Run in Docker, isolated on an internal network — only reachable through the WAF proxy, not directly exposed

### 3.4 Logging & Analytics Store

- Every request (allowed or blocked) logged with: timestamp, source IP, method, path, matched rule/ML score, action taken, latency added by WAF
- Storage: SQLite for simplicity, or JSON-lines file for easy parsing
- Schema:

```sql
CREATE TABLE waf_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    method TEXT,
    path TEXT,
    attack_type TEXT,
    detection_source TEXT,   -- 'rule' | 'ml' | 'none'
    ml_score REAL,
    action TEXT,             -- 'blocked' | 'allowed'
    latency_ms REAL
);
```

### 3.5 Dashboard & Alerting

- **Flask/Streamlit dashboard** reading from the SQLite store:
  - Attacks blocked over time (line chart)
  - Attack type breakdown (bar chart: SQLi vs XSS vs traversal etc.)
  - Top source IPs
  - False-positive review queue (manually reclassify flagged-but-legit requests)
- **Alerting:** webhook (Slack/Discord) or email (SMTP) fired when a block occurs or when blocked-request rate exceeds a threshold in a time window (basic DoS/scan detection)

### 3.6 Automated Testing & Evaluation Harness

This is what turns the project from "a script that regex-matches" into a measurable security tool.

- **sqlmap** — automated SQLi discovery against the DVWA login/search forms, run through the WAF
- **XSStrike** — XSS payload fuzzing
- **OWASP ZAP** (active scan) — broad automated scan to generate mixed traffic
- Custom Python script sending a labeled dataset of malicious + benign requests to compute:
  - **True positive rate** (attacks correctly blocked)
  - **False positive rate** (legitimate requests wrongly blocked)
  - **Detection latency** (added response time per request)

```python
# Evaluation metrics skeleton
results = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
for req in test_requests:
    verdict = send_through_waf(req)
    if req.is_malicious and verdict == "blocked": results["tp"] += 1
    elif req.is_malicious and verdict == "allowed": results["fn"] += 1
    elif not req.is_malicious and verdict == "blocked": results["fp"] += 1
    else: results["tn"] += 1

precision = results["tp"] / (results["tp"] + results["fp"])
recall = results["tp"] / (results["tp"] + results["fn"])
```

---

## 4. Deployment Architecture (Docker Compose)

```yaml
version: "3.8"
services:
  waf-proxy:
    build: ./waf
    ports:
      - "8080:8080"
    depends_on:
      - backend-app
    networks:
      - waf-net

  backend-app:
    image: vulnerables/web-dvwa
    networks:
      - waf-net          # no external port — only reachable via WAF

  dashboard:
    build: ./dashboard
    ports:
      - "8501:8501"
    volumes:
      - ./data:/data
    networks:
      - waf-net

networks:
  waf-net:
    driver: bridge
```

This single command spins up the whole lab: WAF (public), DVWA (internal-only), and dashboard.

---

## 5. Recommended Folder Structure

```
waf-lab/
├── waf/
│   ├── proxy.py                # reverse proxy + request interception
│   ├── rules/
│   │   ├── sqli_rules.py
│   │   ├── xss_rules.py
│   │   └── traversal_rules.py
│   ├── ml/
│   │   ├── feature_extractor.py
│   │   ├── train_model.py
│   │   └── model.joblib
│   ├── decision_engine.py
│   └── logger.py
├── dashboard/
│   └── app.py                  # Streamlit/Flask dashboard
├── testing/
│   ├── run_sqlmap.sh
│   ├── run_xsstrike.sh
│   └── evaluate.py             # precision/recall harness
├── data/
│   └── waf_logs.db
├── docker-compose.yml
└── README.md
```

---

## 6. Evaluation Plan (for your report)

| Metric | How to measure |
|---|---|
| Detection accuracy | Precision/recall against labeled sqlmap/XSStrike traffic |
| False positive rate | Run normal DVWA usage traffic through WAF, count wrongly blocked |
| Latency overhead | Compare response time with WAF vs direct-to-backend |
| Rule vs ML comparison | Run same test set through rule-only mode and ML-only mode, compare scores |
| Evasion resistance | Test double URL-encoding, case variation, comment-based obfuscation |

---

## 7. Suggested Build Order

1. Backend app (DVWA) running in Docker
2. Basic reverse proxy (pass-through, no detection yet)
3. Rule-based detection engine + blocking
4. Logging to SQLite
5. Dashboard reading logs
6. sqlmap/XSStrike testing against rule-only WAF, record baseline metrics
7. ML anomaly detector trained on collected + synthetic data
8. Combine rule + ML in decision engine, re-run tests, compare metrics
9. Alerting (Slack/email webhook)
10. Dockerize everything, write README + report with metrics tables

This order lets you have a working demo early (step 4) and spend the remaining time on the differentiating features (ML layer, metrics, dashboard) rather than being blocked on infrastructure.
