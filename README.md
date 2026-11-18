# Web Application Firewall (WAF) with ML Anomaly Detector

A dual-engine Web Application Firewall reverse proxy combining regex-based signature detection (OWASP CRS rules) and a machine learning anomaly detector (Random Forest & Isolation Forest) implemented in Python.

![Architecture](C:/Users/Parth/.gemini/antigravity/brain/98ac59f4-c241-4901-b46e-5b3afad34796/.user_uploaded/media_1788809573649.png)

---

## 1. Project Layout

```
d:/WAF/
├── waf/
│   ├── rules/                       # Rule-based Engine (Regex signatures)
│   │   ├── sqli_rules.py            # SQL Injection patterns
│   │   ├── xss_rules.py             # XSS & HTML injection patterns
│   │   ├── traversal_rules.py       # Path traversal & LFI/RFI patterns
│   │   └── cmdi_rules.py            # OS Command injection & SSRF/XXE patterns
│   ├── ml/                          # Machine Learning Anomaly Detection
│   │   ├── feature_extractor.py     # Multi-dimensional feature extractor
│   │   ├── dataset.py               # Synthetic training dataset generator
│   │   ├── train_model.py           # Training pipeline (Random Forest + Iso Forest)
│   │   ├── detector.py              # Runtime ML Anomaly Detector
│   │   ├── evaluate.py              # Benchmark & validation suite
│   │   └── model.joblib             # Serialized trained model bundle
│   ├── decision_engine.py           # Combines Rules + ML into unified verdict
│   ├── logger.py                    # SQLite event logger
│   ├── proxy.py                     # Flask-based transparent reverse proxy
│   └── test_demo.py                 # Quick verification demo script
├── dashboard/
│   └── app.py                       # Streamlit security operations dashboard
├── data/
│   └── waf_logs.db                  # SQLite event store
└── WAF_Lab_Architecture.md          # Architecture specification
```

---

## 2. ML Anomaly Detector Specifications

### Features Extracted (`waf/ml/feature_extractor.py`)
- **Statistical Features**: Raw string length, decoded length, query parameter count, maximum parameter length.
- **Character Distribution**: Special character ratio, security punctuation counts (`'`, `"`, `;`, `<`, `>`, `(`, `)`, `=`, `-`, `/`, `\`, `|`, `&`, `$`, `%`, `{`, `}`), digit ratio, non-ASCII count.
- **Information Entropy**: Shannon entropy calculation (\(H(X) = -\sum P(x) \log_2 P(x)\)) to detect shellcode, hex/base64 encoded payloads, and obfuscation.
- **Security Pattern Flags**: Pattern matches and keyword counts for SQLi, XSS, Path Traversal, and Command Injection / SSRF.
- **Header Anomaly Indicators**: Automated vulnerability scanner User-Agents (`sqlmap`, `nikto`, `zap`, `burp`, `python-requests`), missing standard headers.
- **Evasion Normalization**: Multi-layer recursive URL decoding (defeating `%2527` double-encoding) and null-byte detection.

### Models Trained (`waf/ml/train_model.py`)
1. **Random Forest Classifier**: Primary supervised model (`n_estimators=120`, `max_depth=16`).
   - Test Accuracy: **99.68%**
   - Precision: **100.00%**
   - Recall: **99.36%**
   - ROC-AUC: **1.0000**
   - False Positive Rate: **0.00%**
2. **Isolation Forest**: Unsupervised statistical outlier detector for anomaly scoring.
3. **Serialized Bundle**: `waf/ml/model.joblib`.

---

## 3. Quick Start & Execution

### Train the ML Model
```powershell
python waf/ml/train_model.py --samples 5000
```

### Run Model Evaluation & Benchmarking
```powershell
python waf/ml/evaluate.py
```

### Run End-to-End Decision Engine Verification
```powershell
python waf/test_demo.py
```

### Start the Reverse Proxy
```powershell
# Set backend URL if running DVWA/Juice Shop:
# $env:BACKEND_URL="http://localhost:8000"
python waf/proxy.py
```

### Launch the Security Operations Dashboard
```powershell
streamlit run dashboard/app.py
```
