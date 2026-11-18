"""
WAF Reverse Proxy Layer.
Intercepts HTTP requests, runs the Decision Engine (Rules + ML Anomaly Detector),
logs to SQLite, and either blocks (HTTP 403) or forwards to the backend target app.
"""

import os
import sys
from flask import Flask, Response, jsonify, request
import requests

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from waf.decision_engine import WAFDecisionEngine
from waf.logger import WAFLogger

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
WAF_MODE = os.getenv("WAF_MODE", "BLOCK")  # BLOCK | DETECT_ONLY | CHALLENGE

app = Flask(__name__)
engine = WAFDecisionEngine(mode=WAF_MODE, ml_threshold=0.50)
logger = WAFLogger()


def format_blocked_html(result) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>403 Forbidden - Request Blocked by WAF</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .card {{ background: #1e293b; border: 1px solid #ef4444; border-radius: 12px; padding: 2rem; max-width: 600px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }}
        h1 {{ color: #ef4444; margin-top: 0; display: flex; align-items: center; gap: 10px; font-size: 1.5rem; }}
        .badge {{ background: #ef4444; color: white; padding: 3px 8px; border-radius: 6px; font-size: 0.85rem; font-weight: bold; }}
        .detail {{ background: #0f172a; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.9rem; margin: 1rem 0; border: 1px solid #334155; }}
        .row {{ margin-bottom: 0.5rem; }}
        .label {{ color: #94a3b8; }}
        .val {{ color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="card">
        <h1><span>&#9888;</span> 403 Forbidden <span class="badge">WAF INTERCEPT</span></h1>
        <p>Your request has been flagged and blocked by the Web Application Firewall security filter.</p>
        <div class="detail">
            <div class="row"><span class="label">Attack Type:</span> <span class="val">{result.attack_type}</span></div>
            <div class="row"><span class="label">Detection Source:</span> <span class="val">{result.detection_source}</span></div>
            <div class="row"><span class="label">ML Anomaly Score:</span> <span class="val">{result.ml_score:.4f}</span></div>
            <div class="row"><span class="label">Latency Added:</span> <span class="val">{result.latency_ms:.3f} ms</span></div>
            <div class="row"><span class="label">Reason:</span> <span class="val">{result.reason}</span></div>
        </div>
        <small style="color: #64748b;">WAF Reverse Proxy &bull; Machine Learning Anomaly Detector &bull; Powered by scikit-learn</small>
    </div>
</body>
</html>"""


@app.route("/waf/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "mode": engine.mode,
        "ml_threshold": engine.ml_threshold,
        "backend": BACKEND_URL
    })


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy_handler(path):
    # Collect request data for inspection
    raw_body = request.get_data(as_text=True)
    req_data = {
        "path": f"/{path}",
        "method": request.method,
        "params": dict(request.args),
        "body": raw_body,
        "headers": dict(request.headers),
    }

    # Run inspection
    result = engine.inspect_request(req_data)

    # Log event to SQLite database
    logger.log_event(
        src_ip=request.remote_addr or "127.0.0.1",
        method=request.method,
        path=f"/{path}",
        attack_type=result.attack_type,
        detection_source=result.detection_source,
        ml_score=result.ml_score,
        action="blocked" if result.action == "BLOCK" else "allowed",
        latency_ms=result.latency_ms,
        reason=result.reason
    )

    # If blocked, return custom 403 page
    if result.action == "BLOCK":
        return Response(format_blocked_html(result), status=403, mimetype="text/html")

    # Forward request to backend
    target_url = f"{BACKEND_URL.rstrip('/')}/{path}"
    forward_headers = {k: v for k, v in request.headers if k.lower() not in ["host", "content-length"]}

    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10
        )
        return Response(resp.content, resp.status_code, resp.headers.items())
    except requests.exceptions.RequestException as e:
        return Response(f"Backend application unavailable: {str(e)}", status=502)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    print(f"[*] Starting WAF Reverse Proxy on port {port} (Mode: {WAF_MODE})...")
    app.run(host="0.0.0.0", port=port, debug=False)
