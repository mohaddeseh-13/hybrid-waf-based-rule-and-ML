from flask import Flask, request, Response, send_file
import requests
from urllib.parse import unquote
import os

from core.engine import HybridEngine
from app.config import BACKEND_URL
from app.dashboard_api import dashboard_api

app = Flask(__name__)

app.register_blueprint(dashboard_api, url_prefix="/dashboard")

engine = HybridEngine()


# ───── Dashboard HTML ─────
@app.route("/waf-dashboard")
def dashboard():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dashboard_path = os.path.join(base_dir, "..", "dashboard", "dashboard.html")
    return send_file(os.path.abspath(dashboard_path))


# ───── Proxy (باید آخر باشه) ─────
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):

    # جمع‌آوری کامل Payload (Path + Query + Body)
    decoded_path = unquote(path)
    query_string = unquote(request.query_string.decode())
    query_params = " ".join(f"{k}={v}" for k, v in request.args.items())
    body = request.get_data(as_text=True)

    payload = " ".join([
        decoded_path,
        query_string,
        query_params,
        body
    ])

    # تصمیم گیری (Hybrid WAF)
    result = engine.inspect(payload, source_ip=request.remote_addr)

    if result["action"] == "BLOCK":
        return Response(
            f"Blocked by WAF: {result['reason']}",
            status=403,
            mimetype="text/plain"
        )

    # Forward به Backend (ایمن)
    target_url = f"{BACKEND_URL}/{path}"

    try:
        backend_response = requests.request(
            method=request.method,
            url=target_url,
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            verify=False,   # فقط برای تست HTTPS
            timeout=3
        )
    except requests.exceptions.RequestException:
        return Response(
            "Backend is unavailable",
            status=502,
            mimetype="text/plain"
        )

    return Response(
        backend_response.content,
        status=backend_response.status_code,
        headers=list(backend_response.headers.items())
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
