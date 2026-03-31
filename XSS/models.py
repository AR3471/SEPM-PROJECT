"""
XSS Toolkit — In-memory data models and store.
"""

import time
import uuid
import threading


class ScanResult:
    """Represents a single XSS vulnerability finding."""

    def __init__(self, vuln_type, severity, url, field, payload="", screenshot=""):
        self.id = str(uuid.uuid4())
        self.type = vuln_type        # Reflective, DOM, Template, WAF Bypass
        self.severity = severity      # High, Moderate, Low
        self.url = url
        self.field = field
        self.payload = payload
        self.screenshot = screenshot
        self.time = time.strftime("%H:%M:%S")
        self.timestamp = time.time()

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "url": self.url,
            "field": self.field,
            "payload": self.payload,
            "screenshot": self.screenshot,
            "time": self.time,
            "timestamp": self.timestamp,
        }


class Session:
    """Represents a hooked browser C2 session."""

    def __init__(self, ip, user_agent="", cookies=""):
        self.id = str(uuid.uuid4())
        self.ip = ip
        self.user_agent = user_agent
        self.cookies = cookies
        self.time = time.strftime("%H:%M:%S")
        self.timestamp = time.time()
        self.active = True

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "user_agent": self.user_agent,
            "cookies": self.cookies,
            "time": self.time,
            "timestamp": self.timestamp,
            "active": self.active,
        }


class Keystroke:
    """A single captured keystroke from a hooked session."""

    def __init__(self, session_id, ip, key):
        self.session_id = session_id
        self.ip = ip
        self.key = key
        self.time = time.strftime("%H:%M:%S")
        self.timestamp = time.time()

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "ip": self.ip,
            "key": self.key,
            "time": self.time,
            "timestamp": self.timestamp,
        }


class DataStore:
    """Thread-safe in-memory data store (singleton)."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_store()
        return cls._instance

    def _init_store(self):
        self.findings = []          # list[ScanResult]
        self.sessions = []          # list[Session]
        self.keystrokes = []        # list[Keystroke]
        self.scan_logs = []         # list[dict]  — terminal log entries
        self.activity_log = []      # list[dict]  — activity feed entries
        self.stats = {
            "scans": 0,
            "vulns": 0,
            "sessions": 0,
            "blocked": 0,           # WAF bypasses
        }
        self.scan_state = {
            "running": False,
            "progress": 0,
            "label": "",
            "eta": "",
            "target": "",
        }
        self.c2_state = {
            "running": False,
            "host": "127.0.0.1",
            "port": 9000,
            "token": "",
        }
        self.ps_state = {
            "running": False,
            "port": 8080,
        }
        self.lock = threading.Lock()

    # ── Findings ──────────────────────────────────────────────────────────────

    def add_finding(self, result: ScanResult):
        with self.lock:
            self.findings.append(result)
            self.stats["vulns"] = len(self.findings)

    def get_findings(self, vuln_type=None, severity=None):
        with self.lock:
            out = list(self.findings)
        if vuln_type and vuln_type != "all":
            out = [f for f in out if f.type == vuln_type]
        if severity and severity != "all":
            out = [f for f in out if f.severity == severity]
        return out

    def clear_findings(self):
        with self.lock:
            self.findings.clear()
            self.stats["vulns"] = 0

    # ── Sessions ──────────────────────────────────────────────────────────────

    def add_session(self, session: Session):
        with self.lock:
            # Update if same IP already exists
            for s in self.sessions:
                if s.ip == session.ip:
                    s.timestamp = session.timestamp
                    s.time = session.time
                    s.user_agent = session.user_agent or s.user_agent
                    s.cookies = session.cookies or s.cookies
                    s.active = True
                    return s
            self.sessions.append(session)
            self.stats["sessions"] = len(self.sessions)
            return session

    def get_sessions(self):
        with self.lock:
            return list(self.sessions)

    # ── Keystrokes ────────────────────────────────────────────────────────────

    def add_keystroke(self, keystroke: Keystroke):
        with self.lock:
            self.keystrokes.append(keystroke)
            # Cap at 500
            if len(self.keystrokes) > 500:
                self.keystrokes = self.keystrokes[-500:]

    def get_keystrokes(self, session_id=None):
        with self.lock:
            if session_id:
                return [k for k in self.keystrokes if k.session_id == session_id]
            return list(self.keystrokes)

    def clear_keystrokes(self):
        with self.lock:
            self.keystrokes.clear()

    # ── Logs ──────────────────────────────────────────────────────────────────

    def add_log(self, msg, cls="t-info"):
        entry = {"msg": msg, "cls": cls, "time": time.strftime("%H:%M:%S")}
        with self.lock:
            self.scan_logs.append(entry)
            if len(self.scan_logs) > 200:
                self.scan_logs = self.scan_logs[-200:]
        return entry

    def add_activity(self, msg, act_type="info"):
        entry = {"msg": msg, "type": act_type, "time": time.strftime("%H:%M:%S")}
        with self.lock:
            self.activity_log.append(entry)
            if len(self.activity_log) > 100:
                self.activity_log = self.activity_log[-100:]
        return entry

    def get_logs(self, since=0):
        with self.lock:
            return [l for l in self.scan_logs if l.get("_ts", 0) >= since]

    def clear_logs(self):
        with self.lock:
            self.scan_logs.clear()

    def clear_activity(self):
        with self.lock:
            self.activity_log.clear()
