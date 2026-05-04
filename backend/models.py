"""
XSS Toolkit — In-memory data models and store.
"""

import time
import uuid
import threading

from db import _get_conn


class ScanResult:
    """Represents a single XSS vulnerability finding."""

    def __init__(self, vuln_type, severity, url, field, payload="", screenshot="", user_id=None):
        self.id = str(uuid.uuid4())
        self.type = vuln_type        # Reflective, DOM, Template, WAF Bypass
        self.severity = severity      # High, Moderate, Low
        self.url = url
        self.field = field
        self.payload = payload
        self.screenshot = screenshot
        self.user_id = str(user_id) if user_id is not None else None
        self.time = time.strftime("%H:%M:%S")
        self.timestamp = time.time()

    def to_dict(self):
        data = {
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
        if self.user_id is not None:
            data["user_id"] = self.user_id
        return data


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

    findings = None
    sessions = None
    keystrokes = None
    scan_logs = None
    activity_log = None
    stats = None
    scan_state = None
    c2_state = None
    ps_state = None
    lock = None

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if getattr(self, '_initialized', False):
            return
        self._init_store()
        self._initialized = True

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

        self._load_persisted_data()
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

    # ── Persistence helpers ───────────────────────────────────────────────────

    def _load_persisted_data(self):
        # Only load persisted user data from SQLite after tables are initialized.
        try:
            conn = _get_conn()
            # Findings
            cur = conn.execute("SELECT * FROM findings")
            rows = cur.fetchall()
            self.findings = []
            for row in rows:
                f = ScanResult(
                    vuln_type=row["type"],
                    severity=row["severity"],
                    url=row["url"],
                    field=row["field"],
                    payload=row["payload"],
                    screenshot=row["screenshot"],
                    user_id=row["user_id"],
                )
                f.id = row["id"]
                f.time = row["time"]
                f.timestamp = row["timestamp"]
                self.findings.append(f)
            self.stats["vulns"] = len(self.findings)

            # Activity
            cur = conn.execute("SELECT * FROM activity ORDER BY id")
            rows = cur.fetchall()
            self.activity_log = [
                {"msg": r["msg"], "type": r["type"], "time": r["time"], "user_id": r["user_id"]}
                for r in rows
            ]
        except Exception:
            # If DB is not available yet, keep in-memory defaults
            pass

    def _persist_finding(self, result: ScanResult):
        conn = _get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, type, severity, url, field, payload, screenshot, time, timestamp, user_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.id,
                result.type,
                result.severity,
                result.url,
                result.field,
                result.payload,
                result.screenshot,
                result.time,
                result.timestamp,
                result.user_id,
            ),
        )
        conn.commit()

    def _persist_activity(self, entry: dict):
        conn = _get_conn()
        conn.execute(
            """INSERT INTO activity (msg, type, time, user_id)
               VALUES (?, ?, ?, ?)""",
            (entry["msg"], entry["type"], entry["time"], entry.get("user_id")),
        )
        conn.commit()

    # ── Findings ──────────────────────────────────────────────────────────────

    def add_finding(self, result: ScanResult):
        with self.lock:
            self.findings.append(result)
            self.stats["vulns"] = len(self.findings)
            self._persist_finding(result)

    def get_findings(self, user_id=None, vuln_type=None, severity=None):
        with self.lock:
            out = list(self.findings)

        if user_id is not None:
            # Show user-specific findings and legacy/generic results with no user_id.
            out = [
                f for f in out
                if f.user_id is None or str(f.user_id) == str(user_id)
            ]
        if vuln_type and vuln_type != "all":
            out = [f for f in out if f.type == vuln_type]
        if severity and severity != "all":
            out = [f for f in out if f.severity == severity]
        return out

    def clear_findings(self, user_id=None):
        with self.lock:
            if user_id is None:
                self.findings.clear()
            else:
                self.findings = [f for f in self.findings if str(f.user_id) != str(user_id)]
            self.stats["vulns"] = len(self.findings)

        conn = _get_conn()
        if user_id is None:
            conn.execute("DELETE FROM findings")
        else:
            conn.execute("DELETE FROM findings WHERE user_id = ?", (str(user_id),))
        conn.commit()

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

    def add_activity(self, msg, act_type="info", user_id=None):
        entry = {
            "msg": msg,
            "type": act_type,
            "time": time.strftime("%H:%M:%S"),
            "user_id": str(user_id) if user_id is not None else None,
        }
        with self.lock:
            self.activity_log.append(entry)
            if len(self.activity_log) > 100:
                self.activity_log = self.activity_log[-100:]

        self._persist_activity(entry)
        return entry

    def get_activity(self, user_id=None):
        with self.lock:
            if user_id is None:
                return list(self.activity_log)
            return [a for a in self.activity_log if str(a.get("user_id")) == str(user_id)]

    def get_logs(self, since=0):
        with self.lock:
            return [l for l in self.scan_logs if l.get("_ts", 0) >= since]

    def clear_logs(self):
        with self.lock:
            self.scan_logs.clear()

    def clear_activity(self, user_id=None):
        with self.lock:
            if user_id is None:
                self.activity_log.clear()
            else:
                self.activity_log = [a for a in self.activity_log if str(a.get("user_id")) != str(user_id)]

        conn = _get_conn()
        if user_id is None:
            conn.execute("DELETE FROM activity")
        else:
            conn.execute("DELETE FROM activity WHERE user_id = ?", (str(user_id),))
        conn.commit()
