"""
XSS Toolkit — User authentication and database module.

Uses SQLite for persistent user storage, werkzeug for
secure password hashing, and Gmail SMTP for email verification.

Configure via environment variables:
    XSS_SMTP_EMAIL    — Your Gmail address
    XSS_SMTP_PASSWORD — Gmail App Password (not your main password)
"""

import os
import random
import smtplib
import sqlite3
import string
import time
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xss_users.db")

# SMTP config from environment
SMTP_EMAIL = os.environ.get("XSS_SMTP_EMAIL", "")
SMTP_PASSWORD = os.environ.get("XSS_SMTP_PASSWORD", "")
SMTP_HOST = os.environ.get("XSS_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("XSS_SMTP_PORT", "587"))

_local = threading.local()

# In-memory store for pending verification codes
# Key: email, Value: { code, username, password_hash, expires, email }
_pending_verifications = {}
_pending_lock = threading.Lock()


def _get_conn():
    """Return a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    """Create users table if it doesn't exist; seed default admin."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            email       TEXT    NOT NULL DEFAULT '',
            password    TEXT    NOT NULL,
            role        TEXT    NOT NULL DEFAULT 'user',
            avatar_url  TEXT    NOT NULL DEFAULT '',
            bio         TEXT    NOT NULL DEFAULT '',
            created_at  REAL    NOT NULL,
            last_login  REAL    NOT NULL DEFAULT 0
        )
    """)
    conn.commit()

    # Seed default admin if no users exist
    row = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()
    if row["cnt"] == 0:
        now = time.time()
        conn.execute(
            """INSERT INTO users (username, email, password, role, bio, created_at, last_login)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                "admin",
                "admin@xss-toolkit.local",
                generate_password_hash("admin123"),
                "admin",
                "Default administrator account.",
                now,
                0,
            ),
        )
        conn.commit()
        print("[+] Default admin created  →  admin / admin123")

    # Print SMTP status
    if SMTP_EMAIL and SMTP_PASSWORD:
        print(f"[+] SMTP configured  →  {SMTP_EMAIL}")
    else:
        print("[!] SMTP not configured — email verification disabled")
        print("    Set XSS_SMTP_EMAIL and XSS_SMTP_PASSWORD env vars to enable")


def is_smtp_configured() -> bool:
    """Check whether SMTP credentials are available."""
    return bool(SMTP_EMAIL and SMTP_PASSWORD)


# ── Email verification ────────────────────────────────────────────────────────

def generate_verification_code() -> str:
    """Generate a 6-digit verification code."""
    return "".join(random.choices(string.digits, k=6))


def send_verification_email(to_email: str, code: str) -> bool:
    """Send a verification code email via Gmail SMTP. Returns success."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"XSS Toolkit <{SMTP_EMAIL}>"
        msg["To"] = to_email
        msg["Subject"] = f"🔐 XSS Toolkit — Verification Code: {code}"

        # Plain text fallback
        text = f"""XSS Toolkit — Email Verification

Your verification code is: {code}

This code expires in 10 minutes.
If you didn't request this, please ignore this email.

— XSS Automation Toolkit"""

        # HTML email
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0c10;font-family:Arial,sans-serif;">
  <div style="max-width:480px;margin:40px auto;background:#10141c;border-radius:16px;border:1px solid rgba(255,255,255,0.08);overflow:hidden;">
    <div style="background:linear-gradient(135deg,#ff3b3b,#cc2222);padding:28px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:24px;letter-spacing:2px;">☢ XSS Toolkit</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,0.7);font-size:13px;">Email Verification</p>
    </div>
    <div style="padding:32px 28px;text-align:center;">
      <p style="color:#8892a4;font-size:14px;margin:0 0 24px;">Enter this code to complete your registration:</p>
      <div style="background:#0a0c10;border:2px solid rgba(255,59,59,0.3);border-radius:12px;padding:20px;margin:0 auto;max-width:240px;">
        <span style="font-family:'Courier New',monospace;font-size:36px;font-weight:bold;color:#ff6b6b;letter-spacing:8px;">{code}</span>
      </div>
      <p style="color:#4a5568;font-size:12px;margin:20px 0 0;">Code expires in 10 minutes.</p>
    </div>
    <div style="padding:16px 28px;border-top:1px solid rgba(255,255,255,0.06);text-align:center;">
      <p style="color:#4a5568;font-size:11px;margin:0;">If you didn't request this, ignore this email.</p>
    </div>
  </div>
</body>
</html>"""

        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())

        print(f"[+] Verification email sent to {to_email}")
        return True

    except Exception as e:
        print(f"[!] SMTP error: {e}")
        return False


def store_pending_verification(username: str, email: str, password: str) -> str:
    """Store registration data with a verification code. Returns the code."""
    code = generate_verification_code()
    with _pending_lock:
        # Remove any previous pending for this email
        _pending_verifications[email] = {
            "code": code,
            "username": username,
            "password_hash": generate_password_hash(password),
            "email": email,
            "expires": time.time() + 600,  # 10 minutes
        }
    return code


def verify_code(email: str, code: str) -> dict | None:
    """
    Verify the code and create the user if valid.
    Returns user dict or None.
    """
    with _pending_lock:
        pending = _pending_verifications.get(email)
        if not pending:
            return None
        if pending["code"] != code:
            return None
        if time.time() > pending["expires"]:
            del _pending_verifications[email]
            return None

        # Valid — create the user
        conn = _get_conn()
        try:
            now = time.time()
            cur = conn.execute(
                """INSERT INTO users (username, email, password, role, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (pending["username"], pending["email"], pending["password_hash"], "user", now),
            )
            conn.commit()
            del _pending_verifications[email]
            return get_user_by_id(cur.lastrowid)
        except sqlite3.IntegrityError:
            del _pending_verifications[email]
            return None


def resend_code(email: str) -> str | None:
    """Generate a new code for an existing pending verification."""
    with _pending_lock:
        pending = _pending_verifications.get(email)
        if not pending:
            return None
        new_code = generate_verification_code()
        pending["code"] = new_code
        pending["expires"] = time.time() + 600
        return new_code


def check_username_available(username: str) -> bool:
    """Check if a username is available."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row is None


# ── User helpers ──────────────────────────────────────────────────────────────

def create_user(username: str, email: str, password: str, role: str = "user") -> dict | None:
    """Register a new user directly (no verification). Returns user dict or None on duplicate."""
    conn = _get_conn()
    try:
        now = time.time()
        cur = conn.execute(
            """INSERT INTO users (username, email, password, role, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (username, email, generate_password_hash(password), role, now),
        )
        conn.commit()
        return get_user_by_id(cur.lastrowid)
    except sqlite3.IntegrityError:
        return None


def authenticate(username: str, password: str) -> dict | None:
    """Verify credentials. Returns user dict or None."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row and check_password_hash(row["password"], password):
        # Update last_login
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (time.time(), row["id"]),
        )
        conn.commit()
        return _row_to_dict(row)
    return None


def get_user_by_id(uid: int) -> dict | None:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return _row_to_dict(row) if row else None


def get_user_by_username(username: str) -> dict | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return _row_to_dict(row) if row else None


def update_profile(uid: int, email: str = None, bio: str = None, avatar_url: str = None) -> dict | None:
    """Update mutable profile fields."""
    conn = _get_conn()
    fields, vals = [], []
    if email is not None:
        fields.append("email = ?"); vals.append(email)
    if bio is not None:
        fields.append("bio = ?"); vals.append(bio)
    if avatar_url is not None:
        fields.append("avatar_url = ?"); vals.append(avatar_url)
    if not fields:
        return get_user_by_id(uid)
    vals.append(uid)
    conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", vals)
    conn.commit()
    return get_user_by_id(uid)


def change_password(uid: int, old_password: str, new_password: str) -> bool:
    """Change password after verifying current one. Returns success."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row or not check_password_hash(row["password"], old_password):
        return False
    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (generate_password_hash(new_password), uid),
    )
    conn.commit()
    return True


def _row_to_dict(row) -> dict:
    """Convert sqlite3.Row to a safe dict (no password hash)."""
    d = dict(row)
    d.pop("password", None)
    return d
