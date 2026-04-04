"""
XSS Toolkit — User authentication and database module.

Uses SQLite for persistent user storage, werkzeug for
secure password hashing, and Gmail SMTP for email verification.

Configure via environment variables:
    XSS_SMTP_EMAIL    — Your Gmail address
    XSS_SMTP_PASSWORD — Gmail App Password (not your main password)
"""

import os
import sqlite3
import time
import threading
from werkzeug.security import generate_password_hash, check_password_hash

from config import config

DB_PATH = config.DB_PATH

# SMTP config — pulled from centralised config
SMTP_EMAIL = config.SMTP_EMAIL
SMTP_PASSWORD = config.SMTP_PASSWORD
SMTP_HOST = config.SMTP_HOST
SMTP_PORT = config.SMTP_PORT

_local = threading.local()


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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id          TEXT PRIMARY KEY,
            type        TEXT,
            severity    TEXT,
            url         TEXT,
            field       TEXT,
            payload     TEXT,
            screenshot  TEXT,
            time        TEXT,
            timestamp   REAL,
            user_id     TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            msg         TEXT,
            type        TEXT,
            time        TEXT,
            user_id     TEXT
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
    print("[!] Email verification disabled — SMTP support removed")


def is_smtp_configured() -> bool:
    """Always false because SMTP email verification is removed."""
    return False


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
