"""
XSS Toolkit — Centralised configuration.

Uses environment variables with sensible defaults.
Import the active config in other modules:

    from config import config
"""

import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    """Base configuration — shared across all environments."""

    SECRET_KEY = os.environ.get("XSS_SECRET_KEY") or secrets.token_hex(32)
    DB_PATH = os.path.join(BASE_DIR, "xss_users.db")
    DEBUG = False
    VERIFY_SSL = True

    # Buffer size caps (in-memory lists)
    LOG_BUFFER_SIZE = 200
    ACTIVITY_BUFFER_SIZE = 100
    KEYSTROKE_BUFFER_SIZE = 500

    # SMTP (email verification)
    SMTP_EMAIL = os.environ.get("XSS_SMTP_EMAIL", "")
    SMTP_PASSWORD = os.environ.get("XSS_SMTP_PASSWORD", "")
    SMTP_HOST = os.environ.get("XSS_SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("XSS_SMTP_PORT", 587))

    # Session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 86400 * 7  # 7 days


class DevelopmentConfig(Config):
    """Development-specific overrides."""

    DEBUG = True
    VERIFY_SSL = False


class ProductionConfig(Config):
    """Production-specific overrides."""

    DEBUG = False
    VERIFY_SSL = True


# ── Active config (switch via FLASK_ENV env var) ──────────────────────────────

_env = os.environ.get("FLASK_ENV", "development").lower()
config = ProductionConfig() if _env == "production" else DevelopmentConfig()
