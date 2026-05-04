"""
XSS Toolkit — Database connection helper.

Provides a thread-local SQLite connection factory.
Both auth.py and models.py import _get_conn from here,
avoiding circular imports.
"""

import sqlite3
import threading

from config import config

_local = threading.local()


def _get_conn():
    """Return a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(config.DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn
