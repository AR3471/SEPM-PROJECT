"""
Tests for DataStore — add_finding, add_session, add_keystroke, buffer caps.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from models import DataStore, ScanResult, Session, Keystroke


class TestAddFinding:
    """Test DataStore.add_finding()."""

    def setup_method(self):
        self.store = DataStore()
        self._orig = self.store.findings[:]
        self.store.findings = []
        self.store.stats["vulns"] = 0

    def teardown_method(self):
        self.store.findings = self._orig

    def test_add_finding_increases_count(self):
        """Adding a finding should increase the findings list length."""
        r = ScanResult("Reflective", "High", "http://example.com", "q", payload="<script>")
        self.store.add_finding(r)
        assert len(self.store.findings) == 1
        assert self.store.stats["vulns"] == 1

    def test_finding_has_correct_data(self):
        """The stored finding should contain the correct fields."""
        r = ScanResult("DOM", "Moderate", "http://test.com", "search")
        self.store.add_finding(r)
        f = self.store.findings[0]
        assert f.type == "DOM"
        assert f.severity == "Moderate"
        assert f.url == "http://test.com"
        assert f.field == "search"


class TestAddSession:
    """Test DataStore.add_session()."""

    def setup_method(self):
        self.store = DataStore()
        self._orig = self.store.sessions[:]
        self.store.sessions = []

    def teardown_method(self):
        self.store.sessions = self._orig

    def test_add_new_session(self):
        """Adding a new session should increase the list."""
        s = Session(ip="10.0.0.1", user_agent="TestBrowser/1.0")
        self.store.add_session(s)
        assert len(self.store.sessions) == 1
        assert self.store.sessions[0].ip == "10.0.0.1"

    def test_duplicate_ip_updates_existing(self):
        """Adding a session with the same IP should update, not duplicate."""
        s1 = Session(ip="10.0.0.2", user_agent="Old")
        s2 = Session(ip="10.0.0.2", user_agent="New")
        self.store.add_session(s1)
        self.store.add_session(s2)
        assert len(self.store.sessions) == 1
        assert self.store.sessions[0].user_agent == "New"


class TestAddKeystroke:
    """Test DataStore.add_keystroke() and buffer cap."""

    def setup_method(self):
        self.store = DataStore()
        self._orig = self.store.keystrokes[:]
        self.store.keystrokes = []

    def teardown_method(self):
        self.store.keystrokes = self._orig

    def test_add_keystroke(self):
        """Adding a keystroke should store it."""
        ks = Keystroke(session_id="sess1", ip="10.0.0.1", key="a")
        self.store.add_keystroke(ks)
        assert len(self.store.keystrokes) == 1
        assert self.store.keystrokes[0].key == "a"

    def test_keystroke_buffer_cap(self):
        """Buffer should cap at 500 entries, keeping most recent."""
        for i in range(550):
            ks = Keystroke(session_id="sess1", ip="10.0.0.1", key=str(i))
            self.store.add_keystroke(ks)
        assert len(self.store.keystrokes) == 500
        # The most recent entry should be "549"
        assert self.store.keystrokes[-1].key == "549"
        # The oldest kept entry should be "50"
        assert self.store.keystrokes[0].key == "50"


class TestLogBufferCap:
    """Test DataStore.add_log() buffer cap."""

    def setup_method(self):
        self.store = DataStore()
        self._orig = self.store.scan_logs[:]
        self.store.scan_logs = []

    def teardown_method(self):
        self.store.scan_logs = self._orig

    def test_log_buffer_cap(self):
        """Log buffer should cap at 200 entries."""
        for i in range(250):
            self.store.add_log(f"message {i}")
        assert len(self.store.scan_logs) == 200
        # Most recent should be last
        assert "249" in self.store.scan_logs[-1]["msg"]


class TestActivityBufferCap:
    """Test DataStore.add_activity() buffer cap."""

    def setup_method(self):
        self.store = DataStore()
        self._orig = self.store.activity_log[:]
        self.store.activity_log = []

    def teardown_method(self):
        self.store.activity_log = self._orig

    def test_activity_buffer_cap(self):
        """Activity log should cap at 100 entries."""
        for i in range(120):
            self.store.add_activity(f"activity {i}")
        assert len(self.store.activity_log) == 100
