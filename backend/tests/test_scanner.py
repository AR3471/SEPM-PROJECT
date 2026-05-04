"""
Tests for XSS scanner detection logic and DataStore singleton/queries.
"""

import sys
import os

# Ensure project root is on the path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from scanner import XSSScanner
from models import DataStore, ScanResult


# ── _detect_reflection() ─────────────────────────────────────────────────────


class TestDetectReflection:
    """Unit tests for XSSScanner._detect_reflection()."""

    def setup_method(self):
        self.scanner = XSSScanner()

    def test_direct_marker_match(self):
        """Marker found in body → should return True."""
        body = "<html><body>Some text XSS_PROBE_abc123 more text</body></html>"
        assert self.scanner._detect_reflection(body, "XSS_PROBE_abc123") is True

    def test_direct_marker_match_case_insensitive(self):
        """Marker match should be case-insensitive."""
        body = "<html><body>xss_probe_ABC123</body></html>"
        assert self.scanner._detect_reflection(body, "XSS_PROBE_ABC123") is True

    def test_no_match(self):
        """Neither marker nor payload found → should return False."""
        body = "<html><body>Safe content here</body></html>"
        assert self.scanner._detect_reflection(body, "XSS_PROBE_xyz", "<script>alert(1)</script>") is False

    def test_empty_body(self):
        """Empty body → should return False."""
        assert self.scanner._detect_reflection("", "XSS_PROBE_test") is False

    def test_none_body(self):
        """None body → should return False."""
        assert self.scanner._detect_reflection(None, "XSS_PROBE_test") is False

    def test_empty_marker(self):
        """Empty marker → should return False."""
        assert self.scanner._detect_reflection("<html>test</html>", "") is False

    def test_payload_fallback(self):
        """Payload text found (without marker) → should return True via fallback."""
        body = '<html><body><script>alert(1)</script></body></html>'
        assert self.scanner._detect_reflection(body, "NOT_IN_BODY", "<script>alert(1)</script>") is True

    def test_payload_not_found(self):
        """Payload text NOT found, marker NOT found → False."""
        body = "<html><body>clean</body></html>"
        assert self.scanner._detect_reflection(body, "MISSING_MARKER", "<img onerror=alert(1)>") is False


# ── DataStore singleton ───────────────────────────────────────────────────────


class TestDataStoreSingleton:
    """Verify DataStore singleton behaviour."""

    def test_same_instance(self):
        """Two calls to DataStore() should return the exact same object."""
        a = DataStore()
        b = DataStore()
        assert a is b

    def test_shared_state(self):
        """Mutations on one reference should be visible on the other."""
        a = DataStore()
        b = DataStore()
        a.stats["scans"] = 999
        assert b.stats["scans"] == 999
        # Reset to avoid leaking state
        a.stats["scans"] = 0


# ── get_findings() filtering ─────────────────────────────────────────────────


class TestGetFindings:
    """Test DataStore.get_findings() filters correctly by type and severity."""

    def setup_method(self):
        self.store = DataStore()
        # Save original findings and replace with test data
        self._orig_findings = self.store.findings[:]
        self.store.findings = [
            ScanResult(vuln_type="Reflective", severity="High", url="http://a.com", field="q"),
            ScanResult(vuln_type="DOM", severity="Moderate", url="http://b.com", field="s"),
            ScanResult(vuln_type="Reflective", severity="Moderate", url="http://c.com", field="name"),
            ScanResult(vuln_type="DOM", severity="High", url="http://d.com", field="id"),
        ]

    def teardown_method(self):
        self.store.findings = self._orig_findings

    def test_no_filter(self):
        """No type/severity filter → returns all."""
        results = self.store.get_findings()
        assert len(results) == 4

    def test_filter_by_type(self):
        """Filter by vuln_type='Reflective' → only Reflective findings."""
        results = self.store.get_findings(vuln_type="Reflective")
        assert all(f.type == "Reflective" for f in results)
        assert len(results) == 2

    def test_filter_by_severity(self):
        """Filter by severity='High' → only High findings."""
        results = self.store.get_findings(severity="High")
        assert all(f.severity == "High" for f in results)
        assert len(results) == 2

    def test_filter_by_type_and_severity(self):
        """Filter by both type and severity."""
        results = self.store.get_findings(vuln_type="DOM", severity="High")
        assert len(results) == 1
        assert results[0].type == "DOM"
        assert results[0].severity == "High"

    def test_filter_all_passes_through(self):
        """vuln_type='all' and severity='all' should be treated as no filter."""
        results = self.store.get_findings(vuln_type="all", severity="all")
        assert len(results) == 4
