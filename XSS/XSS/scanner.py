"""
XSS Toolkit — XSS scanning engine.

Crawls target URLs, injects payloads, and detects reflected / DOM-based XSS.
"""

import time
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from config import config as app_config
from models import DataStore, ScanResult
from payloads import PAYLOADS


class XSSScanner:
    """Orchestrates crawl → fuzz → detect pipeline."""

    MARKER = "XSS_PROBE_"

    def __init__(self):
        self.store = DataStore()
        self._thread = None
        self._stop_event = threading.Event()
        self.user_id = None
        self._verify_ssl = app_config.VERIFY_SSL

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, target_url, config=None, user_id=None):
        """Start a scan in a background thread."""
        if self.store.scan_state["running"]:
            return {"error": "A scan is already running"}

        self.user_id = user_id
        config = config or {}
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, args=(target_url, config), daemon=True
        )
        self._thread.start()
        return {"status": "started", "target": target_url}

    def stop(self):
        """Signal the running scan to stop."""
        self._stop_event.set()
        self.store.scan_state["running"] = False
        self._log("[!] Scan stopped by user.", "t-warn")
        self.store.add_activity("[!] Scan stopped", "warn", user_id=self.user_id)
        return {"status": "stopped"}

    def get_status(self):
        """Return current scan state + recent findings."""
        return {
            **self.store.scan_state,
            "findings": [f.to_dict() for f in self.store.findings],
            "logs": list(self.store.scan_logs),
        }

    # ── Internal pipeline ─────────────────────────────────────────────────────

    def _run(self, target_url, config):
        depth = config.get("depth", 2)
        timeout = config.get("timeout", 8)
        use_waf = config.get("waf", False)
        use_dom = config.get("dom", True)
        use_template = config.get("template", False)
        self._verify_ssl = config.get("verify_ssl", app_config.VERIFY_SSL)

        scan_state = self.store.scan_state
        scan_state.update({
            "running": True,
            "progress": 0,
            "label": "Initializing…",
            "eta": "calculating…",
            "target": target_url,
        })
        self.store.stats["scans"] += 1

        self._log(f"[*] Target: {target_url}", "t-info")
        self.store.add_activity(f"[*] Scan started → {target_url}", "info", user_id=self.user_id)

        # ── Phase 1: Crawl ────────────────────────────────────────────────────
        self._update_progress(5, "Crawling target…")
        urls, forms = self._crawl(target_url, depth, timeout)
        if self._stopped():
            return

        self._log(f"[+] Found {len(urls)} GET endpoints, {len(forms)} POST forms", "t-safe")
        self.store.add_activity(f"[+] Found {len(urls)} endpoints, {len(forms)} forms", "info", user_id=self.user_id)

        # ── Phase 2: Select payloads ──────────────────────────────────────────
        selected = self._select_payloads(use_waf, use_dom, use_template)
        total_tests = len(urls) * len(selected) + len(forms) * len(selected)
        if total_tests == 0:
            total_tests = 1  # avoid division by zero
        tests_done = 0

        # ── Phase 3 & 4: Fuzzing with parallel workers ──────────────────────────
        self._update_progress(15, "Fuzzing parameters and forms…")

        # Build task list using small per-endpoint units
        tasks = []
        for url in urls:
            for payload_entry in selected:
                tasks.append(("get", url, payload_entry))
        for form in forms:
            for payload_entry in selected:
                tasks.append(("post", form, payload_entry))

        total_tests = len(tasks) or 1
        max_workers = max(1, int(config.get("threads", 4)))
        delay = float(config.get("delay", 0.0))

        tests_done = 0
        progress_lock = threading.Lock()

        def task_runner(task):
            nonlocal tests_done
            if self._stopped():
                return

            kind, target, payload_entry = task
            if kind == "get":
                self._test_get(target, payload_entry, timeout)
            else:
                self._test_post(target, payload_entry, timeout)

            if delay > 0:
                time.sleep(delay)

            with progress_lock:
                tests_done += 1
                pct = 15 + int((tests_done / total_tests) * 75)
                self._update_progress(pct, f"Testing: {tests_done}/{total_tests}")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(task_runner, tasks)

        # ── Phase 5: Done ─────────────────────────────────────────────────────
        vuln_count = len(self.store.findings)
        self._update_progress(100, "Scan complete")
        self._log(
            f"[✓] Scan complete — {vuln_count} vulnerabilities found.",
            "t-safe",
        )
        self.store.add_activity(
            f"[✓] Scan complete — {vuln_count} vulns found", "safe", user_id=self.user_id
        )
        scan_state["running"] = False
        scan_state["eta"] = "Done"

    # ── Crawl ─────────────────────────────────────────────────────────────────

    def _crawl(self, base_url, depth, timeout):
        """Discover URLs with query parameters and HTML forms."""
        urls_with_params = set()
        forms = []
        visited = set()

        def _visit(url, current_depth):
            if current_depth > depth or url in visited or self._stopped():
                return
            visited.add(url)

            try:
                resp = requests.get(url, timeout=timeout, verify=self._verify_ssl,
                                    headers={"User-Agent": "XSS-Scanner/1.0"})
                resp.raise_for_status()
            except requests.RequestException as e:
                self._log(f"[!] Crawl error: {url} — {e}", "t-warn")
                return
            except Exception as e:
                self._log(f"[!] Unexpected crawl error: {url} — {e}", "t-warn")
                return

            parsed = urlparse(url)
            if parsed.query:
                urls_with_params.add(url)

            soup = BeautifulSoup(resp.text, "html.parser")

            # Collect forms
            for form_tag in soup.find_all("form"):
                action = form_tag.get("action", "")
                method = (form_tag.get("method") or "GET").upper()
                full_action = urljoin(url, action) if action else url
                inputs = []
                for inp in form_tag.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs.append({
                            "name": name,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })
                if inputs:
                    forms.append({
                        "action": full_action,
                        "method": method,
                        "inputs": inputs,
                    })

            # Follow links
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                next_url = urljoin(url, href)
                next_parsed = urlparse(next_url)
                if next_parsed.netloc == parsed.netloc:
                    _visit(next_url, current_depth + 1)

        _visit(base_url, 0)

        # If we found no parameterized URLs, make one using FUZZ marker
        if not urls_with_params:
            if "FUZZ" in base_url:
                urls_with_params.add(base_url)
            else:
                # Try adding a common param
                urls_with_params.add(base_url + ("&" if "?" in base_url else "?") + "q=FUZZ")

        return list(urls_with_params), forms

    # ── GET fuzzing ───────────────────────────────────────────────────────────

    def _prepare_payload(self, payload_entry):
        raw_payload = payload_entry.get("code", "")
        marker = f"{self.MARKER}{uuid.uuid4().hex}"

        if "FUZZ" in raw_payload:
            injected = raw_payload.replace("FUZZ", marker)
        else:
            # Keep the original payload and append a unique marker comment.
            injected = f"{raw_payload}<!--{marker}-->"

        return injected, marker


    def _test_get(self, url, payload_entry, timeout):
        """Inject payload into each query parameter and check for reflection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if self._stopped():
                return

            payload_code, marker = self._prepare_payload(payload_entry)

            test_params = dict(params)
            test_params[param_name] = [payload_code]
            test_query = urlencode(test_params, doseq=True)
            test_url = parsed._replace(query=test_query).geturl()

            try:
                resp = requests.get(test_url, timeout=timeout, verify=self._verify_ssl,
                                    headers={"User-Agent": "XSS-Scanner/1.0"},
                                    allow_redirects=False)

                if self._detect_reflection(resp.text, marker, payload_code):
                    vuln_type = payload_entry.get("label", "Reflective")
                    if "DOM" in vuln_type:
                        vuln_type = "DOM"
                    elif "WAF" in vuln_type:
                        vuln_type = "Reflective"
                    else:
                        vuln_type = "Reflective"

                    severity = "High" if payload_entry.get("risk_level") in ("high", "critical") else "Moderate"

                    result = ScanResult(
                        vuln_type=vuln_type,
                        severity=severity,
                        url=test_url,
                        field=param_name,
                        payload=payload_code,
                        user_id=self.user_id,
                    )
                    self.store.add_finding(result)
                    if "WAF" in payload_entry.get("label", ""):
                        self.store.stats["blocked"] += 1

                    self._log(
                        f"[VULN] {vuln_type} XSS → {url} (param={param_name})",
                        "t-vuln",
                    )
                    self.store.add_activity(
                        f"[VULN] {vuln_type} XSS → {param_name}", "vuln"
                    )
            except requests.RequestException as e:
                self._log(f"[!] HTTP error during GET test: {e}", "t-warn")
            except Exception as e:
                self._log(f"[!] Unexpected error during GET test: {e}", "t-warn")

    # ── POST fuzzing ──────────────────────────────────────────────────────────

    def _test_post(self, form, payload_entry, timeout):
        """Inject payload into each form field and check for reflection."""
        action = form["action"]
        payload_code = payload_entry["code"]

        for inp in form["inputs"]:
            if self._stopped():
                return
            payload_code, marker = self._prepare_payload(payload_entry)
            data = {}
            for field in form["inputs"]:
                if field["name"] == inp["name"]:
                    data[field["name"]] = payload_code
                else:
                    data[field["name"]] = field.get("value", "test")

            try:
                if form["method"] == "POST":
                    resp = requests.post(action, data=data, timeout=timeout,
                                         verify=self._verify_ssl,
                                         headers={"User-Agent": "XSS-Scanner/1.0"},
                                         allow_redirects=False)
                else:
                    resp = requests.get(action, params=data, timeout=timeout,
                                        verify=self._verify_ssl,
                                        headers={"User-Agent": "XSS-Scanner/1.0"},
                                        allow_redirects=False)

                if self._detect_reflection(resp.text, marker, payload_code):
                    result = ScanResult(
                        vuln_type="Reflective",
                        severity="High",
                        url=action,
                        field=inp["name"],
                        payload=payload_code,
                    )
                    self.store.add_finding(result)
                    self._log(
                        f"[VULN] Reflective XSS → {action} (field={inp['name']})",
                        "t-vuln",
                    )
                    self.store.add_activity(
                        f"[VULN] Reflective XSS → {inp['name']}", "vuln"
                    )
            except requests.RequestException as e:
                self._log(f"[!] HTTP error during POST test: {e}", "t-warn")
            except Exception as e:
                self._log(f"[!] Unexpected error during POST test: {e}", "t-warn")

    # ── Detection ─────────────────────────────────────────────────────────────

    def _detect_reflection(self, body, marker, payload=None):
        """Check if the injection marker or payload appears unescaped in the response body."""
        if not body or not marker:
            return False

        body_lower = body.lower()
        marker_lower = marker.lower()

        # Exact marker reflection is strongest evidence and reduces false positives.
        if marker_lower in body_lower:
            return True

        # Fallback to payload text (for very simple payloads without marker support)
        if payload and payload.lower() in body_lower:
            return True

        return False

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _select_payloads(self, use_waf, use_dom, use_template):
        """Pick payloads based on scan configuration."""
        types = {"reflective"}
        if use_waf:
            types.add("waf")
        if use_dom:
            types.add("dom")
        if use_template:
            types.add("template")
        return [p for p in PAYLOADS if p["type"] in types]

    def _update_progress(self, pct, label):
        ss = self.store.scan_state
        ss["progress"] = pct
        ss["label"] = label
        remaining = max(0, (100 - pct) * 0.1)
        ss["eta"] = f"~{remaining:.1f}s" if pct < 100 else "Done"

    def _log(self, msg, cls="t-info"):
        self.store.add_log(msg, cls)

    def _stopped(self):
        return self._stop_event.is_set()


# Singleton instance
scanner = XSSScanner()
