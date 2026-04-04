<p align="center">
  <img src="https://img.shields.io/badge/XSS-Toolkit-ff3b3b?style=for-the-badge&logo=hackthebox&logoColor=white" alt="XSS Toolkit"/>
  <br/>
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/flask-3.0+-000000?style=flat-square&logo=flask&logoColor=white" alt="Flask"/>
  <img src="https://img.shields.io/badge/license-MIT-06d6a0?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/status-active-06d6a0?style=flat-square" alt="Status"/>
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-8892a4?style=flat-square" alt="Platform"/>
</p>

<h1 align="center">⚡ XSS Automation Toolkit</h1>

<p align="center">
  <strong>A full-stack XSS vulnerability scanner, C2 listener, and payload management toolkit for authorized penetration testing.</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#%EF%B8%8F-architecture">Architecture</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-api-reference">API Reference</a> •
  <a href="#-project-structure">Project Structure</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#%EF%B8%8F-disclaimer">Disclaimer</a>
</p>

---

## 📖 Overview

**XSS Automation Toolkit** is a self-contained penetration testing tool built with a **Python/Flask** backend and a modern, responsive **HTML/CSS/JS** dashboard. It automates the discovery and exploitation of Cross-Site Scripting (XSS) vulnerabilities through an intuitive web interface.

The toolkit crawls target websites, injects payloads from a curated library, detects reflected and DOM-based XSS, and provides a C2 (Command & Control) listener for post-exploitation session management and keystroke capture.

> **⚠️ This tool is intended for authorized security testing and educational purposes only.**

---

## ✨ Features

### 🔍 XSS Scanner
- **Automated crawling** — Recursively discovers pages, forms, and query parameters up to configurable depth
- **Multi-vector fuzzing** — Tests GET parameters and POST form fields with 22+ built-in payloads
- **Reflection detection** — Identifies unescaped payload reflection using pattern matching and regex analysis
- **Real-time progress** — Live progress bar, ETA, terminal log, and findings table during scans
- **Configurable options** — Adjustable crawl depth, thread count, request timeout, and payload categories
- **Scan control** — Start, stop, and monitor scans from the dashboard

### 🎧 C2 (Command & Control) Listener
- **Session management** — Tracks hooked browser sessions with IP, User-Agent, and cookies
- **Keystroke logging** — Captures keystrokes from compromised browsers in real time
- **Token authentication** — Secure token-based authentication for C2 communications
- **Dynamic payload generation** — Auto-generates JavaScript keylogger payloads embedded with C2 credentials
- **Payload server** — Serves keylogger JS to injected script tags on target pages

### 📦 Payload Library
- **22 curated payloads** across 4 categories:
  | Category | Count | Examples |
  |----------|-------|---------|
  | Reflective XSS | 7 | `<script>alert(1)</script>`, SVG onload, autofocus injection |
  | DOM-Based XSS | 5 | `javascript:` URIs, hash-based injection, `eval(location.hash)` |
  | WAF Bypass | 6 | Template literals, base64 encoding, `String.fromCharCode`, data URIs |
  | Template Injection | 4 | Angular/Vue SSTI, prototype chain, ES6 template literals |
- **Search & filter** — Full-text search across payload code, description, and labels
- **One-click copy** — Copy any payload to clipboard
- **Inject to scanner** — Send payloads directly to the scanner with a FUZZ marker URL

### 📊 Reports & Export
- **Filterable findings** — Filter by vulnerability type and severity
- **Multi-format export** — Download reports as **CSV**, **JSON**, or styled **HTML**
- **Finding details** — Detailed modal view with payload, parameter, URL, and remediation guidance

### 🎨 Dashboard
- **Real-time stat counters** — Animated counters for scans, vulnerabilities, sessions, and WAF bypasses
- **Donut chart** — Visual breakdown of findings by vulnerability type
- **Activity feed** — Chronological log of all scanner and C2 events
- **Dark / Light mode** — Toggle between themes with persistent preference
- **Accent colors** — Customizable accent color (red, blue, green, purple)
- **Responsive design** — Collapsible sidebar for mobile screens

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Operator Browser                              │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Dashboard UI (index.html + app.js + style.css)               │  │
│  │  • Navigation  • Stats  • Scanner  • C2  • Payloads  • Reports│  │
│  └──────────────────────────┬─────────────────────────────────────┘  │
└─────────────────────────────┼────────────────────────────────────────┘
                              │ HTTP (port 5000)
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      Flask Backend (server.py)                       │
│                                                                      │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐               │
│  │ REST API │───▶│  XSSScanner  │    │   C2Server   │               │
│  │ Routes   │    │ (scanner.py) │    │(c2_listener)│               │
│  │          │───▶│              │    │              │               │
│  │ /api/*   │    │ • Crawl      │    │ • Sessions   │               │
│  │          │───▶│ • Fuzz GET   │    │ • Keystrokes │               │
│  └──────────┘    │ • Fuzz POST  │    │ • Payload JS │               │
│       │          │ • Detect     │    └──────┬───────┘               │
│       │          └──────┬───────┘           │                       │
│       │                 │                   │                       │
│       │          ┌──────▼───────────────────▼──────┐                │
│       └─────────▶│     DataStore (models.py)       │                │
│                  │  Thread-safe Singleton           │                │
│                  │  • findings    • sessions        │                │
│                  │  • keystrokes  • scan_logs       │                │
│                  │  • stats       • activity_log    │                │
│                  └─────────────────────────────────┘                │
│                                                                      │
│  ┌────────────────┐                                                  │
│  │ Payload Library │  22 payloads (reflective, DOM, WAF, template)  │
│  │ (payloads.py)   │                                                 │
│  └────────────────┘                                                  │
└──────────────────────────────────────────────────────────────────────┘
         │                                          ▲
         │ HTTP (crawl + fuzz)                      │ XHR (checkin + keys)
         ▼                                          │
┌─────────────────┐                      ┌──────────┴──────────┐
│  Target Website  │                      │   Victim Browser    │
│  (authorized)    │                      │   (hooked via XSS)  │
└─────────────────┘                      └─────────────────────┘
```

### Component Summary

| Component | File | Role |
|-----------|------|------|
| **Flask Server** | `server.py` | REST API routes, static file serving, request routing |
| **XSS Scanner** | `scanner.py` | Crawl → fuzz → detect pipeline; background thread execution |
| **C2 Listener** | `c2_listener.py` | Session tracking, keystroke capture, JS payload generation |
| **Data Store** | `models.py` | Thread-safe singleton for in-memory data (`ScanResult`, `Session`, `Keystroke`) |
| **Payload Library** | `payloads.py` | 22 curated XSS payloads with search and filtering |
| **Dashboard UI** | `index.html` `app.js` `style.css` | Single-page app with 6 pages, real-time polling, charts |

---

## 🚀 Installation

### Prerequisites

- **Python 3.10+** — [Download Python](https://www.python.org/downloads/)
- **pip** — Comes with Python
- **Git** — [Download Git](https://git-scm.com/)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/xss-toolkit.git
cd xss-toolkit

# 2. Create a virtual environment (recommended)
python -m venv .venv

# Activate — Windows
.venv\Scripts\activate

# Activate — Linux / macOS
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the server
python server.py
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `flask` | ≥ 3.0.0 | Web framework and REST API |
| `flask-cors` | ≥ 4.0.0 | Cross-Origin Resource Sharing |
| `flask-limiter` | ≥ 3.5.0 | Rate limiting for auth endpoints |
| `requests` | ≥ 2.31.0 | HTTP client for crawling and fuzzing |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing for form and link extraction |

---

## 💻 Usage

### Starting the Server

```bash
python server.py
```

```
============================================================
  XSS Toolkit — Backend Server
  Dashboard:  http://127.0.0.1:5000
  API Base:   http://127.0.0.1:5000/api
============================================================
```

Open **http://127.0.0.1:5000** in your browser to access the dashboard.

### Running a Scan

1. Navigate to the **Scanner** page
2. Enter a target URL (must begin with `http://` or `https://`)
3. Configure scan options:
   - **Crawl Depth** (1–5) — How deep to follow links
   - **Threads** (1–16) — Concurrent workers
   - **Timeout** (2–60s) — Request timeout
   - **WAF Bypass** — Include WAF evasion payloads
   - **DOM Analysis** — Include DOM-based XSS payloads
   - **Template Injection** — Include SSTI payloads
4. Click **Start Scan** and confirm the authorization disclaimer
5. Monitor real-time progress, logs, and findings

### Using the C2 Listener

1. Navigate to the **C2 Listener** page
2. Configure host, port, and optional authentication token
3. Click **Start Listener**
4. Optionally start the **Payload Server** to serve `keylogger.js`
5. When a victim loads the injected script tag, sessions and keystrokes will appear in real time

### Exporting Reports

1. Navigate to the **Reports** page
2. Filter by vulnerability type or severity
3. Click **Export CSV**, **Export JSON**, or **Export HTML**

---

## 📡 API Reference

### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Get scan/vuln/session/blocked counters |
| `GET` | `/api/activity` | Get activity feed entries |
| `DELETE` | `/api/activity` | Clear activity feed |

### Scanner

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/start` | Start a new scan (`{url, depth, threads, timeout, waf, dom, template}`) |
| `POST` | `/api/scan/stop` | Stop the running scan |
| `GET` | `/api/scan/status` | Get scan state, progress, findings, and logs |
| `GET` | `/api/scan/logs` | Get terminal log entries |
| `DELETE` | `/api/scan/logs` | Clear terminal logs |

### Findings / Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/findings` | Get findings (optional `?type=` and `?severity=` filters) |
| `DELETE` | `/api/findings` | Clear all findings |
| `GET` | `/api/findings/export/csv` | Download report as CSV |
| `GET` | `/api/findings/export/json` | Download report as JSON |
| `GET` | `/api/findings/export/html` | Download report as styled HTML |

### Payloads

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/payloads` | Get payload library (optional `?type=` and `?q=` filters) |

### C2 Listener

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/c2/start` | Start C2 listener (`{host, port, token}`) |
| `POST` | `/api/c2/stop` | Stop C2 listener |
| `GET` | `/api/c2/status` | Get C2 state and session count |
| `GET` | `/api/c2/sessions` | Get all hooked sessions |
| `GET` | `/api/c2/keystrokes` | Get captured keystrokes (optional `?session_id=`) |
| `DELETE` | `/api/c2/keystrokes` | Clear all keystrokes |
| `POST` | `/api/c2/log` | Session check-in from hooked browser |
| `POST` | `/api/c2/keys` | Keystroke submission from hooked browser |
| `GET` | `/api/c2/payload.js` | Serve dynamic keylogger JavaScript |

### Payload Server

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ps/start` | Start payload server (`{port}`) |
| `POST` | `/api/ps/stop` | Stop payload server |
| `GET` | `/api/ps/status` | Get payload server state |

---

## 📁 Project Structure

```
xss-toolkit/
├── server.py            # Flask backend — REST API routes and static file serving
├── scanner.py           # XSS scanning engine — crawl, fuzz, detect pipeline
├── c2_listener.py       # C2 listener — session management, keystroke capture
├── models.py            # Data models — ScanResult, Session, Keystroke, DataStore
├── payloads.py          # Payload library — 22 curated XSS payloads
├── auth.py              # User authentication (SQLite + password hashing)
├── db.py                # Database connection helper
├── config.py            # Application configuration and environment variables
├── .env.example         # Template for environment variables
├── index.html           # Dashboard frontend — single-page app (6 pages)
├── app.js               # Frontend logic — API calls, polling, UI rendering
├── style.css            # Stylesheet — dark/light themes, glassmorphism, animations
├── requirements.txt     # Python dependencies
├── requirements-dev.txt # Development dependencies (testing tools)
├── tests/               # Pytest unit tests (scanner, auth, models)
└── README.md            # This file
```

---

## 🧩 Class Diagram

```
┌──────────────────────────┐     ┌───────────────────────────┐
│       XSSScanner         │     │        C2Server            │
├──────────────────────────┤     ├───────────────────────────┤
│ - store: DataStore       │     │ - store: DataStore         │
│ - _thread: Thread        │     ├───────────────────────────┤
│ - _stop_event: Event     │     │ + start(host, port, token) │
├──────────────────────────┤     │ + stop()                   │
│ + start(url, config)     │     │ + get_status()             │
│ + stop()                 │     │ + validate_token(token)    │
│ + get_status()           │     │ + register_session(...)    │
│ - _run(url, config)      │     │ + get_sessions()           │
│ - _crawl(url, depth)     │     │ + log_keystroke(...)       │
│ - _test_get(url, payload)│     │ + get_keystrokes(sid)      │
│ - _test_post(form, pay.) │     │ + start_payload_server(p)  │
│ - _detect_reflection()   │     │ + stop_payload_server()    │
│ - _select_payloads()     │     │ + get_keylogger_js()       │
└──────────┬───────────────┘     └───────────┬───────────────┘
           │                                  │
           └──────────┐    ┌──────────────────┘
                      ▼    ▼
         ┌─────────────────────────────────┐
         │    DataStore «singleton»        │
         ├─────────────────────────────────┤
         │ - findings: list[ScanResult]    │
         │ - sessions: list[Session]       │
         │ - keystrokes: list[Keystroke]   │
         │ - scan_logs: list[dict]         │
         │ - activity_log: list[dict]      │
         │ - stats: dict                   │
         │ - scan_state: dict              │
         │ - c2_state: dict                │
         │ - ps_state: dict                │
         │ - lock: Lock                    │
         ├─────────────────────────────────┤
         │ + add_finding(result)           │
         │ + get_findings(type, sev)       │
         │ + add_session(session)          │
         │ + add_keystroke(keystroke)      │
         │ + add_log(msg, cls)             │
         │ + add_activity(msg, type)       │
         └─────────────────────────────────┘
                      ▲
     ┌────────────────┼────────────────┐
     │                │                │
┌────┴─────┐   ┌──────┴────┐   ┌──────┴──────┐
│ScanResult│   │  Session   │   │ Keystroke   │
├──────────┤   ├───────────┤   ├─────────────┤
│ id       │   │ id        │   │ session_id  │
│ type     │   │ ip        │   │ ip          │
│ severity │   │ user_agent│   │ key         │
│ url      │   │ cookies   │   │ time        │
│ field    │   │ time      │   │ timestamp   │
│ payload  │   │ active    │   └─────────────┘
│ time     │   └───────────┘
└──────────┘
```

---

## 🖼️ Screenshots

> _Add screenshots of your dashboard here after deployment._

| Dashboard | Scanner | C2 Listener |
|-----------|---------|-------------|
| ![Dashboard](#) | ![Scanner](#) | ![C2](#) |

| Payload Library | Reports | Settings |
|-----------------|---------|----------|
| ![Payloads](#) | ![Reports](#) | ![Settings](#) |

---

## 🔧 Configuration

### Scan Configuration Options

| Option | Type | Default | Range | Description |
|--------|------|---------|-------|-------------|
| `depth` | int | 2 | 1–5 | Crawl depth (how many links deep to follow) |
| `threads` | int | 4 | 1–16 | Number of concurrent workers |
| `timeout` | int | 8 | 2–60 | HTTP request timeout in seconds |
| `waf` | bool | false | — | Include WAF bypass payloads |
| `dom` | bool | true | — | Include DOM-based XSS payloads |
| `template` | bool | false | — | Include template injection payloads |

### C2 Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | `127.0.0.1` | Listener bind address |
| `port` | int | `9000` | Listener port |
| `token` | string | auto-generated | Authentication token (32-char hex) |

---

## 🛡️ Security Considerations

- **SQLite persistence** — Findings and activity data are persisted to SQLite database for durability across server restarts. User authentication data includes encrypted passwords and profile information.
- **Token authentication** — C2 communications are authenticated via secret tokens.
- **No TLS by default** — Run behind a reverse proxy (NGINX/Caddy) for HTTPS in production.
- **Keystroke buffer** — Capped at 500 entries to prevent memory exhaustion.
- **Scan logs** — Capped at 200 entries with automatic trimming.
- **Activity log** — Capped at 100 entries with automatic trimming.

---

## 🗺️ Roadmap

- [ ] Persistent storage (SQLite / PostgreSQL)
- [ ] Blind XSS detection with out-of-band callbacks
- [ ] Browser-based DOM analysis using headless Chrome
- [ ] PDF report generation
- [ ] Multi-user authentication
- [ ] Scan scheduling and recurring scans
- [ ] Plugin system for custom payloads
- [ ] WebSocket-based real-time updates (replace polling)

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/<your-username>/xss-toolkit.git
cd xss-toolkit

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Run in development mode
python server.py
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

> **This tool is designed for AUTHORIZED penetration testing and educational purposes ONLY.**
>
> - You **MUST** have explicit written permission from the system owner before scanning any target.
> - Unauthorized access to computer systems is **ILLEGAL** under the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and equivalent laws worldwide.
> - The developers assume **NO liability** for misuse of this tool.
> - By using this tool, you agree to use it **responsibly and legally**.
>
> **If you do not have authorization — DO NOT USE THIS TOOL.**

---

<p align="center">
  <sub>Built with ⚡ by the XSS Toolkit team</sub>
</p>
