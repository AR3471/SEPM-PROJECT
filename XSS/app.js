/* ═══════════════════════════════════════════════════════════
   XSS Dashboard – app.js
   Connected to Flask backend at /api/*
   ═══════════════════════════════════════════════════════════ */

const API = '';  // same-origin, no prefix needed

// ── State ────────────────────────────────────────────────────────────────────
const state = {
    findings: [],
    scanRunning: false,
    scanPollTimer: null,
    c2Running: false,
    c2PollTimer: null,
    psRunning: false,
    sessions: [],
    keystrokes: [],
    depth: 2,
    threads: 4,
    timeout: 8,
    defaultDepth: 2,
    fontSize: 10,
    waf: false,
    dom: true,
    template: false,
    currentPage: 'dashboard',
    stats: { scans: 0, vulns: 0, sessions: 0, blocked: 0 },
    statsPollTimer: null,
    currentUser: null,
    lastLogIndex: 0,
    reportPage: 1,
    reportPageSize: 20,
};

// ── Payload library (fetched from backend) ───────────────────────────────────
let PAYLOADS = [];

// ── API helpers ──────────────────────────────────────────────────────────────
async function apiGet(path) {
    try {
        const r = await fetch(API + path);
        return await r.json();
    } catch (e) {
        console.warn('API GET failed:', path, e);
        return null;
    }
}

async function apiPost(path, body = {}) {
    try {
        const r = await fetch(API + path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        return await r.json();
    } catch (e) {
        console.warn('API POST failed:', path, e);
        return null;
    }
}

async function apiDelete(path) {
    try {
        const r = await fetch(API + path, { method: 'DELETE' });
        return await r.json();
    } catch (e) {
        console.warn('API DELETE failed:', path, e);
        return null;
    }
}

// ── Clock ────────────────────────────────────────────────────────────────────
function updateClock() {
    const now = new Date();
    const t = [now.getHours(), now.getMinutes(), now.getSeconds()]
        .map(n => String(n).padStart(2, '0')).join(':');
    document.getElementById('clock').textContent = t;
}
setInterval(updateClock, 1000);
updateClock();

// ── Navigation ───────────────────────────────────────────────────────────────
const PAGE_TITLES = {
    dashboard: 'Dashboard',
    scanner: 'XSS Scanner',
    payloads: 'Payload Library',
    c2: 'C2 Listener',
    reports: 'Reports',
    settings: 'Settings',
    profile: 'My Profile',
};

function navigate(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('page-' + page).classList.add('active');
    document.getElementById('nav-' + page).classList.add('active');
    document.getElementById('topbar-title').textContent = PAGE_TITLES[page] || page;
    state.currentPage = page;

    if (page === 'payloads') renderPayloads();
    if (page === 'reports') loadAndRenderReport();
    if (page === 'profile') loadProfile();
    return false;
}

// ── Sidebar toggle (mobile) ──────────────────────────────────────────────────
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
}

// ── Stat counters ────────────────────────────────────────────────────────────
function animateCounter(id, target) {
    const el = document.getElementById(id);
    const start = parseInt(el.textContent) || 0;
    const diff = target - start;
    const steps = 30;
    let i = 0;
    const t = setInterval(() => {
        i++;
        el.textContent = Math.round(start + diff * (i / steps));
        if (i >= steps) clearInterval(t);
    }, 16);
}

function updateStats() {
    animateCounter('stat-scans', state.stats.scans);
    animateCounter('stat-vulns', state.stats.vulns);
    animateCounter('stat-sessions', state.stats.sessions);
    animateCounter('stat-blocked', state.stats.blocked);
}

async function fetchStats() {
    const data = await apiGet('/api/stats');
    if (data) {
        state.stats = data;
        updateStats();
    }
}

// ── Donut chart ──────────────────────────────────────────────────────────────
function drawDonut() {
    const canvas = document.getElementById('donut-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = 100, cy = 100, r = 70, ir = 45;

    const findings = state.findings;
    const counts = {
        reflective: findings.filter(f => f.type === 'Reflective').length,
        dom: findings.filter(f => f.type === 'DOM').length,
        template: findings.filter(f => f.type === 'Template').length,
        waf: findings.filter(f => f.type === 'WAF Bypass').length,
    };
    const total = counts.reflective + counts.dom + counts.template + counts.waf || 4;
    const slices = [
        { val: counts.reflective || 2, color: '#ff3b3b' },
        { val: counts.dom || 1, color: '#ff8c42' },
        { val: counts.template || 1, color: '#ffd166' },
        { val: counts.waf || 0.5, color: '#bb86fc' },
    ];

    ctx.clearRect(0, 0, 200, 200);
    let angle = -Math.PI / 2;
    slices.forEach(s => {
        const sweep = (s.val / (total + 0.5)) * 2 * Math.PI;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, angle, angle + sweep);
        ctx.closePath();
        ctx.fillStyle = s.color;
        ctx.fill();
        angle += sweep;
    });
    // inner circle
    ctx.beginPath();
    ctx.arc(cx, cy, ir, 0, 2 * Math.PI);
    const isLight = document.body.classList.contains('light');
    ctx.fillStyle = isLight ? '#f0f2f5' : '#10141c';
    ctx.fill();
    // center text
    ctx.fillStyle = isLight ? '#1a1a2e' : '#e2e8f0';
    ctx.font = 'bold 22px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(findings.length || '—', cx, cy - 6);
    ctx.font = '10px Inter, sans-serif';
    ctx.fillStyle = '#8892a4';
    ctx.fillText('findings', cx, cy + 12);
}

// ── Activity log ─────────────────────────────────────────────────────────────
function addActivity(msg, type = 'info') {
    const list = document.getElementById('activity-list');
    const now = new Date();
    const t = [now.getHours(), now.getMinutes(), now.getSeconds()]
        .map(n => String(n).padStart(2, '0')).join(':');
    const div = document.createElement('div');
    div.className = `activity-item ${type}`;
    div.innerHTML = `<span class="act-time">${t}</span><span class="act-msg">${msg}</span>`;
    list.appendChild(div);
    list.scrollTop = list.scrollHeight;
    while (list.children.length > 100) list.removeChild(list.firstChild);
}

async function clearActivity() {
    document.getElementById('activity-list').innerHTML = '';
    await apiDelete('/api/activity');
}

// ── Terminal log ─────────────────────────────────────────────────────────────
function termLog(msg, cls = '') {
    const box = document.getElementById('scan-log');
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = msg;
    box.appendChild(span);
    box.appendChild(document.createElement('br'));
    box.scrollTop = box.scrollHeight;
}

async function clearLog() {
    document.getElementById('scan-log').innerHTML = '';
    state.lastLogIndex = 0;
    termLog('[*] Log cleared.', 't-info');
    await apiDelete('/api/scan/logs');
}

function exportLog() {
    const text = document.getElementById('scan-log').innerText;
    download('scan_log.txt', text);
    showToast('📄 Log exported');
}

// ── Spinners ─────────────────────────────────────────────────────────────────
function adjustDepth(d) {
    state.depth = Math.min(5, Math.max(1, state.depth + d));
    document.getElementById('depth-val').textContent = state.depth;
}
function adjustThreads(d) {
    state.threads = Math.min(16, Math.max(1, state.threads + d));
    document.getElementById('threads-val').textContent = state.threads;
}
function adjustTimeout(d) {
    state.timeout = Math.min(60, Math.max(2, state.timeout + d));
    document.getElementById('timeout-val').textContent = state.timeout;
}
function adjustDefaultDepth(d) {
    state.defaultDepth = Math.min(5, Math.max(1, state.defaultDepth + d));
    document.getElementById('default-depth-val').textContent = state.defaultDepth;
}
function adjustFontSize(d) {
    state.fontSize = Math.min(18, Math.max(8, state.fontSize + d));
    document.getElementById('font-size-val').textContent = state.fontSize;
    document.querySelectorAll('.terminal, .keylog-stream').forEach(el => {
        el.style.fontSize = state.fontSize + 'px';
    });
}

// ── Toggles ──────────────────────────────────────────────────────────────────
function toggle(key, elId) {
    state[key] = !state[key];
    document.getElementById(elId).classList.toggle('active', state[key]);
}
function toggleWaf() { toggle('waf', 'waf-toggle'); }
function toggleDom() { toggle('dom', 'dom-toggle'); }
function toggleTemplate() { toggle('template', 'tmpl-toggle'); }

// ══════════════════════════════════════════════════════════════════════════════
//  SCANNER — calls real backend API
// ══════════════════════════════════════════════════════════════════════════════

async function startScan() {
    const url = document.getElementById('target-url').value.trim();
    if (!url) {
        showToast('⚠ Please enter a target URL', 'warn');
        return;
    }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        showToast('⚠ URL must start with http:// or https://', 'warn');
        return;
    }

    // Disclaimer
    if (!confirm(
        '⚠ Legal Disclaimer\n\nThis tool is for AUTHORIZED penetration testing ONLY.\n\nBy clicking OK, you confirm you have explicit permission to test the target system.\n\nUnauthorized scanning is ILLEGAL.'
    )) {
        termLog('[!] Scan aborted — authorization not confirmed.', 't-warn');
        addActivity('[!] Scan aborted — auth not confirmed', 'warn');
        return;
    }

    await withLoading('scan-btn', async () => {
        // Call backend
        const result = await apiPost('/api/scan/start', {
            url,
            depth: state.depth,
            threads: state.threads,
            timeout: state.timeout,
            waf: state.waf,
            dom: state.dom,
            template: state.template,
        });

        if (!result || result.error) {
            showToast('⚠ ' + (result?.error || 'Failed to start scan'), 'warn');
            return;
        }

        state.scanRunning = true;
        state.lastLogIndex = 0;

        document.getElementById('scan-btn').disabled = true;
        document.getElementById('stop-btn').disabled = false;
        document.getElementById('progress-section').style.display = '';
        document.getElementById('live-findings').style.display = '';
        document.getElementById('live-tbody').innerHTML = '';
        document.getElementById('live-count').textContent = '0 found';
        document.getElementById('status-dot').className = 'status-dot busy';
        document.getElementById('status-label').textContent = 'Scanning…';

        termLog(`[*] Target: ${url}`, 't-info');
        addActivity(`[*] Scan started → ${url}`, 'info');

        // Start polling for status
        pollScanStatus();
    });
}

function pollScanStatus() {
    if (state.scanPollTimer) clearInterval(state.scanPollTimer);
    state.scanPollTimer = setInterval(async () => {
        const status = await apiGet('/api/scan/status');
        if (!status) return;

        // Update progress bar
        const pct = status.progress || 0;
        document.getElementById('progress-fill').style.width = pct + '%';
        document.getElementById('progress-pct').textContent = pct + '%';
        document.getElementById('progress-label').textContent = status.label || '';
        document.getElementById('eta-label').textContent = 'ETA: ' + (status.eta || 'calculating…');

        // Update logs — slice from lastLogIndex instead of DOM text comparison
        if (status.logs && status.logs.length > state.lastLogIndex) {
            const newLogs = status.logs.slice(state.lastLogIndex);
            newLogs.forEach(entry => {
                termLog(entry.msg, entry.cls);
            });
            state.lastLogIndex = status.logs.length;
        }

        // Update findings
        if (status.findings && status.findings.length > state.findings.length) {
            const newFindings = status.findings.slice(state.findings.length);
            newFindings.forEach(f => {
                state.findings.push(f);
                addLiveFinding(f, state.findings.length);
                addActivity(`[VULN] ${f.type} XSS → ${f.field || f.url}`, 'vuln');
            });
            document.getElementById('live-count').textContent = state.findings.length + ' found';
            updateDashboardTable();
            drawDonut();
        }

        // Fetch updated stats
        await fetchStats();

        // Check if scan is done
        if (!status.running) {
            clearInterval(state.scanPollTimer);
            state.scanPollTimer = null;
            finishScan();
        }
    }, 1000);
}

function addLiveFinding(v, idx) {
    const tbody = document.getElementById('live-tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `
    <td>${idx}</td>
    <td><span class="type-badge">${v.type}</span></td>
    <td><span class="sev-badge sev-${v.severity.toLowerCase()}">${v.severity}</span></td>
    <td title="${v.url}">${truncate(v.url, 50)}</td>
    <td>${v.field || '—'}</td>
  `;
    tbody.appendChild(tr);
}

function finishScan() {
    state.scanRunning = false;
    document.getElementById('scan-btn').disabled = false;
    document.getElementById('stop-btn').disabled = true;
    document.getElementById('progress-fill').style.width = '100%';
    document.getElementById('progress-pct').textContent = '100%';
    document.getElementById('status-dot').className = 'status-dot online';
    document.getElementById('status-label').textContent = 'Scan Complete';
    showToast('✅ Scan complete — ' + state.findings.length + ' vulnerabilities found');

    // Refresh report table and stats immediately after scan finishes
    loadAndRenderReport();
    fetchStats();
}

async function stopScan() {
    await apiPost('/api/scan/stop');
    if (state.scanPollTimer) {
        clearInterval(state.scanPollTimer);
        state.scanPollTimer = null;
    }
    state.scanRunning = false;
    termLog('[!] Scan stopped by user.', 't-warn');
    addActivity('[!] Scan stopped', 'warn');
    document.getElementById('scan-btn').disabled = false;
    document.getElementById('stop-btn').disabled = true;
    document.getElementById('status-dot').className = 'status-dot online';
    document.getElementById('status-label').textContent = 'Stopped';
    showToast('🛑 Scan stopped');
}

// ── Dashboard table ───────────────────────────────────────────────────────────
function updateDashboardTable() {
    const tbody = document.getElementById('recent-tbody');
    tbody.innerHTML = '';
    const slice = state.findings.slice(-10).reverse();
    if (!slice.length) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No findings yet. Run a scan to discover vulnerabilities.</td></tr>';
        return;
    }
    slice.forEach((v, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
      <td>${i + 1}</td>
      <td><span class="type-badge">${v.type}</span></td>
      <td><span class="sev-badge sev-${v.severity.toLowerCase()}">${v.severity}</span></td>
      <td title="${v.url}">${truncate(v.url, 48)}</td>
      <td>${v.field || '—'}</td>
      <td>${v.time || '—'}</td>
      <td><button class="btn-icon" onclick="showDetail('${v.id}')">Details</button></td>
    `;
        tbody.appendChild(tr);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  PAYLOADS — fetched from backend
// ══════════════════════════════════════════════════════════════════════════════

async function fetchPayloads(type, query) {
    const params = new URLSearchParams();
    if (type && type !== 'all') params.set('type', type);
    if (query) params.set('q', query);
    const data = await apiGet('/api/payloads?' + params.toString());
    if (data) PAYLOADS = data;
    return data || [];
}

async function renderPayloads(list) {
    if (!list) {
        list = await fetchPayloads();
    }
    const grid = document.getElementById('payload-grid');
    grid.innerHTML = '';
    list.forEach((p, i) => {
        const div = document.createElement('div');
        div.className = 'payload-card';
        div.setAttribute('data-type', p.type);
        div.innerHTML = `
      <div class="payload-card-top">
        <span class="payload-type-label pl-${p.type}">${p.label}</span>
        <span style="font-size:0.72rem;color:var(--text-dim)">#${p.id || i + 1}</span>
      </div>
      <div class="payload-code">${escHtml(p.code)}</div>
      <div class="payload-actions">
        <button class="copy-btn" onclick="copyPayload(${i})">📋 Copy</button>
        <button class="copy-btn" onclick="injectToScanner(${i})">→ Use in Scanner</button>
      </div>
    `;
        grid.appendChild(div);
    });
}

async function filterPayloads() {
    const q = document.getElementById('payload-search').value.toLowerCase();
    const t = document.getElementById('payload-filter').value;
    const list = await fetchPayloads(t, q);
    renderPayloads(list);
}

function copyPayload(i) {
    if (PAYLOADS[i]) {
        navigator.clipboard.writeText(PAYLOADS[i].code).then(() => showToast('📋 Payload copied!'));
    }
}

function injectToScanner(i) {
    navigate('scanner');
    document.getElementById('target-url').value = `https://target.example.com/search?q=FUZZ`;
    showToast('✅ Payload ready — enter your target URL and start scan');
}

// ══════════════════════════════════════════════════════════════════════════════
//  C2 LISTENER — calls real backend API
// ══════════════════════════════════════════════════════════════════════════════

async function toggleC2() {
    await withLoading('c2-start-btn', async () => {
        const info = document.getElementById('c2-info');

        if (!state.c2Running) {
            // START
            const host = document.getElementById('c2-host').value || '127.0.0.1';
            const port = document.getElementById('c2-port').value || 9000;
            const token = document.getElementById('c2-token').value || '';

            const result = await apiPost('/api/c2/start', { host, port, token });
            if (!result || result.error) {
                showToast('⚠ Failed to start C2');
                return;
            }

            state.c2Running = true;
            document.getElementById('c2-url-display').textContent = result.url || `http://${host}:${port}/log`;
            document.getElementById('c2-token-display').textContent = result.token || '—';
            document.getElementById('c2-start-btn').textContent = '🔴 Stop Listener';
            document.getElementById('c2-start-btn').className = 'btn-danger';
            info.style.display = '';
            document.getElementById('status-dot').className = 'status-dot online';
            document.getElementById('status-label').textContent = 'C2 Active';
            addActivity('[*] C2 Listener started', 'info');
            showToast('🎧 C2 Listener started');

            // Start polling for sessions/keystrokes
            startC2Polling();
        } else {
            // STOP
            await apiPost('/api/c2/stop');
            state.c2Running = false;
            if (state.c2PollTimer) {
                clearInterval(state.c2PollTimer);
                state.c2PollTimer = null;
            }
            document.getElementById('c2-start-btn').textContent = '🎧 Start Listener';
            document.getElementById('c2-start-btn').className = 'btn-primary';
            info.style.display = 'none';
            document.getElementById('status-label').textContent = 'System Ready';
            addActivity('[!] C2 Listener stopped', 'warn');
            showToast('🛑 C2 Listener stopped');
        }
    });
}

function startC2Polling() {
    if (state.c2PollTimer) clearInterval(state.c2PollTimer);
    state.c2PollTimer = setInterval(async () => {
        if (!state.c2Running) {
            clearInterval(state.c2PollTimer);
            return;
        }

        // Fetch sessions
        const sessions = await apiGet('/api/c2/sessions');
        if (sessions && sessions.length > 0) {
            renderSessions(sessions);
        }

        // Fetch keystrokes
        const keystrokes = await apiGet('/api/c2/keystrokes');
        if (keystrokes && keystrokes.length > state.keystrokes.length) {
            const newKeys = keystrokes.slice(state.keystrokes.length);
            newKeys.forEach(k => addKeystroke(k.key, k.ip));
            state.keystrokes = keystrokes;
        }

        // Update stats
        await fetchStats();
    }, 2000);
}

function renderSessions(sessions) {
    const list = document.getElementById('sessions-list');
    list.innerHTML = '';
    sessions.forEach(s => {
        const div = document.createElement('div');
        div.className = 'session-card';
        div.innerHTML = `
      <div class="session-card-top">
        <span class="session-ip">⬤ ${s.ip}</span>
        <span class="session-time">${s.time || 'just now'}</span>
      </div>
      <div class="session-details">UA: ${truncate(s.user_agent || 'Unknown', 60)} • Cookie: ${truncate(s.cookies || 'none', 30)}</div>
    `;
        list.appendChild(div);
    });
    document.getElementById('session-count-badge').textContent = sessions.length + ' active';
}

async function togglePayloadServer() {
    await withLoading('ps-start-btn', async () => {
        const info = document.getElementById('ps-info');

        if (!state.psRunning) {
            const port = document.getElementById('ps-port').value || 8080;
            const result = await apiPost('/api/ps/start', { port });
            if (!result || result.error) {
                showToast('⚠ Failed to start payload server');
                return;
            }
            state.psRunning = true;
            document.getElementById('ps-url-display').textContent = result.url || `http://127.0.0.1:${port}/keylogger.js`;
            document.getElementById('ps-start-btn').textContent = '🔴 Stop Payload Server';
            document.getElementById('ps-start-btn').className = 'btn-danger';
            info.style.display = '';
            showToast('📦 Payload server started');
            addActivity('[*] Payload server started at :' + port, 'info');
        } else {
            await apiPost('/api/ps/stop');
            state.psRunning = false;
            document.getElementById('ps-start-btn').textContent = '📦 Start Payload Server';
            document.getElementById('ps-start-btn').className = 'btn-secondary';
            info.style.display = 'none';
            showToast('🛑 Payload server stopped');
            addActivity('[!] Payload server stopped', 'warn');
        }
    });
}

function addKeystroke(key, ip) {
    const stream = document.getElementById('keylog-stream');
    const span = document.createElement('span');
    const now = new Date().toLocaleTimeString();
    span.textContent = `[${now}] ${ip}  →  ${key === 'Enter' ? '⏎ Enter' : key}\n`;
    stream.appendChild(span);
    stream.scrollTop = stream.scrollHeight;
}

async function clearKeylog() {
    document.getElementById('keylog-stream').innerHTML = '<span class="t-info">Log cleared…</span>';
    await apiDelete('/api/c2/keystrokes');
    state.keystrokes = [];
}

// ══════════════════════════════════════════════════════════════════════════════
//  REPORTS — fetched from backend
// ══════════════════════════════════════════════════════════════════════════════

// Store report data for pagination navigation
let _reportDataCache = [];

async function loadAndRenderReport() {
    const vuln_type = document.getElementById('report-filter-type')?.value || 'all';
    const severity = document.getElementById('report-filter-sev')?.value || 'all';
    const params = new URLSearchParams();
    if (vuln_type !== 'all') params.set('type', vuln_type);
    if (severity !== 'all') params.set('severity', severity);

    const data = await apiGet('/api/findings?' + params.toString());
    if (data) {
        _reportDataCache = data;
        state.reportPage = 1;
        renderReportTable(data);
    }
}

function renderReportTable(data) {
    const tbody = document.getElementById('report-tbody');
    tbody.innerHTML = '';
    if (!data.length) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No data. Run a scan first.</td></tr>';
        const pag = document.getElementById('report-pagination');
        if (pag) pag.style.display = 'none';
        return;
    }

    // Pagination
    const totalPages = Math.ceil(data.length / state.reportPageSize);
    if (state.reportPage > totalPages) state.reportPage = totalPages;
    if (state.reportPage < 1) state.reportPage = 1;

    const startIdx = (state.reportPage - 1) * state.reportPageSize;
    const pageData = data.slice(startIdx, startIdx + state.reportPageSize);

    pageData.forEach((v, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
      <td>${startIdx + i + 1}</td>
      <td><span class="type-badge">${v.type}</span></td>
      <td><span class="sev-badge sev-${v.severity.toLowerCase()}">${v.severity}</span></td>
      <td title="${v.url}">${truncate(v.url, 55)}</td>
      <td>${v.field || '—'}</td>
      <td>—</td>
      <td>${v.time || '—'}</td>
    `;
        tbody.appendChild(tr);
    });

    // Update pagination controls
    const pag = document.getElementById('report-pagination');
    if (pag) {
        pag.style.display = totalPages > 1 ? '' : 'none';
        document.getElementById('report-page-label').textContent = `Page ${state.reportPage} of ${totalPages}`;
        document.getElementById('report-prev-btn').disabled = state.reportPage <= 1;
        document.getElementById('report-next-btn').disabled = state.reportPage >= totalPages;
    }
}

function reportNextPage() {
    state.reportPage++;
    renderReportTable(_reportDataCache);
}

function reportPrevPage() {
    state.reportPage--;
    renderReportTable(_reportDataCache);
}

function filterReport() {
    loadAndRenderReport();
}

async function exportCSV() {
    window.location.href = '/api/findings/export/csv';
    showToast('📊 CSV exported');
}

async function exportHTML() {
    window.location.href = '/api/findings/export/html';
    showToast('🌐 HTML exported');
}

async function exportJSON() {
    window.location.href = '/api/findings/export/json';
    showToast('💾 JSON exported');
}

async function clearReport() {
    if (!confirm('Clear all findings?')) return;
    await apiDelete('/api/findings');
    state.findings = [];
    state.stats.vulns = 0;
    updateStats();
    renderReportTable([]);
    updateDashboardTable();
    drawDonut();
    showToast('🗑 Report cleared');
}

// ── Modal ─────────────────────────────────────────────────────────────────────
function showDetail(id) {
    const v = state.findings.find(f => f.id === id || f.id === String(id));
    if (!v) return;
    document.getElementById('modal-title').textContent = `${v.type} XSS — ${v.severity} Severity`;
    document.getElementById('modal-body').innerHTML = `
    <div class="detail-row"><span class="detail-label">Type</span><span class="detail-value">${v.type} XSS</span></div>
    <div class="detail-row"><span class="detail-label">Severity</span><span class="detail-value">${v.severity}</span></div>
    <div class="detail-row"><span class="detail-label">URL</span><span class="detail-value">${v.url}</span></div>
    <div class="detail-row"><span class="detail-label">Field</span><span class="detail-value">${v.field || '—'}</span></div>
    <div class="detail-row"><span class="detail-label">Payload</span><span class="detail-value" style="font-family:monospace;color:var(--accent)">${escHtml(v.payload || '—')}</span></div>
    <div class="detail-row"><span class="detail-label">Detected at</span><span class="detail-value">${v.time || '—'}</span></div>
    <div class="detail-row"><span class="detail-label">Screenshot</span><span class="detail-value">${v.screenshot || 'Not captured'}</span></div>
    <hr style="border-color:var(--border);margin:14px 0">
    <p style="color:var(--text-dim);font-size:0.8rem">This vulnerability was detected during an authorized scan. Remediation: sanitize and encode all user-supplied data before rendering in HTML context.</p>
  `;
    document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('open');
}

// ── Theme toggle ──────────────────────────────────────────────────────────────
function toggleTheme() {
    const isLight = document.body.classList.toggle('light');
    const btn = document.getElementById('theme-toggle');
    btn.textContent = isLight ? '☀️' : '🌙';
    btn.title = isLight ? 'Switch to Dark Mode' : 'Switch to Light Mode';
    localStorage.setItem('xss-theme', isLight ? 'light' : 'dark');
    drawDonut(); // redraw with correct center color
    showToast(isLight ? '☀️ Light mode enabled' : '🌙 Dark mode enabled');
}

function restoreTheme() {
    const saved = localStorage.getItem('xss-theme');
    if (saved === 'light') {
        document.body.classList.add('light');
        const btn = document.getElementById('theme-toggle');
        if (btn) { btn.textContent = '☀️'; btn.title = 'Switch to Dark Mode'; }
    }
}

// ── Settings ──────────────────────────────────────────────────────────────────
const ACCENT_MAP = {
    red: { accent: '#ff3b3b', accent2: '#ff6b6b', glow: 'rgba(255,59,59,0.35)' },
    blue: { accent: '#4fc3f7', accent2: '#81d4fa', glow: 'rgba(79,195,247,0.35)' },
    green: { accent: '#06d6a0', accent2: '#34e8b5', glow: 'rgba(6,214,160,0.35)' },
    purple: { accent: '#bb86fc', accent2: '#ce93d8', glow: 'rgba(187,134,252,0.35)' },
};

function setAccent(color, btn) {
    const map = ACCENT_MAP[color];
    if (!map) return;
    const root = document.documentElement;
    root.style.setProperty('--accent', map.accent);
    root.style.setProperty('--accent2', map.accent2);
    root.style.setProperty('--accent-glow', map.glow);
    document.querySelectorAll('.swatch').forEach(s => s.classList.remove('active'));
    btn.classList.add('active');
    showToast('🎨 Accent color updated');
}

// ── Toast ─────────────────────────────────────────────────────────────────────
let toastTimer;
function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function truncate(str, n) {
    if (!str) return '—';
    return str.length > n ? str.substring(0, n) + '…' : str;
}

function escHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function generateToken() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(n) {
    return Array.from(crypto.getRandomValues(new Uint8Array(n)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

function download(filename, content) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content]));
    a.download = filename;
    a.click();
}

// ── withLoading helper ───────────────────────────────────────────────────────
async function withLoading(buttonId, asyncFn) {
    const btn = document.getElementById(buttonId);
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Loading…';
    try {
        return await asyncFn();
    } catch (e) {
        showToast('⚠ Operation failed');
        console.error(e);
    } finally {
        btn.disabled = false;
        btn.textContent = original;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  INIT
// ══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
    restoreTheme();

    // Auth gate — redirect to login if not authenticated
    const authed = await checkAuth();
    if (!authed) return;

    await fetchStats();
    await renderPayloads();
    drawDonut();
    updateDashboardTable();
    navigate('dashboard');

    // Poll stats every 5 seconds
    state.statsPollTimer = setInterval(fetchStats, 5000);

    // Load existing findings from backend
    const existingFindings = await apiGet('/api/findings');
    if (existingFindings && existingFindings.length) {
        state.findings = existingFindings;
        updateDashboardTable();
        drawDonut();
    }

    // ── Payload grid scroll-to-top wiring ────────────────────────────────────
    const grid = document.getElementById('payload-grid');
    const scrollBtn = document.getElementById('scroll-top-btn');
    if (grid && scrollBtn) {
        grid.addEventListener('scroll', () => {
            if (grid.scrollTop > 120) {
                scrollBtn.classList.add('visible');
            } else {
                scrollBtn.classList.remove('visible');
            }
        });
    }
});

function scrollPayloadsToTop() {
    const grid = document.getElementById('payload-grid');
    if (grid) grid.scrollTo({ top: 0, behavior: 'smooth' });
}

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH — check session, logout, profile
// ══════════════════════════════════════════════════════════════════════════════

async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        if (res.status === 401) {
            window.location.href = '/login.html';
            return false;
        }
        const data = await res.json();
        if (data && data.user) {
            state.currentUser = data.user;
            renderSidebarUser(data.user);
            return true;
        }
    } catch (e) {
        console.warn('Auth check failed', e);
    }
    window.location.href = '/login.html';
    return false;
}

function renderSidebarUser(user) {
    const nameEl = document.getElementById('sidebar-username');
    const roleEl = document.getElementById('sidebar-role');
    const avatarEl = document.getElementById('sidebar-avatar');
    if (nameEl) nameEl.textContent = user.username || '—';
    if (roleEl) roleEl.textContent = user.role || 'user';
    if (avatarEl) {
        if (user.avatar_url) {
            avatarEl.innerHTML = `<img src="${user.avatar_url}" alt="avatar">`;
        } else {
            avatarEl.textContent = (user.username || '?')[0].toUpperCase();
        }
    }
}

async function handleLogout() {
    await apiPost('/api/auth/logout');
    window.location.href = '/login.html';
}

// ── Profile page ─────────────────────────────────────────────────────────────

async function loadProfile() {
    const data = await apiGet('/api/auth/me');
    if (!data || !data.user) return;
    const user = data.user;
    state.currentUser = user;

    // Update profile card
    const nameEl = document.getElementById('profile-display-name');
    const roleEl = document.getElementById('profile-role-badge');
    const emailEl = document.getElementById('profile-email-display');
    const joinedEl = document.getElementById('profile-joined');
    const lastLoginEl = document.getElementById('profile-last-login');
    const bioEl = document.getElementById('profile-bio-display');
    const avatarEl = document.getElementById('profile-avatar-lg');

    if (nameEl) nameEl.textContent = user.username || '—';
    if (roleEl) roleEl.textContent = user.role || 'user';
    if (emailEl) emailEl.textContent = user.email || 'Not set';
    if (joinedEl) joinedEl.textContent = 'Joined: ' + formatTimestamp(user.created_at);
    if (lastLoginEl) lastLoginEl.textContent = 'Last login: ' + (user.last_login ? formatTimestamp(user.last_login) : 'N/A');
    if (bioEl) bioEl.textContent = user.bio || 'No bio set.';
    if (avatarEl) {
        if (user.avatar_url) {
            avatarEl.innerHTML = `<img src="${user.avatar_url}" alt="avatar">`;
        } else {
            avatarEl.textContent = (user.username || '?')[0].toUpperCase();
        }
    }

    // Fill edit form
    const emailInput = document.getElementById('profile-email');
    const bioInput = document.getElementById('profile-bio');
    const avatarInput = document.getElementById('profile-avatar-url');
    if (emailInput) emailInput.value = user.email || '';
    if (bioInput) bioInput.value = user.bio || '';
    if (avatarInput) avatarInput.value = user.avatar_url || '';

    // Profile stats
    document.getElementById('profile-stat-scans').textContent = state.stats.scans || 0;
    document.getElementById('profile-stat-vulns').textContent = state.stats.vulns || 0;
    document.getElementById('profile-stat-sessions').textContent = state.stats.sessions || 0;

    // Also update sidebar
    renderSidebarUser(user);
}

function formatTimestamp(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

async function handleProfileUpdate(e) {
    e.preventDefault();
    const msgEl = document.getElementById('profile-edit-msg');
    msgEl.className = 'profile-form-msg';
    msgEl.textContent = '';

    const email = document.getElementById('profile-email').value.trim();
    const bio = document.getElementById('profile-bio').value.trim();
    const avatar_url = document.getElementById('profile-avatar-url').value.trim();

    const res = await fetch('/api/auth/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, bio, avatar_url }),
    });
    const data = await res.json();

    if (res.ok && data.user) {
        msgEl.className = 'profile-form-msg success';
        msgEl.textContent = '✓ Profile updated successfully';
        state.currentUser = data.user;
        renderSidebarUser(data.user);
        loadProfile();
        showToast('✅ Profile saved');
    } else {
        msgEl.className = 'profile-form-msg error';
        msgEl.textContent = '⚠ ' + (data.error || 'Update failed');
    }
}

async function handlePasswordChange(e) {
    e.preventDefault();
    const msgEl = document.getElementById('pw-change-msg');
    msgEl.className = 'profile-form-msg';
    msgEl.textContent = '';

    const oldPassword = document.getElementById('pw-current').value;
    const newPassword = document.getElementById('pw-new').value;
    const confirmPassword = document.getElementById('pw-confirm').value;

    if (newPassword.length < 6) {
        msgEl.className = 'profile-form-msg error';
        msgEl.textContent = '⚠ New password must be at least 6 characters';
        return;
    }

    if (newPassword !== confirmPassword) {
        msgEl.className = 'profile-form-msg error';
        msgEl.textContent = '⚠ Passwords do not match';
        return;
    }

    const res = await fetch('/api/auth/password', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
    const data = await res.json();

    if (res.ok) {
        msgEl.className = 'profile-form-msg success';
        msgEl.textContent = '✓ Password changed successfully';
        document.getElementById('pw-current').value = '';
        document.getElementById('pw-new').value = '';
        document.getElementById('pw-confirm').value = '';
        showToast('🔑 Password updated');
    } else {
        msgEl.className = 'profile-form-msg error';
        msgEl.textContent = '⚠ ' + (data.error || 'Password change failed');
    }
}
