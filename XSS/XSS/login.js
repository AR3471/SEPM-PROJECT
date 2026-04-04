/* ═══════════════════════════════════════════════════════════
   XSS Toolkit — login.js
   Handles login / register forms and redirects
   ═══════════════════════════════════════════════════════════ */

// ── Particles ────────────────────────────────────────────────────────────────
function spawnParticles() {
    const container = document.getElementById('particles');
    const count = 25;
    for (let i = 0; i < count; i++) {
        const p = document.createElement('div');
        p.className = 'particle';
        p.style.left = Math.random() * 100 + '%';
        p.style.animationDuration = (6 + Math.random() * 10) + 's';
        p.style.animationDelay = (Math.random() * 8) + 's';
        p.style.width = p.style.height = (2 + Math.random() * 3) + 'px';
        const colors = ['#ff3b3b', '#ff6b6b', '#bb86fc', '#4fc3f7', '#ffffff'];
        p.style.background = colors[Math.floor(Math.random() * colors.length)];
        container.appendChild(p);
    }
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(tab) {
    const indicator = document.getElementById('tab-indicator');
    const loginTab = document.getElementById('tab-login');
    const registerTab = document.getElementById('tab-register');
    const loginForm = document.getElementById('form-login');
    const registerForm = document.getElementById('form-register');

    // Clear errors
    document.getElementById('login-error').classList.remove('visible');
    document.getElementById('login-error').textContent = '';
    document.getElementById('register-error').classList.remove('visible');
    document.getElementById('register-error').textContent = '';

    if (tab === 'login') {
        indicator.classList.remove('right');
        loginTab.classList.add('active');
        registerTab.classList.remove('active');
        loginForm.classList.add('active');
        registerForm.classList.remove('active');
    } else {
        indicator.classList.add('right');
        registerTab.classList.add('active');
        loginTab.classList.remove('active');
        registerForm.classList.add('active');
        loginForm.classList.remove('active');
    }
}

// ── Toggle password visibility ────────────────────────────────────────────────
function togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🙈';
    } else {
        input.type = 'password';
        btn.textContent = '👁';
    }
}

// ── Show error ────────────────────────────────────────────────────────────────
function showError(elementId, message) {
    const el = document.getElementById(elementId);
    el.textContent = '⚠ ' + message;
    el.classList.add('visible');
}

function clearError(elementId) {
    const el = document.getElementById(elementId);
    el.textContent = '';
    el.classList.remove('visible');
}

// ── Show success animation ────────────────────────────────────────────────────
function showSuccess(message) {
    const card = document.getElementById('auth-card');
    card.classList.add('success');
    card.style.position = 'relative';

    const overlay = document.createElement('div');
    overlay.className = 'success-overlay';
    overlay.innerHTML = `
        <div class="success-check">✓</div>
        <span class="success-text">${message}</span>
    `;
    card.appendChild(overlay);
}

// ── Login handler ─────────────────────────────────────────────────────────────
async function handleLogin(e) {
    e.preventDefault();
    clearError('login-error');

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showError('login-error', 'Please fill in all fields');
        return;
    }

    const btn = document.getElementById('login-btn');
    btn.classList.add('loading');

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        const data = await res.json();

        if (res.ok && data.user) {
            showSuccess('Welcome back, ' + data.user.username + '!');
            setTimeout(() => {
                window.location.href = '/';
            }, 1200);
        } else {
            btn.classList.remove('loading');
            showError('login-error', data.error || 'Invalid credentials');
        }
    } catch (err) {
        btn.classList.remove('loading');
        showError('login-error', 'Connection failed — is the server running?');
    }
}

// ── Register handler ──────────────────────────────────────────────────────────
let _pendingVerificationEmail = '';

async function handleRegister(e) {
    e.preventDefault();
    clearError('register-error');

    const username = document.getElementById('reg-username').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;

    if (!username || !email || !password || !confirm) {
        showError('register-error', 'Please fill in all fields');
        return;
    }

    if (username.length < 3) {
        showError('register-error', 'Username must be at least 3 characters');
        return;
    }

    if (password.length < 6) {
        showError('register-error', 'Password must be at least 6 characters');
        return;
    }

    if (password !== confirm) {
        showError('register-error', 'Passwords do not match');
        return;
    }

    const btn = document.getElementById('register-btn');
    btn.classList.add('loading');

    try {
        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password }),
        });

        const data = await res.json();

        if (res.ok && data.user) {
            // Direct registration (no SMTP) — auto-login
            showSuccess('Account created!');
            setTimeout(() => {
                window.location.href = '/';
            }, 1200);
        } else if (data.status === 'verification_required') {
            // SMTP is configured — show verification code form
            btn.classList.remove('loading');
            _pendingVerificationEmail = data.email || email;
            showVerificationForm(_pendingVerificationEmail);
        } else {
            btn.classList.remove('loading');
            showError('register-error', data.error || 'Registration failed');
        }
    } catch (err) {
        btn.classList.remove('loading');
        showError('register-error', 'Connection failed — is the server running?');
    }
}

// ── Verification form handling ────────────────────────────────────────────────
function showVerificationForm(email) {
    // Hide register form, show verification form
    document.getElementById('form-register').classList.remove('active');
    const vForm = document.getElementById('form-verify');
    if (vForm) {
        vForm.classList.add('active');
        document.getElementById('verify-email-display').textContent = email;
        document.getElementById('verify-code').value = '';
        document.getElementById('verify-code').focus();
    }
    // Hide tab switcher
    document.querySelector('.auth-tabs-wrap').style.display = 'none';
}

async function handleVerify(e) {
    e.preventDefault();
    clearError('verify-error');

    const code = document.getElementById('verify-code').value.trim();
    if (!code) {
        showError('verify-error', 'Please enter the verification code');
        return;
    }

    const btn = document.getElementById('verify-btn');
    btn.classList.add('loading');

    try {
        const res = await fetch('/api/auth/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: _pendingVerificationEmail, code }),
        });

        const data = await res.json();

        if (res.ok && data.user) {
            showSuccess('Email verified!');
            setTimeout(() => {
                window.location.href = '/';
            }, 1200);
        } else {
            btn.classList.remove('loading');
            showError('verify-error', data.error || 'Invalid verification code');
        }
    } catch (err) {
        btn.classList.remove('loading');
        showError('verify-error', 'Connection failed — is the server running?');
    }
}

async function handleResend() {
    clearError('verify-error');

    try {
        const res = await fetch('/api/auth/resend', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: _pendingVerificationEmail }),
        });

        const data = await res.json();

        if (res.ok) {
            const el = document.getElementById('verify-error');
            el.textContent = '✓ New code sent to ' + _pendingVerificationEmail;
            el.classList.add('visible');
            el.style.color = '#06d6a0';
        } else {
            showError('verify-error', data.error || 'Failed to resend code');
        }
    } catch (err) {
        showError('verify-error', 'Connection failed');
    }
}

// ── Theme toggle for login page ───────────────────────────────────────────────
function toggleTheme() {
    const body = document.body;
    const isLight = body.classList.toggle('light');
    const btn = document.getElementById('theme-toggle-login');

    if (btn) {
        btn.textContent = isLight ? '☀️' : '🌙';
        btn.title = isLight ? 'Switch to dark mode' : 'Switch to light mode';
    }

    localStorage.setItem('xss-login-theme', isLight ? 'light' : 'dark');
}

function restoreTheme() {
    const saved = localStorage.getItem('xss-login-theme');
    if (saved === 'light') {
        document.body.classList.add('light');
    } else {
        document.body.classList.remove('light');
    }

    const btn = document.getElementById('theme-toggle-login');
    if (btn) {
        const isLight = document.body.classList.contains('light');
        btn.textContent = isLight ? '☀️' : '🌙';
        btn.title = isLight ? 'Switch to dark mode' : 'Switch to light mode';
    }
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    restoreTheme();
    spawnParticles();

    // If already logged in, redirect to dashboard
    fetch('/api/auth/me')
        .then(r => {
            if (r.ok) window.location.href = '/';
        })
        .catch(() => { });
});
