// ═══════════════════════════════════════════════════════
//  Password Police — App Logic
//  First-run setup + EmailJS recovery + AES-256 vault
// ═══════════════════════════════════════════════════════

const MAX_ATTEMPTS   = 5;
const AUTO_LOCK_SEC  = 60;
const LOCKOUT_HOURS  = 24;

// Storage keys
const KEY_VAULT        = 'pp_vault_v1';
const KEY_LOCKOUT      = 'pp_lockout_until';
const KEY_FAIL_COUNT   = 'pp_fail_count';
const KEY_SETUP_DONE   = 'pp_setup_done';
const KEY_PW_HASH      = 'pp_pw_hash';        // PBKDF2 hash used to verify PW
const KEY_PW_SALT      = 'pp_pw_salt';        // salt for PW verification
const KEY_RECOVERY     = 'pp_recovery_email'; // stored (plaintext — not sensitive)
const KEY_EMAILJS_SVC  = 'pp_ejs_service';
const KEY_EMAILJS_TPL  = 'pp_ejs_template';
const KEY_EMAILJS_PUB  = 'pp_ejs_pubkey';

let masterPassword = null;
let entries        = [];
let failCount      = 0;
let lockTimer      = null;
let secondsLeft    = AUTO_LOCK_SEC;

// ── Storage bridge (Electron IPC or localStorage) ───────
const store = {
  async get(key)      { return window.electronStore ? window.electronStore.get(key)        : localStorage.getItem(key); },
  async set(key, val) { return window.electronStore ? window.electronStore.set(key, val)   : localStorage.setItem(key, val); },
  async del(key)      { return window.electronStore ? window.electronStore.delete(key)     : localStorage.removeItem(key); },
};

// ── AES-256-GCM ──────────────────────────────────────────
async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptData(data, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(data));
  const buf  = new Uint8Array(28 + ct.byteLength);
  buf.set(salt, 0); buf.set(iv, 16); buf.set(new Uint8Array(ct), 28);
  return btoa(String.fromCharCode(...buf));
}

async function decryptData(b64, password) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const key = await deriveKey(password, buf.slice(0, 16));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(16, 28) }, key, buf.slice(28));
  return new TextDecoder().decode(plain);
}

// Hash password for verification (separate salt, not the vault salt)
async function hashPassword(password, saltBytes) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
  const key  = await deriveKey(password, salt);
  // Export is not allowed on non-extractable keys — use encrypt a known plaintext instead
  const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, key, new TextEncoder().encode('pp-verify'));
  return { hash: btoa(String.fromCharCode(...new Uint8Array(ct))), salt: btoa(String.fromCharCode(...salt)) };
}

async function verifyPassword(password) {
  const storedHash = await store.get(KEY_PW_HASH);
  const storedSalt = await store.get(KEY_PW_SALT);
  if (!storedHash || !storedSalt) return false;
  const saltBytes = Uint8Array.from(atob(storedSalt), c => c.charCodeAt(0));
  const { hash } = await hashPassword(password, saltBytes);
  return hash === storedHash;
}

// ── Vault ────────────────────────────────────────────────
async function saveVault() {
  await store.set(KEY_VAULT, await encryptData(JSON.stringify(entries), masterPassword));
}

async function loadVault() {
  const stored = await store.get(KEY_VAULT);
  if (!stored) { entries = []; return; }
  entries = JSON.parse(await decryptData(stored, masterPassword));
}

// ── Lockout ──────────────────────────────────────────────
async function isLockedOut() {
  const until = await store.get(KEY_LOCKOUT);
  return until && Date.now() < parseInt(until, 10);
}
async function getLockoutUntil() {
  return parseInt(await store.get(KEY_LOCKOUT) || '0', 10);
}
async function applyLockout() {
  await store.set(KEY_LOCKOUT, String(Date.now() + LOCKOUT_HOURS * 3600000));
}
async function clearLockout() {
  await store.del(KEY_LOCKOUT);
  await store.del(KEY_FAIL_COUNT);
  failCount = 0;
}

// ── Recovery code generation ─────────────────────────────
function generateCode() {
  return Array.from(crypto.getRandomValues(new Uint8Array(3)))
    .map(b => b.toString(10).padStart(3, '0')).join('-');
}

let pendingRecoveryCode = null;

async function sendRecoveryEmail() {
  const email  = await store.get(KEY_RECOVERY);
  const svcId  = await store.get(KEY_EMAILJS_SVC);
  const tplId  = await store.get(KEY_EMAILJS_TPL);
  const pubKey = await store.get(KEY_EMAILJS_PUB);

  if (!email || !svcId || !tplId || !pubKey) return { ok: false, reason: 'no_config' };

  pendingRecoveryCode = generateCode();

  try {
    // Load EmailJS SDK dynamically
    if (!window.emailjs) {
      await new Promise((res, rej) => {
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js';
        s.onload = res; s.onerror = rej;
        document.head.appendChild(s);
      });
    }
    emailjs.init({ publicKey: pubKey });
    await emailjs.send(svcId, tplId, {
      to_email:      email,
      recovery_code: pendingRecoveryCode,
      app_name:      'Password Police',
    });
    return { ok: true };
  } catch (e) {
    console.error('EmailJS error', e);
    return { ok: false, reason: 'send_failed' };
  }
}

// ── Utilities ────────────────────────────────────────────
function esc(s)     { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escA(s)    { return (s||'').replace(/'/g,'&#39;').replace(/"/g,'&quot;'); }
function showToast(msg, type='success') {
  document.querySelectorAll('.toast').forEach(t => t.remove());
  const t = document.createElement('div');
  t.className = `toast ${type}`; t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2500);
}
function getFavicon(url) {
  const map = {'google.com':'🔵','github.com':'🐙','twitter.com':'🐦','x.com':'✖️','facebook.com':'📘','instagram.com':'📸','amazon.com':'📦','netflix.com':'🎬','spotify.com':'🎵','apple.com':'🍎','microsoft.com':'🪟','discord.com':'💬','reddit.com':'🟠','linkedin.com':'💼'};
  try { return map[new URL(url.startsWith('http')?url:'https://'+url).hostname.replace('www.','')] ?? '🔑'; } catch { return '🔑'; }
}

// ── Tung Tung flash ──────────────────────────────────────
function showTungTung(attemptsLeft) {
  document.querySelectorAll('.tung-overlay').forEach(e => e.remove());
  const el = document.createElement('div');
  el.className = 'tung-overlay';
  const sub = attemptsLeft <= 0
    ? '💀 INITIATING LOCKOUT...'
    : `⚠️ ${attemptsLeft} ATTEMPT${attemptsLeft===1?'':'S'} UNTIL LOCKED OUT`;
  el.innerHTML = `
    <img class="tung-img" src="${IMG_TUNG_LAUGH}" alt="Tung Tung" />
    <div class="tung-text">YOU HAVE BEEN CAUGHT BY<br>TUNG TUNG TUNG SAHUR!</div>
    <div class="tung-sub">${sub}</div>`;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 1800);
}

// ── Killed / lockout screen ──────────────────────────────
function renderKilled(until) {
  document.querySelectorAll('.tung-overlay, .killed-overlay').forEach(e => e.remove());
  const el = document.createElement('div');
  el.className = 'killed-overlay'; el.id = 'killedOverlay';
  el.innerHTML = `
    <img class="killed-img" src="${IMG_TUNG_KILL}" alt="Tung Tung Kill" />
    <div class="killed-title">YOU HAVE BEEN KILLED BY<br>TUNG TUNG TUNG SAHUR!</div>
    <div class="killed-sub">YOU ARE LOCKED OUT FOR 24 HOURS</div>
    <div class="killed-timer" id="lockoutTimer">--:--:--</div>`;
  document.body.appendChild(el);
  const tick = () => {
    const diff = until - Date.now();
    if (diff <= 0) { clearLockout(); el.remove(); renderLock(); return; }
    const h = Math.floor(diff/3600000), m = Math.floor((diff%3600000)/60000), s = Math.floor((diff%60000)/1000);
    const timerEl = document.getElementById('lockoutTimer');
    if (timerEl) timerEl.textContent = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
    setTimeout(tick, 1000);
  };
  tick();
}

// ════════════════════════════════════════════════════════
//  FIRST-RUN SETUP SCREEN
// ════════════════════════════════════════════════════════
function renderSetup() {
  document.getElementById('app').innerHTML = `
    <div class="lock-screen" style="animation: fadeUp 0.5s ease both">
      <div class="logo">
        <div class="logo-icon">🚔</div>
        <div class="logo-text">Password <span>Police</span></div>
      </div>
      <div class="lock-card">
        <div class="lock-icon-wrap">🛡️</div>
        <h2>Create Your Vault</h2>
        <p>First time here. Set a master password to protect your vault.<br>
           You'll enter this every time you open the app.</p>

        <div class="form-field" style="margin-top:20px;text-align:left">
          <label>Master Password</label>
          <div class="pw-wrap input-group" style="margin-bottom:0">
            <input type="password" id="s_pw" placeholder="Choose a strong password…" />
            <button class="eye-btn" id="s_eye1">👁</button>
          </div>
        </div>

        <div class="form-field" style="text-align:left;margin-top:12px">
          <label>Confirm Password</label>
          <div class="pw-wrap input-group" style="margin-bottom:0">
            <input type="password" id="s_pw2" placeholder="Repeat password…" />
            <button class="eye-btn" id="s_eye2">👁</button>
          </div>
        </div>

        <div class="strength-bar-wrap" style="margin-top:10px">
          <div class="strength-bar"><div class="strength-fill" id="strengthFill"></div></div>
          <span class="strength-label" id="strengthLabel">Enter a password</span>
        </div>

        <div class="divider"></div>

        <div class="recovery-section">
          <div class="recovery-toggle" id="recoveryToggle">
            <span>📧 Add recovery email</span>
            <span class="optional-badge">optional</span>
          </div>
          <div class="recovery-fields" id="recoveryFields" style="display:none">
            <div class="form-field" style="text-align:left;margin-top:12px">
              <label>Recovery Email</label>
              <input type="email" id="s_email" placeholder="you@example.com" />
            </div>
            <div class="emailjs-info">
              <p>Password Police uses <strong>EmailJS</strong> to send recovery codes.<br>
              It's free — <a href="#" id="ejsLink">set up your EmailJS account</a> and paste your IDs below.</p>
            </div>
            <div class="form-field" style="text-align:left">
              <label>EmailJS Service ID</label>
              <input type="text" id="s_svc" placeholder="service_xxxxxxx" />
            </div>
            <div class="form-field" style="text-align:left">
              <label>EmailJS Template ID</label>
              <input type="text" id="s_tpl" placeholder="template_xxxxxxx" />
            </div>
            <div class="form-field" style="text-align:left">
              <label>EmailJS Public Key</label>
              <input type="text" id="s_pub" placeholder="xxxxxxxxxxxxxxxxxxxx" />
            </div>
            <p class="muted-note">Your EmailJS template must have variables: <code>to_email</code>, <code>recovery_code</code>, <code>app_name</code></p>
          </div>
        </div>

        <div id="setup_error" class="error-msg" style="display:none"></div>

        <button class="btn-primary" id="setupBtn" style="margin-top:20px">CREATE VAULT</button>
      </div>
    </div>`;

  // Eye toggles
  document.getElementById('s_eye1').addEventListener('click', () => toggleEye('s_pw', 's_eye1'));
  document.getElementById('s_eye2').addEventListener('click', () => toggleEye('s_pw2', 's_eye2'));

  // Strength meter
  document.getElementById('s_pw').addEventListener('input', e => updateStrength(e.target.value));

  // Recovery toggle
  document.getElementById('recoveryToggle').addEventListener('click', () => {
    const fields = document.getElementById('recoveryFields');
    const isOpen = fields.style.display !== 'none';
    fields.style.display = isOpen ? 'none' : 'block';
    document.getElementById('recoveryToggle').classList.toggle('open', !isOpen);
  });

  document.getElementById('ejsLink').addEventListener('click', e => {
    e.preventDefault();
    if (window.require) { const { shell } = window.require('electron'); shell.openExternal('https://www.emailjs.com/'); }
    else window.open('https://www.emailjs.com/', '_blank');
  });

  document.getElementById('setupBtn').addEventListener('click', handleSetup);
  document.getElementById('s_pw2').addEventListener('keydown', e => { if (e.key === 'Enter') handleSetup(); });
}

function updateStrength(pw) {
  const fill  = document.getElementById('strengthFill');
  const label = document.getElementById('strengthLabel');
  if (!fill) return;
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const levels = [
    { pct: '0%',   color: 'transparent', text: 'Enter a password' },
    { pct: '20%',  color: '#ff4757',     text: 'Very weak' },
    { pct: '40%',  color: '#ff6b35',     text: 'Weak' },
    { pct: '60%',  color: '#ffa502',     text: 'Fair' },
    { pct: '80%',  color: '#2ed573',     text: 'Strong' },
    { pct: '100%', color: '#00e5a0',     text: 'Very strong' },
  ];
  const l = levels[score];
  fill.style.width = l.pct;
  fill.style.background = l.color;
  label.textContent = l.text;
  label.style.color = l.color === 'transparent' ? 'var(--muted)' : l.color;
}

async function handleSetup() {
  const pw    = document.getElementById('s_pw').value;
  const pw2   = document.getElementById('s_pw2').value;
  const email = document.getElementById('s_email')?.value.trim();
  const svc   = document.getElementById('s_svc')?.value.trim();
  const tpl   = document.getElementById('s_tpl')?.value.trim();
  const pub   = document.getElementById('s_pub')?.value.trim();

  const errEl = document.getElementById('setup_error');
  const showErr = msg => { errEl.textContent = msg; errEl.style.display = 'block'; };

  if (!pw)          return showErr('Please choose a master password.');
  if (pw.length < 8) return showErr('Password must be at least 8 characters.');
  if (pw !== pw2)   return showErr('Passwords do not match.');

  // If recovery fields are open, validate them
  const recoveryOpen = document.getElementById('recoveryFields').style.display !== 'none';
  if (recoveryOpen && email) {
    if (!svc || !tpl || !pub) return showErr('Fill in all EmailJS fields or close the recovery section.');
  }

  errEl.style.display = 'none';
  document.getElementById('setupBtn').textContent = 'SETTING UP...';
  document.getElementById('setupBtn').disabled = true;

  // Hash & store the password
  const { hash, salt } = await hashPassword(pw);
  await store.set(KEY_PW_HASH, hash);
  await store.set(KEY_PW_SALT, salt);
  await store.set(KEY_SETUP_DONE, '1');

  // Store recovery config if provided
  if (recoveryOpen && email && svc && tpl && pub) {
    await store.set(KEY_RECOVERY,    email);
    await store.set(KEY_EMAILJS_SVC, svc);
    await store.set(KEY_EMAILJS_TPL, tpl);
    await store.set(KEY_EMAILJS_PUB, pub);
  }

  // Init empty vault
  masterPassword = pw;
  entries = [];
  await saveVault();

  showToast('✓ Vault created!');
  setTimeout(() => renderVault(), 600);
}

// ════════════════════════════════════════════════════════
//  LOCK / UNLOCK SCREEN
// ════════════════════════════════════════════════════════
function renderLock(error = '') {
  clearInterval(lockTimer);
  masterPassword = null;

  const pips = Array.from({ length: MAX_ATTEMPTS }, (_, i) =>
    `<div class="attempt-pip ${i < failCount ? 'used' : ''}"></div>`
  ).join('');

  document.getElementById('app').innerHTML = `
    <div class="lock-screen">
      <div class="logo">
        <div class="logo-icon">🚔</div>
        <div class="logo-text">Password <span>Police</span></div>
      </div>
      <div class="lock-card">
        <div class="lock-icon-wrap">🔒</div>
        <h2>Welcome Back</h2>
        <p>Enter your master password to unlock your vault.</p>
        <div class="input-group">
          <input type="password" id="masterPwInput" placeholder="Master password…" autocomplete="current-password" />
          <button class="eye-btn" id="eyeBtn">👁</button>
        </div>
        ${error ? `<div class="error-msg">✗ ${error}</div>` : ''}
        <button class="btn-primary" id="unlockBtn" style="margin-top:${error?'12':'4'}px">UNLOCK VAULT</button>
        <div class="attempts-bar">${pips}</div>
        <button class="forgot-btn" id="forgotBtn">Forgot password?</button>
      </div>
    </div>`;

  const inp = document.getElementById('masterPwInput');
  inp.focus();
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') handleUnlock(); });
  document.getElementById('unlockBtn').addEventListener('click', handleUnlock);
  document.getElementById('eyeBtn').addEventListener('click', () => toggleEye('masterPwInput', 'eyeBtn'));
  document.getElementById('forgotBtn').addEventListener('click', handleForgot);
}

async function handleUnlock() {
  const pw = document.getElementById('masterPwInput')?.value;
  if (!pw) return;

  const ok = await verifyPassword(pw);
  if (ok) {
    failCount = 0;
    await store.del(KEY_FAIL_COUNT);
    masterPassword = pw;
    await loadVault();
    renderVault();
  } else {
    failCount++;
    await store.set(KEY_FAIL_COUNT, String(failCount));
    const left = MAX_ATTEMPTS - failCount;
    showTungTung(left);
    if (left <= 0) {
      setTimeout(async () => { await applyLockout(); renderKilled(await getLockoutUntil()); }, 1900);
    } else {
      setTimeout(() => renderLock('Incorrect password. Try again.'), 1900);
    }
  }
}

// ── Forgot password flow ─────────────────────────────────
async function handleForgot() {
  const email = await store.get(KEY_RECOVERY);
  if (!email) {
    renderForgotNoEmail();
    return;
  }
  renderForgotSend(email);
}

function renderForgotNoEmail() {
  showModal(`
    <div class="modal-header"><h3>// FORGOT PASSWORD</h3><div class="close-btn" id="closeModal">✕</div></div>
    <div style="text-align:center;padding:16px 0">
      <div style="font-size:40px;margin-bottom:16px">😟</div>
      <p style="color:var(--text);margin-bottom:8px;font-weight:600">No recovery email set</p>
      <p style="color:var(--muted);font-size:13px;line-height:1.6">
        You didn't set up a recovery email during setup.<br>
        Unfortunately your vault cannot be recovered.<br><br>
        You can <strong style="color:var(--danger)">reset the app</strong> to start fresh — this will delete all saved passwords.
      </p>
    </div>
    <div class="modal-footer" style="flex-direction:column;gap:8px">
      <button class="btn-ghost" id="closeModal2" style="flex:none;width:100%">Cancel</button>
      <button class="btn-danger" id="resetBtn">RESET VAULT (deletes everything)</button>
    </div>
  `);
  document.getElementById('closeModal').addEventListener('click', closeModal);
  document.getElementById('closeModal2').addEventListener('click', closeModal);
  document.getElementById('resetBtn').addEventListener('click', handleReset);
}

function renderForgotSend(email) {
  const masked = email.replace(/(.{2})(.*)(@.*)/, (_, a, b, c) => a + '*'.repeat(b.length) + c);
  showModal(`
    <div class="modal-header"><h3>// FORGOT PASSWORD</h3><div class="close-btn" id="closeModal">✕</div></div>
    <div style="text-align:center;padding:8px 0 16px">
      <div style="font-size:40px;margin-bottom:16px">📧</div>
      <p style="color:var(--text);margin-bottom:8px;font-weight:600">Send recovery code</p>
      <p style="color:var(--muted);font-size:13px;line-height:1.6">
        We'll email a 9-digit code to<br>
        <strong style="color:var(--accent)">${masked}</strong>
      </p>
    </div>
    <div class="modal-footer">
      <button class="btn-ghost" id="closeModal2">Cancel</button>
      <button class="btn-save" id="sendCodeBtn">SEND CODE</button>
    </div>
  `);
  document.getElementById('closeModal').addEventListener('click', closeModal);
  document.getElementById('closeModal2').addEventListener('click', closeModal);
  document.getElementById('sendCodeBtn').addEventListener('click', async () => {
    const btn = document.getElementById('sendCodeBtn');
    btn.textContent = 'SENDING...'; btn.disabled = true;
    const result = await sendRecoveryEmail();
    closeModal();
    if (result.ok) {
      renderEnterCode();
    } else {
      showToast('⚠ Failed to send email. Check internet connection.', 'error');
      renderLock();
    }
  });
}

function renderEnterCode() {
  showModal(`
    <div class="modal-header"><h3>// ENTER RECOVERY CODE</h3><div class="close-btn" id="closeModal">✕</div></div>
    <div style="text-align:center;padding:8px 0 16px">
      <div style="font-size:40px;margin-bottom:12px">🔓</div>
      <p style="color:var(--muted);font-size:13px;margin-bottom:16px">Check your email and enter the code below.</p>
      <input type="text" id="codeInput" placeholder="000-000-000"
        style="width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:14px;color:var(--text);font-family:var(--mono);font-size:20px;text-align:center;outline:none;letter-spacing:4px" />
      <div id="codeError" class="error-msg" style="display:none;margin-top:8px"></div>
    </div>
    <div style="text-align:center;margin-bottom:12px">
      <p style="color:var(--muted);font-size:13px">After verifying, you'll set a new password.</p>
    </div>
    <div class="modal-footer">
      <button class="btn-ghost" id="closeModal2">Cancel</button>
      <button class="btn-save" id="verifyCodeBtn">VERIFY CODE</button>
    </div>
  `);
  document.getElementById('closeModal').addEventListener('click',  () => { closeModal(); renderLock(); });
  document.getElementById('closeModal2').addEventListener('click', () => { closeModal(); renderLock(); });
  document.getElementById('verifyCodeBtn').addEventListener('click', () => {
    const entered = document.getElementById('codeInput').value.trim();
    if (entered === pendingRecoveryCode) {
      closeModal();
      renderSetNewPassword();
    } else {
      const err = document.getElementById('codeError');
      err.textContent = '✗ Incorrect code. Check your email.';
      err.style.display = 'block';
    }
  });
  document.getElementById('codeInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('verifyCodeBtn').click();
  });
}

function renderSetNewPassword() {
  showModal(`
    <div class="modal-header"><h3>// SET NEW PASSWORD</h3></div>
    <div style="text-align:center;padding:4px 0 16px">
      <div style="font-size:36px;margin-bottom:12px">🔑</div>
      <p style="color:var(--muted);font-size:13px;margin-bottom:16px">Code verified! Choose a new master password.</p>
    </div>
    <div class="form-field" style="text-align:left">
      <label>New Password</label>
      <div class="pw-wrap"><input type="password" id="np_pw" placeholder="New password…" /><button class="eye-btn" id="np_eye1">👁</button></div>
    </div>
    <div class="form-field" style="text-align:left;margin-top:10px">
      <label>Confirm New Password</label>
      <div class="pw-wrap"><input type="password" id="np_pw2" placeholder="Repeat…" /><button class="eye-btn" id="np_eye2">👁</button></div>
    </div>
    <div class="strength-bar-wrap" style="margin-top:8px">
      <div class="strength-bar"><div class="strength-fill" id="strengthFill2"></div></div>
      <span class="strength-label" id="strengthLabel2">Enter a password</span>
    </div>
    <div id="np_error" class="error-msg" style="display:none;margin-top:8px"></div>
    <div class="modal-footer" style="margin-top:16px">
      <button class="btn-save" id="saveNewPwBtn" style="flex:1">SAVE NEW PASSWORD</button>
    </div>
  `);
  document.getElementById('np_eye1').addEventListener('click', () => toggleEye('np_pw', 'np_eye1'));
  document.getElementById('np_eye2').addEventListener('click', () => toggleEye('np_pw2', 'np_eye2'));
  document.getElementById('np_pw').addEventListener('input', e => {
    const fill  = document.getElementById('strengthFill2');
    const label = document.getElementById('strengthLabel2');
    if (!fill) return;
    const pw = e.target.value; let score = 0;
    if (pw.length>=8) score++; if (pw.length>=12) score++;
    if (/[A-Z]/.test(pw)) score++; if (/[0-9]/.test(pw)) score++; if (/[^A-Za-z0-9]/.test(pw)) score++;
    const levels=[{pct:'0%',color:'transparent',text:'Enter a password'},{pct:'20%',color:'#ff4757',text:'Very weak'},{pct:'40%',color:'#ff6b35',text:'Weak'},{pct:'60%',color:'#ffa502',text:'Fair'},{pct:'80%',color:'#2ed573',text:'Strong'},{pct:'100%',color:'#00e5a0',text:'Very strong'}];
    const l=levels[score]; fill.style.width=l.pct; fill.style.background=l.color; label.textContent=l.text; label.style.color=l.color==='transparent'?'var(--muted)':l.color;
  });
  document.getElementById('saveNewPwBtn').addEventListener('click', async () => {
    const pw  = document.getElementById('np_pw').value;
    const pw2 = document.getElementById('np_pw2').value;
    const err = document.getElementById('np_error');
    if (!pw || pw.length < 8) { err.textContent='Min 8 characters.'; err.style.display='block'; return; }
    if (pw !== pw2)            { err.textContent='Passwords do not match.'; err.style.display='block'; return; }

    // Re-encrypt the vault with the new password
    const oldPw = masterPassword;
    const loaded = await store.get(KEY_VAULT);
    let decrypted = [];
    if (loaded && oldPw) {
      try { decrypted = JSON.parse(await decryptData(loaded, oldPw)); } catch {}
    }

    const { hash, salt } = await hashPassword(pw);
    await store.set(KEY_PW_HASH, hash);
    await store.set(KEY_PW_SALT, salt);
    masterPassword = pw;
    entries = decrypted;
    await saveVault();
    pendingRecoveryCode = null;
    closeModal();
    showToast('✓ Password updated!');
    setTimeout(() => renderVault(), 500);
  });
}

async function handleReset() {
  if (!confirm('This will permanently delete ALL saved passwords. Are you sure?')) return;
  await store.del(KEY_VAULT);
  await store.del(KEY_PW_HASH);
  await store.del(KEY_PW_SALT);
  await store.del(KEY_SETUP_DONE);
  await store.del(KEY_RECOVERY);
  await store.del(KEY_EMAILJS_SVC);
  await store.del(KEY_EMAILJS_TPL);
  await store.del(KEY_EMAILJS_PUB);
  await clearLockout();
  closeModal();
  renderSetup();
}

// ════════════════════════════════════════════════════════
//  AUTO-LOCK TIMER
// ════════════════════════════════════════════════════════
function resetTimer() { secondsLeft = AUTO_LOCK_SEC; }

function startAutoLock() {
  clearInterval(lockTimer);
  secondsLeft = AUTO_LOCK_SEC;
  lockTimer = setInterval(() => {
    secondsLeft--;
    const te = document.getElementById('lockTimer');
    const fe = document.getElementById('progressFill');
    if (te) { te.textContent=`🔒 ${secondsLeft}s`; te.classList.toggle('warn', secondsLeft<=15); }
    if (fe) { fe.style.width=(secondsLeft/AUTO_LOCK_SEC*100)+'%'; fe.classList.toggle('danger', secondsLeft<=15); }
    if (secondsLeft <= 0) { clearInterval(lockTimer); stopAutoLock(); renderLock(); }
  }, 1000);
  document.addEventListener('mousemove', resetTimer);
  document.addEventListener('keydown',   resetTimer);
}

function stopAutoLock() {
  clearInterval(lockTimer);
  document.removeEventListener('mousemove', resetTimer);
  document.removeEventListener('keydown',   resetTimer);
}

// ════════════════════════════════════════════════════════
//  VAULT SCREEN
// ════════════════════════════════════════════════════════
function renderVault(search = '') {
  startAutoLock();
  const filtered = search
    ? entries.filter(e => [e.title,e.url,e.comment||''].some(v=>v.toLowerCase().includes(search.toLowerCase())))
    : entries;

  document.getElementById('app').innerHTML = `
    <div class="vault-screen">
      <div class="vault-header">
        <div class="logo">
          <div class="logo-icon">🚔</div>
          <div class="logo-text">Password <span>Police</span></div>
        </div>
        <div class="header-actions">
          <span class="lock-timer" id="lockTimer">🔒 ${secondsLeft}s</span>
          <div class="icon-btn" id="addBtn" title="Add entry">＋</div>
          <div class="icon-btn" id="lockBtn" title="Lock vault">🔒</div>
        </div>
      </div>
      <div class="progress-bar"><div class="progress-fill" id="progressFill" style="width:100%"></div></div>
      <div class="search-bar">
        <span class="search-icon">🔍</span>
        <input type="text" id="searchInput" placeholder="Search entries…" value="${esc(search)}" />
      </div>
      <div class="count-badge">${filtered.length} / ${entries.length} entries</div>
      <div class="entries-list">
        ${filtered.length===0
          ? `<div class="empty-state"><div class="empty-icon">🗄️</div><p>${entries.length===0?'No entries yet. Click ＋ to add one.':'No results.'}</p></div>`
          : filtered.map((e,i)=>entryHTML(e,i)).join('')}
      </div>
    </div>`;

  document.getElementById('addBtn').addEventListener('click', openAddModal);
  document.getElementById('lockBtn').addEventListener('click', () => { stopAutoLock(); renderLock(); });
  document.getElementById('searchInput').addEventListener('input', e => { resetTimer(); renderVault(e.target.value); });
  document.querySelectorAll('[data-copy-user]').forEach(b=>b.addEventListener('click',()=>copyText(b.dataset.copyUser,'Username')));
  document.querySelectorAll('[data-copy-pw]').forEach(b=>b.addEventListener('click',()=>copyText(b.dataset.copyPw,'Password')));
  document.querySelectorAll('[data-open-url]').forEach(b=>b.addEventListener('click',()=>openLogin(b.dataset.openUrl,b.dataset.pw)));
  document.querySelectorAll('[data-delete]').forEach(b=>b.addEventListener('click',()=>deleteEntry(Number(b.dataset.delete))));
}

function entryHTML(e, i) {
  const ri = entries.indexOf(e);
  return `
    <div class="entry-card" style="animation-delay:${i*0.04}s">
      <div class="entry-favicon">${getFavicon(e.url)}</div>
      <div class="entry-info">
        <div class="entry-title">${esc(e.title)}</div>
        <div class="entry-url">${esc(e.url)}</div>
        ${e.comment?`<div class="entry-comment">💬 ${esc(e.comment)}</div>`:''}
      </div>
      <div class="entry-actions">
        <div class="action-btn copy"   title="Copy username" data-copy-user="${escA(e.username)}">👤</div>
        <div class="action-btn copy"   title="Copy password" data-copy-pw="${escA(e.password)}">🔑</div>
        <div class="action-btn login"  title="Open URL"      data-open-url="${escA(e.url)}" data-pw="${escA(e.password)}">↗</div>
        <div class="action-btn delete" title="Delete"        data-delete="${ri}">✕</div>
      </div>
    </div>`;
}

function copyText(t, l) { resetTimer(); navigator.clipboard.writeText(t).then(()=>showToast(`✓ ${l} copied`)); }
function openLogin(url, pw) {
  resetTimer();
  navigator.clipboard.writeText(pw).then(()=>showToast('✓ Password copied for login'));
  window.open(url.startsWith('http')?url:'https://'+url,'_blank');
}
async function deleteEntry(idx) {
  if (!confirm('Delete this entry?')) return;
  resetTimer(); entries.splice(idx,1); await saveVault(); renderVault(); showToast('Entry deleted');
}

// ── Add modal ────────────────────────────────────────────
function openAddModal() {
  resetTimer();
  showModal(`
    <div class="modal-header"><h3>// ADD ENTRY</h3><div class="close-btn" id="closeModal">✕</div></div>
    <div class="form-field"><label>Title / Service</label><input type="text" id="f_title" placeholder="e.g. GitHub" /></div>
    <div class="form-field"><label>URL</label><input type="text" id="f_url" placeholder="e.g. github.com" /></div>
    <div class="form-field"><label>Username / Email</label><input type="text" id="f_username" placeholder="user@example.com" autocomplete="off" /></div>
    <div class="form-field"><label>Password</label>
      <div class="pw-wrap"><input type="password" id="f_password" class="pw-input" placeholder="••••••••••••" autocomplete="off" /><button class="eye-btn" id="modalEye">👁</button></div>
    </div>
    <div class="form-field"><label>Comment (optional)</label><textarea id="f_comment" rows="2" placeholder="Notes…"></textarea></div>
    <div class="modal-footer">
      <button class="btn-ghost" id="cancelBtn">Cancel</button>
      <button class="btn-save"  id="saveBtn">SAVE ENTRY</button>
    </div>`);
  document.getElementById('f_title').focus();
  document.getElementById('closeModal').addEventListener('click', closeModal);
  document.getElementById('cancelBtn').addEventListener('click',  closeModal);
  document.getElementById('saveBtn').addEventListener('click',    saveEntry);
  document.getElementById('modalEye').addEventListener('click', ()=>toggleEye('f_password','modalEye'));
}

async function saveEntry() {
  const title=document.getElementById('f_title').value.trim();
  const url=document.getElementById('f_url').value.trim();
  const username=document.getElementById('f_username').value.trim();
  const password=document.getElementById('f_password').value;
  const comment=document.getElementById('f_comment').value.trim();
  if (!title||!username||!password) { showToast('⚠ Title, username & password required','error'); return; }
  entries.push({title,url,username,password,comment,added:Date.now()});
  await saveVault(); closeModal(); renderVault(); showToast('✓ Entry saved & encrypted');
}

// ── Shared modal helper ──────────────────────────────────
function showModal(inner) {
  document.getElementById('addModal')?.remove();
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay'; overlay.id = 'addModal';
  overlay.innerHTML = `<div class="modal">${inner}</div>`;
  overlay.addEventListener('click', e => { if (e.target===overlay) closeModal(); });
  document.body.appendChild(overlay);
}
function closeModal() { document.getElementById('addModal')?.remove(); }

// ── Eye toggle ───────────────────────────────────────────
function toggleEye(inputId, btnId) {
  const inp = document.getElementById(inputId);
  const btn = document.getElementById(btnId);
  if (!inp||!btn) return;
  inp.type = inp.type==='password' ? 'text' : 'password';
  btn.textContent = inp.type==='password' ? '👁' : '🙈';
}

// ════════════════════════════════════════════════════════
//  BOOT
// ════════════════════════════════════════════════════════
async function boot() {
  // Restore fail count
  failCount = parseInt(await store.get(KEY_FAIL_COUNT)||'0', 10);

  // Check lockout
  if (await isLockedOut()) {
    renderKilled(await getLockoutUntil());
    return;
  }

  // First run?
  const setupDone = await store.get(KEY_SETUP_DONE);
  if (!setupDone) {
    renderSetup();
    return;
  }

  renderLock();
}

boot();
