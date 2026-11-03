import { deriveKeys, encryptJson, decryptJson, KDF_ITERATIONS } from './crypto.js';
import { generatePassword, DEFAULT_GEN } from './generator.js';
import { assessStrength } from './strength.js';
import { checkBreach } from './breach.js';

const root = document.getElementById('app');
const toastEl = document.getElementById('toast');

// All sensitive state lives only in memory. Nothing secret is ever written to localStorage.
const state = {
  email: '',
  encKey: null,
  token: null,
  version: 0,
  entries: [],
  filter: '',
  autoLockMin: loadAutoLock(),
  breach: new Map(), // entry id -> {status:'checking'|'error'|'done', count?}
  revealed: new Set(),
};
let ui = null; // references into the vault view

// ---------- tiny DOM helper (text is always set as text nodes => no XSS) ----------
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k in el) el[k] = v;
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

let toastTimer;
function toast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2600);
}

function loadAutoLock() {
  try {
    const v = Number(localStorage.getItem('vaultguard.autolockMinutes'));
    return [1, 2, 5, 10, 15, 30].includes(v) ? v : 5;
  } catch {
    return 5;
  }
}

// ---------- API ----------
async function api(path, { method = 'GET', body, auth = true } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (auth && state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined, cache: 'no-store' });
  let data = {};
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    if (res.status === 401 && auth && state.token) wipeAndShowAuth('Session expired. Please unlock again.');
    throw err;
  }
  return data;
}

// ---------- auto-lock ----------
const ACTIVITY = ['pointerdown', 'keydown', 'mousemove', 'touchstart', 'scroll'];
let lastActivity = Date.now();
let idleInterval = null;
const bump = () => {
  lastActivity = Date.now();
};
function startIdle() {
  stopIdle();
  bump();
  ACTIVITY.forEach((e) => window.addEventListener(e, bump, { passive: true }));
  idleInterval = setInterval(() => {
    if (state.encKey && Date.now() - lastActivity >= state.autoLockMin * 60_000) {
      lock('auto', 'Vault locked after inactivity.');
    }
  }, 1000);
}
function stopIdle() {
  ACTIVITY.forEach((e) => window.removeEventListener(e, bump));
  clearInterval(idleInterval);
  idleInterval = null;
}

function wipe() {
  state.encKey = null;
  state.token = null;
  state.entries = [];
  state.filter = '';
  state.breach.clear();
  state.revealed.clear();
  document.querySelectorAll('dialog').forEach((d) => d.close());
  stopIdle();
  ui = null;
}

function wipeAndShowAuth(notice) {
  wipe();
  renderAuth(notice);
}

async function lock(reason = 'manual', notice = 'Vault locked.') {
  const token = state.token;
  wipe(); // drop the key and decrypted data first, then tell the server
  renderAuth(notice);
  if (!token) return;
  try {
    await fetch('/api/logout', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    });
  } catch {
    /* best effort; the session also expires server-side */
  }
}

// ---------- shared components ----------
function strengthMeter() {
  const bar = h('div', { class: 'bar' });
  const label = h('span', { class: 'meter-label' });
  const issues = h('ul', { class: 'issues' });
  const el = h('div', { class: 'meter' }, h('div', { class: 'track' }, bar), label, issues);
  el.update = (pw) => {
    const r = assessStrength(pw);
    bar.className = `bar s${pw ? r.score : 0}`;
    bar.style.width = pw ? '' : '0';
    label.textContent = pw ? `${r.label} · ~${Math.round(r.bits)} bits` : '';
    issues.replaceChildren(...(pw ? r.issues : []).map((i) => h('li', {}, i)));
    return r;
  };
  return el;
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${what} copied — clipboard clears in 20s`);
    setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 20_000);
  } catch {
    toast('Could not access the clipboard');
  }
}

// ---------- auth view ----------
function renderAuth(notice) {
  let mode = 'login';
  const card = h('div', { class: 'card auth' });
  root.replaceChildren(
    h('main', { class: 'center' }, h('h1', { class: 'brand' }, '🔐 VaultGuard'),
      h('p', { class: 'tag' }, 'Zero-knowledge password manager'), card),
  );

  const draw = () => {
    const err = h('p', { class: 'error', role: 'alert' });
    const email = h('input', { type: 'email', required: true, autocomplete: 'username', value: state.email, placeholder: 'you@example.com', maxLength: 254 });
    const pw = h('input', { type: 'password', required: true, autocomplete: mode === 'login' ? 'current-password' : 'new-password', placeholder: 'Master password' });
    const meter = strengthMeter();
    const confirmPw = h('input', { type: 'password', required: true, autocomplete: 'new-password', placeholder: 'Repeat master password' });
    const ack = h('input', { type: 'checkbox' });
    pw.addEventListener('input', () => mode === 'register' && meter.update(pw.value));

    const btn = h('button', { type: 'submit', class: 'primary' }, mode === 'login' ? 'Unlock vault' : 'Create account');
    const form = h('form', {
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        const label = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Deriving keys…';
        try {
          if (mode === 'login') await doLogin(email.value, pw.value);
          else await doRegister(email.value, pw.value, confirmPw.value, ack.checked);
        } catch (ex) {
          err.textContent = ex.message;
          btn.disabled = false;
          btn.textContent = label;
        }
      },
    },
      h('label', {}, 'Email'), email,
      h('label', {}, 'Master password'), pw,
      mode === 'register' && [
        meter,
        h('label', {}, 'Confirm master password'), confirmPw,
        h('label', { class: 'chk' }, ack, 'I understand my master password cannot be recovered — if I lose it, my vault is gone.'),
        h('p', { class: 'hint' }, 'Your master password never leaves this browser. Use a long passphrase (12+ characters).'),
      ],
      err,
      btn,
    );

    const tab = (m, label) =>
      h('button', { type: 'button', class: mode === m ? 'active' : '', onclick: () => { mode = m; draw(); } }, label);
    // replaceChildren() turns undefined/false into the text "undefined"/"false", so only pass real nodes
    card.replaceChildren(
      ...[
        notice ? h('p', { class: 'notice' }, notice) : null,
        h('div', { class: 'tabs' }, tab('login', 'Unlock'), tab('register', 'Create account')),
        form,
      ].filter(Boolean),
    );
    email.value ? pw.focus() : email.focus();
  };
  draw();
}

async function doLogin(email, masterPassword) {
  const { iterations } = await api(`/api/prelogin?email=${encodeURIComponent(email)}`, { auth: false });
  const { encKey, authKey } = await deriveKeys(masterPassword, email, iterations);
  const res = await api('/api/login', { method: 'POST', auth: false, body: { email, authKey } });
  let data;
  try {
    data = await decryptJson(encKey, res.vault);
  } catch {
    throw new Error('Could not decrypt the vault (corrupted or tampered data).');
  }
  startSession({ email, encKey, token: res.token, version: res.vault.version, entries: Array.isArray(data.entries) ? data.entries : [] });
}

async function doRegister(email, masterPassword, confirm, acknowledged) {
  if (masterPassword.length < 12) throw new Error('Master password must be at least 12 characters.');
  if (assessStrength(masterPassword).score < 3) throw new Error('Master password is too weak. Try a longer passphrase.');
  if (masterPassword !== confirm) throw new Error('Passwords do not match.');
  if (!acknowledged) throw new Error('Please confirm you understand the password cannot be recovered.');
  const { encKey, authKey } = await deriveKeys(masterPassword, email, KDF_ITERATIONS);
  const vault = await encryptJson(encKey, { entries: [] });
  const res = await api('/api/register', { method: 'POST', auth: false, body: { email, authKey, iterations: KDF_ITERATIONS, vault } });
  startSession({ email, encKey, token: res.token, version: res.version, entries: [] });
}

function startSession({ email, encKey, token, version, entries }) {
  Object.assign(state, { email: email.trim().toLowerCase(), encKey, token, version, entries });
  startIdle();
  renderVault();
}

// ---------- persistence ----------
async function commit(newEntries) {
  const blob = await encryptJson(state.encKey, { entries: newEntries }); // encrypt BEFORE it leaves the browser
  try {
    const res = await api('/api/vault', { method: 'PUT', body: { ...blob, baseVersion: state.version } });
    state.version = res.version;
    state.entries = newEntries;
  } catch (ex) {
    if (ex.status === 409) lock('manual', 'Vault was changed on another device. Unlock again to load the latest version.');
    throw ex;
  }
}

// ---------- vault view ----------
function renderVault() {
  const search = h('input', { type: 'search', placeholder: 'Search vault…', 'aria-label': 'Search', oninput: (e) => { state.filter = e.target.value; renderList(); } });
  const stats = h('p', { class: 'stats' });
  const list = h('div', { class: 'list' });
  const checkAll = h('button', { onclick: runCheckAll }, 'Check all for breaches');
  ui = { list, stats, checkAll };

  const autoSel = h('select', {
    'aria-label': 'Auto-lock after',
    onchange: (e) => {
      state.autoLockMin = Number(e.target.value);
      try { localStorage.setItem('vaultguard.autolockMinutes', String(state.autoLockMin)); } catch { /* ignore */ }
      toast(`Auto-lock set to ${state.autoLockMin} min`);
    },
  }, [1, 2, 5, 10, 15, 30].map((m) => h('option', { value: m, selected: m === state.autoLockMin }, `Auto-lock ${m} min`)));

  root.replaceChildren(
    h('main', { class: 'app' },
      h('div', { class: 'topbar' },
        h('div', {}, h('h2', {}, '🔐 VaultGuard'), h('span', { class: 'who' }, state.email)),
        h('div', { class: 'right' }, autoSel,
          h('button', { onclick: openAuditDialog }, 'Audit log'),
          h('button', { class: 'primary', onclick: () => lock('manual') }, 'Lock now')),
      ),
      h('div', { class: 'toolbar' }, search,
        h('button', { class: 'primary', onclick: () => openEntryDialog(null) }, '+ Add entry'), checkAll),
      stats, list),
  );
  renderList();
}

function renderList() {
  if (!ui) return;
  const counts = new Map();
  for (const e of state.entries) counts.set(e.password, (counts.get(e.password) || 0) + 1);

  let weak = 0, reused = 0, breached = 0;
  for (const e of state.entries) {
    if (assessStrength(e.password).score <= 1) weak++;
    if (counts.get(e.password) > 1) reused++;
    const b = state.breach.get(e.id);
    if (b?.status === 'done' && b.count > 0) breached++;
  }
  ui.stats.textContent = `${state.entries.length} item${state.entries.length === 1 ? '' : 's'} · ${weak} weak · ${reused} reused · ${breached} breached`;

  const q = state.filter.trim().toLowerCase();
  const shown = state.entries
    .filter((e) => !q || `${e.site} ${e.username} ${e.notes || ''}`.toLowerCase().includes(q))
    .sort((a, b) => a.site.localeCompare(b.site));

  if (!shown.length) {
    ui.list.replaceChildren(h('div', { class: 'empty' }, state.entries.length ? 'No matching entries.' : 'Your vault is empty. Add your first entry.'));
    return;
  }
  ui.list.replaceChildren(...shown.map((e) => entryRow(e, counts.get(e.password) > 1)));
}

function entryRow(e, isReused) {
  const s = assessStrength(e.password);
  const b = state.breach.get(e.id);
  const shown = state.revealed.has(e.id);
  const strengthBadge = h('span', { class: `badge ${s.score <= 1 ? 'bad' : s.score === 2 ? 'warn' : 'ok'}` }, s.label);
  let breachBadge = null;
  if (b?.status === 'checking') breachBadge = h('span', { class: 'badge' }, 'Checking…');
  else if (b?.status === 'error') breachBadge = h('span', { class: 'badge warn' }, 'Breach check failed');
  else if (b?.status === 'done') {
    breachBadge = b.count > 0
      ? h('span', { class: 'badge bad' }, `Found in ${b.count.toLocaleString()} breaches`)
      : h('span', { class: 'badge ok' }, 'Not in known breaches');
  }
  return h('div', { class: 'entry' },
    h('div', { class: 'entry-head' }, h('strong', {}, e.site), h('span', { class: 'user' }, e.username),
      strengthBadge, isReused && h('span', { class: 'badge warn' }, 'Reused'), breachBadge),
    h('div', {}, h('code', {}, shown ? e.password : '••••••••••••')),
    e.notes && h('div', { class: 'notes' }, e.notes),
    h('div', { class: 'entry-actions' },
      h('button', { class: 'small', onclick: () => { state.revealed.has(e.id) ? state.revealed.delete(e.id) : state.revealed.add(e.id); renderList(); } }, shown ? 'Hide' : 'Reveal'),
      h('button', { class: 'small', onclick: () => copy(e.password, 'Password') }, 'Copy password'),
      h('button', { class: 'small', onclick: () => copy(e.username, 'Username') }, 'Copy username'),
      h('button', { class: 'small', onclick: () => checkOne(e) }, 'Breach check'),
      h('button', { class: 'small', onclick: () => openEntryDialog(e) }, 'Edit'),
      h('button', { class: 'small danger', onclick: () => deleteEntry(e) }, 'Delete')),
  );
}

async function deleteEntry(e) {
  if (!confirm(`Delete "${e.site}"? This cannot be undone.`)) return;
  try {
    await commit(state.entries.filter((x) => x.id !== e.id));
    state.breach.delete(e.id);
    renderList();
    toast('Entry deleted');
  } catch (ex) {
    toast(ex.message);
  }
}

// ---------- breach checks ----------
function reportBreachCheck() {
  api('/api/audit', { method: 'POST', body: { event: 'breach_check' } }).catch(() => {});
}

async function checkOne(e) {
  state.breach.set(e.id, { status: 'checking' });
  renderList();
  try {
    state.breach.set(e.id, { status: 'done', count: await checkBreach(e.password) });
    reportBreachCheck();
  } catch {
    state.breach.set(e.id, { status: 'error' });
  }
  renderList();
}

async function runCheckAll() {
  if (!state.entries.length) return toast('Nothing to check');
  ui.checkAll.disabled = true;
  const cache = new Map(); // identical passwords are only looked up once
  for (const e of [...state.entries]) {
    if (!state.encKey) return; // locked meanwhile
    state.breach.set(e.id, { status: 'checking' });
    renderList();
    try {
      if (!cache.has(e.password)) cache.set(e.password, await checkBreach(e.password));
      state.breach.set(e.id, { status: 'done', count: cache.get(e.password) });
    } catch {
      state.breach.set(e.id, { status: 'error' });
    }
    renderList();
  }
  reportBreachCheck();
  if (ui) ui.checkAll.disabled = false;
  toast('Breach check finished');
}

// ---------- entry dialog (with generator) ----------
function openEntryDialog(entry) {
  const gen = { ...DEFAULT_GEN };
  const dlg = h('dialog');
  const err = h('p', { class: 'error', role: 'alert' });
  const site = h('input', { type: 'text', required: true, maxLength: 200, value: entry?.site || '', placeholder: 'example.com', autocomplete: 'off' });
  const username = h('input', { type: 'text', maxLength: 200, value: entry?.username || '', placeholder: 'Username or email', autocomplete: 'off' });
  const pw = h('input', { type: 'password', required: true, maxLength: 1024, value: entry?.password || '', autocomplete: 'new-password', spellcheck: false });
  const notes = h('textarea', { rows: 3, maxLength: 2000, value: entry?.notes || '', placeholder: 'Optional notes (also encrypted)' });
  const meter = strengthMeter();
  const lenOut = h('span', {}, String(gen.length));
  pw.addEventListener('input', () => meter.update(pw.value));

  const showBtn = h('button', { type: 'button', onclick: () => { pw.type = pw.type === 'password' ? 'text' : 'password'; showBtn.textContent = pw.type === 'password' ? 'Show' : 'Hide'; } }, 'Show');
  const doGenerate = () => {
    try {
      pw.value = generatePassword(gen);
      pw.type = 'text';
      showBtn.textContent = 'Hide';
      meter.update(pw.value);
    } catch (ex) {
      err.textContent = ex.message;
    }
  };
  const opt = (label, key) =>
    h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: gen[key], onchange: (e) => { gen[key] = e.target.checked; } }), label);

  const saveBtn = h('button', { type: 'submit', class: 'primary' }, 'Save');
  const form = h('form', {
    method: 'dialog',
    onsubmit: async (ev) => {
      ev.preventDefault();
      err.textContent = '';
      saveBtn.disabled = true;
      const updated = {
        id: entry?.id || crypto.randomUUID(),
        site: site.value.trim(),
        username: username.value.trim(),
        password: pw.value,
        notes: notes.value,
        updatedAt: new Date().toISOString(),
      };
      const next = entry ? state.entries.map((x) => (x.id === updated.id ? updated : x)) : [...state.entries, updated];
      try {
        await commit(next);
        state.breach.delete(updated.id);
        dlg.close();
        renderList();
        toast('Saved (encrypted in your browser first)');
      } catch (ex) {
        err.textContent = ex.message;
        saveBtn.disabled = false;
      }
    },
  },
    h('h2', {}, entry ? 'Edit entry' : 'New entry'),
    h('label', {}, 'Website'), site,
    h('label', {}, 'Username'), username,
    h('label', {}, 'Password'),
    h('div', { class: 'row' }, pw, showBtn, h('button', { type: 'button', onclick: doGenerate }, 'Generate')),
    meter,
    h('div', { class: 'gen' },
      h('label', {}, 'Generator length: ', lenOut),
      h('input', { type: 'range', min: 8, max: 64, value: gen.length, oninput: (e) => { gen.length = Number(e.target.value); lenOut.textContent = e.target.value; } }),
      h('div', { class: 'opts' }, opt('a–z', 'lower'), opt('A–Z', 'upper'), opt('0–9', 'digits'), opt('Symbols', 'symbols'), opt('Avoid look-alikes', 'avoidAmbiguous'))),
    h('label', {}, 'Notes'), notes,
    err,
    h('div', { class: 'actions' }, h('button', { type: 'button', onclick: () => dlg.close() }, 'Cancel'), saveBtn),
  );
  dlg.append(form);
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  meter.update(pw.value);
  site.focus();
}

// ---------- audit log ----------
const EVENT_LABELS = {
  account_created: 'Account created',
  login_success: 'Signed in / vault unlocked',
  login_failed: 'Failed sign-in attempt',
  vault_read: 'Vault downloaded',
  vault_updated: 'Vault saved',
  vault_locked: 'Vault locked',
  vault_auto_locked: 'Vault auto-locked (inactivity)',
  breach_check: 'Breach check run',
};

async function openAuditDialog() {
  const body = h('div', { class: 'scroll' }, 'Loading…');
  const dlg = h('dialog', {}, h('h2', {}, 'Audit log'),
    h('p', { class: 'hint' }, 'Security events recorded by the server. It contains no vault contents.'),
    body, h('div', { class: 'actions' }, h('button', { onclick: () => dlg.close() }, 'Close')));
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  try {
    const { events } = await api('/api/audit');
    body.replaceChildren(
      h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Event'), h('th', {}, 'IP'))),
        h('tbody', {}, events.map((ev) =>
          h('tr', { title: ev.ua }, h('td', {}, new Date(ev.ts).toLocaleString()), h('td', {}, EVENT_LABELS[ev.event] || ev.event), h('td', {}, ev.ip))))),
    );
  } catch (ex) {
    body.textContent = ex.message;
  }
}

// Lock if the tab is hidden for longer than the auto-lock window (timers throttle in background tabs).
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && state.encKey && Date.now() - lastActivity >= state.autoLockMin * 60_000) {
    lock('auto', 'Vault locked after inactivity.');
  }
});

renderAuth();