// VaultGuard backend — zero dependencies.
//
// ZERO-KNOWLEDGE CONTRACT
// The server only ever receives:
//   * an "authKey" (a 256-bit value derived client-side from the master password via
//     PBKDF2 -> HKDF; it is NOT the master password and cannot decrypt anything), and
//   * an opaque AES-GCM ciphertext of the whole vault.
// It never sees the master password, the encryption key, or any website credentials.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scrypt = promisify(crypto.scrypt);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

const DEFAULT_ITERATIONS = 600_000;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 5_000_000;
const SESSION_TTL_MS = 30 * 60 * 1000; // sliding
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS_PER_EMAIL = 5;
const MAX_FAILS_PER_IP = 20;
const MAX_AUDIT = 500;
const MAX_VAULT_B64 = 1_400_000; // ~1 MB ciphertext
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const CLIENT_EVENTS = new Set(['breach_check']); // events the client may report
const LOGOUT_EVENTS = { manual: 'vault_locked', auto: 'vault_auto_locked' };

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
};

const normEmail = (e) => {
  if (typeof e !== 'string') throw new HttpError(400, 'Invalid email');
  const v = e.trim().toLowerCase();
  if (v.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) throw new HttpError(400, 'Invalid email');
  return v;
};

const checkB64 = (s, max, what) => {
  if (typeof s !== 'string' || !s.length || s.length > max || !B64.test(s)) {
    throw new HttpError(400, `Invalid ${what}`);
  }
  return s;
};

const checkAuthKey = (s) => {
  checkB64(s, 64, 'authKey');
  if (Buffer.from(s, 'base64').length !== 32) throw new HttpError(400, 'Invalid authKey');
  return s;
};

const checkBlob = (b) => {
  if (!b || typeof b !== 'object') throw new HttpError(400, 'Invalid vault');
  checkB64(b.iv, 32, 'vault iv');
  checkB64(b.ct, MAX_VAULT_B64, 'vault ciphertext');
  return { iv: b.iv, ct: b.ct };
};

const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function createApp({ dataFile = path.join(__dirname, 'data', 'db.json'), trustProxy = false } = {}) {
  // ---------- persistence ----------
  let db = { users: {} };
  try {
    db = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  } catch {
    /* fresh database */
  }
  const save = () => {
    fs.mkdirSync(path.dirname(dataFile), { recursive: true });
    const tmp = `${dataFile}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(db), { mode: 0o600 });
    fs.renameSync(tmp, dataFile); // atomic replace
  };

  // ---------- sessions (in memory; only token hashes are held) ----------
  const sessions = new Map();
  const cleaner = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of sessions) if (v.expires < now) sessions.delete(k);
    for (const [k, v] of failures) if (now - v.first > FAIL_WINDOW_MS) failures.delete(k);
  }, 60_000);
  cleaner.unref();

  const newSession = (email) => {
    const token = crypto.randomBytes(32).toString('base64url');
    sessions.set(sha256hex(token), { email, expires: Date.now() + SESSION_TTL_MS });
    return token;
  };

  const authenticate = (req) => {
    const m = /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(req.headers.authorization || '');
    if (!m) throw new HttpError(401, 'Not signed in');
    const key = sha256hex(m[1]);
    const s = sessions.get(key);
    if (!s || s.expires < Date.now()) {
      sessions.delete(key);
      throw new HttpError(401, 'Session expired');
    }
    s.expires = Date.now() + SESSION_TTL_MS;
    const user = db.users[s.email];
    if (!user) throw new HttpError(401, 'Not signed in');
    return { user, key };
  };

  // ---------- login throttling ----------
  const failures = new Map();
  const limited = (key, max) => {
    const f = failures.get(key);
    if (!f) return false;
    if (Date.now() - f.first > FAIL_WINDOW_MS) {
      failures.delete(key);
      return false;
    }
    return f.count >= max;
  };
  const recordFail = (key) => {
    const f = failures.get(key);
    if (!f || Date.now() - f.first > FAIL_WINDOW_MS) failures.set(key, { count: 1, first: Date.now() });
    else f.count++;
  };

  // ---------- helpers ----------
  const clientIp = (req) =>
    (trustProxy && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) ||
    req.socket.remoteAddress ||
    'unknown';

  const audit = (user, event, req) => {
    user.audit.push({
      ts: new Date().toISOString(),
      event,
      ip: clientIp(req),
      ua: String(req.headers['user-agent'] || '').slice(0, 120),
    });
    if (user.audit.length > MAX_AUDIT) user.audit.splice(0, user.audit.length - MAX_AUDIT);
  };

  // The stored value is scrypt(authKey, per-user salt): even a stolen database does not
  // contain the authKey itself, so it cannot be replayed to log in.
  const hashAuth = (authKey, salt) => scrypt(Buffer.from(authKey, 'base64'), salt, 64);

  const readBody = (req, limit = 1_600_000) =>
    new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > limit) {
          reject(new HttpError(413, 'Request too large'));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        if (!chunks.length) return resolve({});
        try {
          const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolve(v && typeof v === 'object' ? v : {});
        } catch {
          reject(new HttpError(400, 'Invalid JSON'));
        }
      });
      req.on('error', reject);
    });

  const securityHeaders = (res) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self' https://api.pwnedpasswords.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  };

  const sendJson = (res, status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(body));
  };

  // ---------- API ----------
  async function api(req, res, url) {
    const route = `${req.method} ${url.pathname}`;

    if (route === 'GET /api/prelogin') {
      // Returns KDF parameters. Unknown emails get the default so accounts are not revealed here.
      const email = normEmail(url.searchParams.get('email'));
      return sendJson(res, 200, { iterations: db.users[email]?.iterations ?? DEFAULT_ITERATIONS });
    }

    if (route === 'POST /api/register') {
      const body = await readBody(req);
      const email = normEmail(body.email);
      checkAuthKey(body.authKey);
      const iterations = Number(body.iterations);
      if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
        throw new HttpError(400, 'Invalid KDF iterations');
      }
      const blob = checkBlob(body.vault);
      if (db.users[email]) throw new HttpError(409, 'An account with this email already exists');
      const salt = crypto.randomBytes(16);
      const user = {
        id: crypto.randomUUID(),
        email,
        iterations,
        authSalt: salt.toString('base64'),
        authHash: (await hashAuth(body.authKey, salt)).toString('base64'),
        vault: { ...blob, version: 1 },
        createdAt: new Date().toISOString(),
        audit: [],
      };
      db.users[email] = user;
      audit(user, 'account_created', req);
      audit(user, 'login_success', req);
      save();
      return sendJson(res, 201, { token: newSession(email), version: 1 });
    }

    if (route === 'POST /api/login') {
      const body = await readBody(req);
      const email = normEmail(body.email);
      checkAuthKey(body.authKey);
      const ip = clientIp(req);
      if (limited(`e:${email}`, MAX_FAILS_PER_EMAIL) || limited(`i:${ip}`, MAX_FAILS_PER_IP)) {
        throw new HttpError(429, 'Too many failed attempts. Try again in 15 minutes.');
      }
      const user = db.users[email];
      // Always do the same amount of work so timing does not reveal whether the account exists.
      const salt = user ? Buffer.from(user.authSalt, 'base64') : crypto.randomBytes(16);
      const hash = await hashAuth(body.authKey, salt);
      const ok = user && crypto.timingSafeEqual(hash, Buffer.from(user.authHash, 'base64'));
      if (!ok) {
        recordFail(`e:${email}`);
        recordFail(`i:${ip}`);
        if (user) {
          audit(user, 'login_failed', req);
          save();
        }
        throw new HttpError(401, 'Invalid email or master password');
      }
      failures.delete(`e:${email}`);
      audit(user, 'login_success', req);
      save();
      return sendJson(res, 200, { token: newSession(email), vault: user.vault });
    }

    // ---- everything below requires a session ----
    const { user, key } = authenticate(req);

    if (route === 'GET /api/vault') {
      audit(user, 'vault_read', req);
      save();
      return sendJson(res, 200, user.vault);
    }

    if (route === 'PUT /api/vault') {
      const body = await readBody(req);
      const blob = checkBlob(body);
      // Optimistic concurrency: refuse to overwrite a vault changed from another device.
      if (body.baseVersion !== user.vault.version) throw new HttpError(409, 'Vault was changed elsewhere');
      user.vault = { ...blob, version: user.vault.version + 1 };
      audit(user, 'vault_updated', req);
      save();
      return sendJson(res, 200, { version: user.vault.version });
    }

    if (route === 'POST /api/audit') {
      const body = await readBody(req);
      if (!CLIENT_EVENTS.has(body.event)) throw new HttpError(400, 'Unknown event');
      audit(user, body.event, req);
      save();
      return sendJson(res, 200, { ok: true });
    }

    if (route === 'GET /api/audit') {
      return sendJson(res, 200, { events: user.audit.slice(-100).reverse() });
    }

    if (route === 'POST /api/logout') {
      const body = await readBody(req);
      audit(user, LOGOUT_EVENTS[body.reason] || 'vault_locked', req);
      sessions.delete(key);
      save();
      return sendJson(res, 200, { ok: true });
    }

    throw new HttpError(404, 'Not found');
  }

  // ---------- static files ----------
  function serveStatic(req, res, url) {
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed');
    let p;
    try {
      p = decodeURIComponent(url.pathname);
    } catch {
      throw new HttpError(400, 'Bad path');
    }
    if (p === '/') p = '/index.html';
    const file = path.normalize(path.join(PUBLIC_DIR, p));
    if (!file.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(403, 'Forbidden');
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      throw new HttpError(404, 'Not found');
    }
    if (!stat.isFile()) throw new HttpError(404, 'Not found');
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'Content-Length': stat.size,
      'Cache-Control': 'no-cache',
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  }

  return http.createServer(async (req, res) => {
    securityHeaders(res);
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/api/')) await api(req, res, url);
      else serveStatic(req, res, url);
    } catch (e) {
      const status = e.status || 500;
      if (status === 500) console.error(e);
      if (!res.headersSent) sendJson(res, status, { error: status === 500 ? 'Internal error' : e.message });
      else res.end();
    }
  });
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  createApp({ trustProxy: process.env.TRUST_PROXY === '1' }).listen(port, host, () => {
    console.log(`VaultGuard running at http://${host}:${port}`);
  });
}
