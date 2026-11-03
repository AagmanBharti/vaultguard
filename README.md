# VaultGuard — zero-knowledge encrypted password manager

Passwords are encrypted in the browser before they are sent anywhere. The backend only stores
ciphertext and can never read your master password or your saved credentials.

## Run

```bash
npm start            # http://127.0.0.1:3000  (Node 20+, no dependencies to install)
npm test             # unit + end-to-end tests
```

Env vars: `PORT`, `HOST` (default `127.0.0.1`), `TRUST_PROXY=1` (use `X-Forwarded-For` for IPs behind a proxy).
Data is stored in `data/db.json`. Web Crypto needs a secure context: `localhost` works, anything else needs HTTPS.

## Feature map

| Feature | Where |
|---|---|
| User registration | `POST /api/register`, `public/app.js` (`doRegister`) |
| Master password | Never sent; derives keys locally (`public/crypto.js`) |
| Client-side encryption | AES-256-GCM, fresh random IV per save (`encryptJson`) |
| Password generator | `public/generator.js` — `crypto.getRandomValues` + rejection sampling, no `Math.random` |
| Secure vault | Entire vault is one encrypted blob; server stores `{iv, ct, version}` |
| Strength checker | `public/strength.js` — entropy estimate, common-password / leetspeak / sequence / repeat penalties; also flags reused passwords |
| Auto-lock | Inactivity timer (1–30 min, default 5); drops key + decrypted data and ends the session |
| Breach check | `public/breach.js` — HIBP range API, k-anonymity (only a 5-char SHA-1 prefix leaves the browser) |
| Audit log | Server records register / login / failed login / save / lock / auto-lock / breach-check, with time + IP; viewable in the UI |

## How the zero-knowledge design works

```
master password + email
   │ PBKDF2-SHA256, 600,000 iterations
   ▼
master key ── HKDF "vaultguard-auth" ──► authKey  → sent to server (login proof only)
          └── HKDF "vaultguard-enc"  ──► AES key  → stays in browser, non-extractable
```

- The server stores `scrypt(authKey, per-user salt)`, so even its database can't be replayed to log in.
- The authKey and encryption key are independent (domain-separated HKDF), so the server learns nothing that helps it decrypt.
- AES-GCM authenticates the data: a tampered or wrong-key ciphertext fails to decrypt.
- A test (`test/vaultguard.test.js`) asserts the master password, site passwords, site names and authKey never appear in the stored database.

## Other protections

- Login throttling (5 failures/email, 20/IP per 15 min), constant-work login to avoid account-existence timing leaks.
- Sessions are random 256-bit bearer tokens (hash stored server-side), 30-min sliding expiry, kept only in memory in the browser.
- Optimistic concurrency on vault saves (409 if changed on another device) so edits aren't silently overwritten.
- Strict CSP (no inline script/style), `nosniff`, `no-referrer`, frame denial, HSTS; UI is built with text nodes only (no `innerHTML`).
- Clipboard is cleared 20 s after copying.

## Known limitations (be honest about these)

- **No master-password recovery or change flow.** Forgetting it means the vault is unrecoverable (by design). Changing it requires re-encrypting and re-registering the verifier; not implemented.
- JavaScript can't reliably wipe memory; "locking" drops references but the GC decides when bytes disappear.
- The web app is trusted code delivered by the server: a compromised server could ship malicious JS. A browser extension or native client with signed code narrows this.
- The "already exists" response on registration reveals which emails have accounts.
- The weak-password list is small and bundled; the breach check is the stronger signal.
- Single JSON file storage and a single process: fine for personal use, swap in a real database for production.
- Run behind HTTPS in any real deployment.

## API

| Route | Auth | Purpose |
|---|---|---|
| `GET /api/prelogin?email=` | – | KDF iteration count |
| `POST /api/register` | – | `{email, authKey, iterations, vault:{iv,ct}}` |
| `POST /api/login` | – | `{email, authKey}` → `{token, vault}` |
| `GET/PUT /api/vault` | Bearer | Fetch / save encrypted blob (`baseVersion` required on PUT) |
| `GET /api/audit`, `POST /api/audit` | Bearer | Read log; report `breach_check` event |
| `POST /api/logout` | Bearer | `{reason: 'manual' \| 'auto'}` |
