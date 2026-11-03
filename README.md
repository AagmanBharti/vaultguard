# 🔐 VaultGuard

**A zero-knowledge password manager.** Your passwords are encrypted in your browser before they ever leave it, so the server stores only unreadable ciphertext and can never see your master password or your saved credentials.

Built with vanilla JavaScript, the Web Crypto API and Node.js, with **no third-party dependencies**.

<!-- After adding screenshots to a /screenshots folder, remove these comment markers:
![Sign in](screenshots/login.png)
![Vault](screenshots/vault.png)
![Password generator](screenshots/generator.png)
-->

## Features

- **Client-side encryption:** AES-256-GCM with a fresh random IV on every save. Tampered or wrong-key data fails to decrypt.
- **Master password that never leaves your browser:** keys are derived locally with PBKDF2-SHA256 (600,000 iterations) and split with HKDF.
- **Secure password generator:** uses `crypto.getRandomValues` with unbiased sampling, never `Math.random`. Configurable length (8–64), character sets and look-alike avoidance.
- **Password strength checker:** entropy estimate with penalties for common passwords, leetspeak variants, repeats and sequences. Reused passwords are flagged too.
- **Breached-password check:** queries the Have I Been Pwned range API using k-anonymity, so only the first 5 characters of a SHA-1 hash leave the browser.
- **Auto-lock:** locks after 1–30 minutes of inactivity (default 5), wiping the key and decrypted data and ending the session.
- **Audit log:** records account creation, sign-ins, failed sign-ins, vault saves, locks, auto-locks and breach checks with time and IP.
- **Vault tools:** add, edit, delete and search entries, reveal passwords, and copy to the clipboard, which clears after 20 seconds.

## How the zero-knowledge design works

```
master password + email
   │  PBKDF2-SHA256, 600,000 iterations
   ▼
master key ── HKDF "vaultguard-auth" ──► authKey  → sent to the server (login proof only)
          └── HKDF "vaultguard-enc"  ──► AES key  → stays in the browser, non-extractable
```

1. You register or sign in. Your master password is turned into a master key **in the browser**.
2. Two independent keys are derived from it. The **auth key** proves who you are. The **encryption key** encrypts your vault and is never sent anywhere.
3. The entire vault is encrypted as one blob. The server stores `{ iv, ciphertext, version }`.
4. The server stores only `scrypt(authKey, per-user salt)`, so even a stolen database can't be replayed to log in or used to decrypt vaults.

An automated end-to-end test asserts that the master password, site passwords, site names and auth key **never appear** in the stored database.

## Getting started

**Requirements:** [Node.js](https://nodejs.org) 20 or newer. There is nothing else to install.

```bash
git clone https://github.com/AagmanBharti/VaultGuard.git
cd VaultGuard
npm start
```

Open **http://localhost:3000**, click **Create account**, and choose a long master password (12+ characters).

Run the tests:

```bash
npm test
```

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Port to listen on |
| `HOST` | `127.0.0.1` | Use `0.0.0.0` when deploying |
| `TRUST_PROXY` | off | Set to `1` behind a reverse proxy so the real client IP is logged |

Data is stored in `data/db.json`. The Web Crypto API requires a secure context: `localhost` works, and anything else needs HTTPS.

## Security measures

- Login rate limiting (5 failures per email and 20 per IP in 15 minutes), with constant-work logins so timing doesn't reveal which accounts exist
- Random 256-bit session tokens (only a hash is stored on the server) with a 30-minute sliding expiry, held in memory only in the browser
- Optimistic concurrency on vault saves, so a stale write returns HTTP 409 instead of overwriting newer data
- Strict Content Security Policy with no inline scripts or styles, plus `nosniff`, `no-referrer`, frame denial and HSTS
- The UI is built from text nodes only (no `innerHTML`), which prevents XSS from stored data

## Project structure

```
server.js            Node HTTP server: auth, encrypted vault storage, audit log, static files
public/
  index.html         App shell
  app.js             UI, session handling, auto-lock
  crypto.js          Key derivation and AES-GCM encryption (Web Crypto)
  generator.js       Cryptographically secure password generator
  strength.js        Password strength checker
  breach.js          Have I Been Pwned k-anonymity lookup
  style.css          Styles (dark and light themes)
test/
  vaultguard.test.js Unit tests and end-to-end zero-knowledge test
```

## API

| Route | Auth | Purpose |
|---|---|---|
| `GET /api/prelogin?email=` | – | Key-derivation iteration count |
| `POST /api/register` | – | `{ email, authKey, iterations, vault: { iv, ct } }` |
| `POST /api/login` | – | `{ email, authKey }` → `{ token, vault }` |
| `GET` / `PUT /api/vault` | Bearer | Fetch or save the encrypted blob (`baseVersion` required on PUT) |
| `GET` / `POST /api/audit` | Bearer | Read the audit log, or report a `breach_check` event |
| `POST /api/logout` | Bearer | `{ reason: "manual" \| "auto" }` |

## Known limitations

This is a learning and portfolio project that hasn't had a professional security audit.

- **No master-password recovery or change.** Forgetting the password makes the vault unrecoverable, by design.
- The web app's JavaScript is delivered by the server, so a compromised server could ship malicious code. A signed browser extension or native client would reduce this risk.
- JavaScript can't reliably erase memory. Locking drops references, but the garbage collector decides when the bytes disappear.
- The "account already exists" response on registration reveals which emails are registered.
- The bundled weak-password list is small. The breach check is the stronger signal.
- Storage is a single JSON file on a single process, which is fine for personal use. A production deployment should use a real database and HTTPS.

## Roadmap

- Master-password change with automatic re-encryption
- Import and export (encrypted)
- Two-factor authentication
- Database storage (SQLite or PostgreSQL)
- Browser extension for autofill

## License

MIT
