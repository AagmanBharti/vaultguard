import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.js';
import { deriveKeys, encryptJson, decryptJson } from '../public/crypto.js';
import { generatePassword, randomInt } from '../public/generator.js';
import { assessStrength } from '../public/strength.js';
import { parseRange, sha1Hex } from '../public/breach.js';

const ITER = 100_000; // server minimum; production uses 600k
const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

test('client code never uses Math.random', () => {
  for (const f of fs.readdirSync(publicDir).filter((n) => n.endsWith('.js'))) {
    const code = fs.readFileSync(path.join(publicDir, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.ok(!code.includes('Math.random'), `${f} uses Math.random`);
  }
});

test('generator: length, character classes, ambiguity, bounds', () => {
  for (let i = 0; i < 200; i++) {
    const p = generatePassword({ length: 16 });
    assert.equal(p.length, 16);
    assert.match(p, /[a-z]/); assert.match(p, /[A-Z]/); assert.match(p, /\d/); assert.match(p, /[^A-Za-z0-9]/);
  }
  assert.doesNotMatch(generatePassword({ length: 128, avoidAmbiguous: true }), /[Il1O0o|]/);
  assert.match(generatePassword({ length: 30, upper: false, digits: false, symbols: false }), /^[a-z]{30}$/);
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false }));
  assert.throws(() => generatePassword({ length: 4 }));
  assert.equal(new Set(Array.from({ length: 50 }, () => generatePassword())).size, 50);
});

test('randomInt is in range and roughly uniform', () => {
  const counts = new Array(6).fill(0);
  for (let i = 0; i < 12_000; i++) counts[randomInt(6)]++;
  for (const c of counts) assert.ok(c > 1700 && c < 2300, `bucket ${c} looks biased`);
});

test('strength checker', () => {
  assert.ok(assessStrength('password').score <= 1);
  assert.ok(assessStrength('P@ssw0rd').score <= 1);
  assert.ok(assessStrength('123456789012').score <= 2);
  assert.ok(assessStrength('aaaaaaaaaaaa').score <= 1);
  assert.ok(assessStrength('correct horse battery staple 42!').score >= 3);
  for (let i = 0; i < 50; i++) assert.ok(assessStrength(generatePassword()).score >= 3);
});

test('breach range parsing + k-anonymity prefix', async () => {
  assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  assert.equal(parseRange('AAA:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nBBB:0', '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 9545824);
  assert.equal(parseRange('AAA:1', 'ZZZ'), 0);
});

test('encryption round-trip, wrong key, tampering', async () => {
  const a = await deriveKeys('correct horse battery', 'A@x.com', ITER);
  const same = await deriveKeys('correct horse battery', ' a@x.com ', ITER);
  const other = await deriveKeys('wrong password here', 'a@x.com', ITER);
  assert.equal(a.authKey, same.authKey); // email is normalised
  assert.notEqual(a.authKey, other.authKey);
  const blob = await encryptJson(a.encKey, { entries: [{ site: 'x' }] });
  assert.deepEqual(await decryptJson(same.encKey, blob), { entries: [{ site: 'x' }] });
  await assert.rejects(decryptJson(other.encKey, blob));
  const bad = { ...blob, ct: blob.ct.slice(0, -4) + (blob.ct.endsWith('AAAA') ? 'BBBB' : 'AAAA') };
  await assert.rejects(decryptJson(a.encKey, bad));
  assert.notEqual((await encryptJson(a.encKey, { entries: [] })).iv, (await encryptJson(a.encKey, { entries: [] })).iv);
  await assert.rejects(crypto.subtle.exportKey('raw', a.encKey)); // non-extractable
});

test('end to end: server stores and sees ciphertext only', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-'));
  const dataFile = path.join(dir, 'db.json');
  const server = createApp({ dataFile });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => { server.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (p, { method = 'GET', body, token } = {}) => {
    const res = await fetch(base + p, {
      method,
      headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
      body: body && JSON.stringify(body),
    });
    return { status: res.status, body: await res.json().catch(() => ({})), headers: res.headers };
  };

  const email = 'alice@example.com';
  const master = 'MASTER-passphrase-9f3k!zebra';
  const sitePassword = 'S3cretSite!Pass#7731';

  // register
  const k = await deriveKeys(master, email, ITER);
  let r = await call('/api/register', { method: 'POST', body: { email, authKey: k.authKey, iterations: ITER, vault: await encryptJson(k.encKey, { entries: [] }) } });
  assert.equal(r.status, 201);
  let token = r.body.token;
  assert.equal((await call('/api/register', { method: 'POST', body: { email, authKey: k.authKey, iterations: ITER, vault: await encryptJson(k.encKey, { entries: [] }) } })).status, 409);

  // save a vault containing a plaintext password (encrypted client-side)
  const blob = await encryptJson(k.encKey, { entries: [{ site: 'bank.example', username: 'alice', password: sitePassword }] });
  assert.equal((await call('/api/vault', { method: 'PUT', token, body: { ...blob, baseVersion: 1 } })).status, 200);
  assert.equal((await call('/api/vault', { method: 'PUT', token, body: { ...blob, baseVersion: 1 } })).status, 409); // stale write refused

  // THE zero-knowledge assertion: nothing sensitive is in the stored database
  const raw = fs.readFileSync(dataFile, 'utf8');
  for (const secret of [master, sitePassword, 'bank.example', 'alice"', k.authKey]) {
    assert.ok(!raw.includes(secret), `database leaks: ${secret}`);
  }

  // login with the right key returns a vault only the right key can read
  r = await call('/api/login', { method: 'POST', body: { email, authKey: k.authKey } });
  assert.equal(r.status, 200);
  const data = await decryptJson(k.encKey, r.body.vault);
  assert.equal(data.entries[0].password, sitePassword);

  // auth + headers
  assert.equal((await call('/api/vault')).status, 401);
  assert.ok(r.headers.get('content-security-policy').includes("script-src 'self'"));

  // audit log
  r = await call('/api/audit', { token });
  const events = r.body.events.map((e) => e.event);
  for (const e of ['account_created', 'vault_updated', 'login_success']) assert.ok(events.includes(e), e);
  assert.ok(!JSON.stringify(r.body).includes(sitePassword));

  // logout invalidates the session and is logged
  await call('/api/logout', { method: 'POST', token, body: { reason: 'auto' } });
  assert.equal((await call('/api/vault', { token })).status, 401);

  // wrong password: 401, then rate limiting after repeated failures
  const wrong = (await deriveKeys('not the password', email, ITER)).authKey;
  for (let i = 0; i < 5; i++) assert.equal((await call('/api/login', { method: 'POST', body: { email, authKey: wrong } })).status, 401);
  assert.equal((await call('/api/login', { method: 'POST', body: { email, authKey: wrong } })).status, 429);
  assert.equal((await call('/api/login', { method: 'POST', body: { email, authKey: k.authKey } })).status, 429); // locked out even with correct key

  // static serving is traversal-safe
  assert.equal((await fetch(`${base}/..%2fserver.js`)).status, 403);
  assert.equal((await fetch(`${base}/`)).status, 200);
});
