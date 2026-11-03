// Client-side cryptography (Web Crypto API only — no third-party code).
//
//   master password + email
//        │  PBKDF2-HMAC-SHA256 (600k iterations, salt = "vaultguard:v1:" + email)
//        ▼
//   256-bit master key
//        │  HKDF-SHA256, domain-separated
//        ├──► "vaultguard-auth" → authKey (sent to server, only proves knowledge of password)
//        └──► "vaultguard-enc"  → AES-256-GCM key (non-extractable, NEVER leaves the browser)
//
// Because the two keys come from HKDF with different labels, the server (which sees the
// authKey) learns nothing that helps it derive the encryption key.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const KDF_ITERATIONS = 600_000;
const SALT_PREFIX = 'vaultguard:v1:';
const AAD = enc.encode('vaultguard:vault:v1');

export const toB64 = (buf) => {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};

export const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const normalizeEmail = (email) => email.trim().toLowerCase();

export async function deriveKeys(masterPassword, email, iterations = KDF_ITERATIONS) {
  const pw = await crypto.subtle.importKey(
    'raw',
    enc.encode(masterPassword.normalize('NFKC')),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const masterBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(SALT_PREFIX + normalizeEmail(email)), iterations },
    pw,
    256,
  );
  const hkdf = await crypto.subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const salt = new Uint8Array(32);
  const authBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('vaultguard-auth') },
    hkdf,
    256,
  );
  const encKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('vaultguard-enc') },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: page scripts cannot read the raw key bytes
    ['encrypt', 'decrypt'],
  );
  return { encKey, authKey: toB64(authBits) };
}

/** Encrypt any JSON-serialisable value. A fresh random 96-bit IV is used for every save. */
export async function encryptJson(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: AAD },
    key,
    enc.encode(JSON.stringify(value)),
  );
  return { iv: toB64(iv), ct: toB64(ct) };
}

/** Throws if the key is wrong or the ciphertext was tampered with (GCM authentication). */
export async function decryptJson(key, blob) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(blob.iv), additionalData: AAD },
    key,
    fromB64(blob.ct),
  );
  return JSON.parse(dec.decode(pt));
}
