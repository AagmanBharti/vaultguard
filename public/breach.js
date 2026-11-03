// Breached-password check using the Have I Been Pwned "Pwned Passwords" range API (k-anonymity).
// Only the first 5 hex characters of the password's SHA-1 are sent; the full hash and the
// password never leave the browser, and the response is matched locally.

export async function sha1Hex(text) {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** Find `suffix` in a range response ("SUFFIX:COUNT" lines). Returns the count, or 0. */
export function parseRange(text, suffix) {
  for (const line of text.split(/\r?\n/)) {
    const [s, c] = line.split(':');
    if (s && s.trim() === suffix) return Number(c) || 0;
  }
  return 0;
}

export async function checkBreach(password, fetchImpl = fetch) {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetchImpl(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' }, // pads responses so their size doesn't leak information
    referrerPolicy: 'no-referrer',
    credentials: 'omit',
  });
  if (!res.ok) throw new Error(`Breach service returned ${res.status}`);
  return parseRange(await res.text(), suffix);
}
