// Password generator backed by crypto.getRandomValues (a CSPRNG). Math.random is never used.

export const DEFAULT_GEN = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?/~',
};
const AMBIGUOUS = new Set('Il1O0o|');

/** Uniform random integer in [0, max) using rejection sampling (no modulo bias). */
export function randomInt(max) {
  if (!Number.isInteger(max) || max <= 0 || max > 2 ** 32) throw new RangeError('max out of range');
  const limit = Math.floor(2 ** 32 / max) * max;
  const buf = new Uint32Array(1);
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

export function generatePassword(options = {}) {
  const o = { ...DEFAULT_GEN, ...options };
  const classes = ['lower', 'upper', 'digits', 'symbols']
    .filter((k) => o[k])
    .map((k) => [...SETS[k]].filter((c) => !(o.avoidAmbiguous && AMBIGUOUS.has(c))));
  if (!classes.length) throw new Error('Select at least one character type');
  const length = Math.floor(o.length);
  if (length < Math.max(8, classes.length) || length > 128) throw new RangeError('Length must be 8–128');

  const pool = classes.flat();
  // Guarantee one character from each selected class, fill the rest from the whole pool…
  const out = classes.map((set) => set[randomInt(set.length)]);
  while (out.length < length) out.push(pool[randomInt(pool.length)]);
  // …then Fisher–Yates shuffle so the guaranteed characters aren't in predictable positions.
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join('');
}
