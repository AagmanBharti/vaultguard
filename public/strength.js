// Heuristic password strength checker (runs locally; passwords never leave the browser).
// Entropy estimate with penalties for common passwords, leetspeak variants, repeats and sequences.

const COMMON = new Set(
  (
    'password 123456 123456789 12345678 1234567 12345 1234567890 qwerty qwerty123 qwertyuiop abc123 password1 ' +
    'passw0rd p@ssw0rd 111111 000000 654321 iloveyou admin admin123 administrator welcome welcome1 monkey dragon ' +
    'letmein login princess football baseball master sunshine shadow trustno1 1q2w3e4r zaq12wsx qazwsx asdfgh ' +
    'asdfghjkl superman batman starwars access flower hottie loveme charlie donald freedom whatever michael ' +
    'secret hello google computer internet test test123 guest root user changeme default letmein1 summer winter ' +
    'spring autumn football1 chocolate jordan michelle jessica ashley hunter tigger soccer killer pepper ' +
    'ginger buster cookie banana mustang liverpool arsenal'
  ).split(' '),
);

const LEET = { '@': 'a', 4: 'a', 3: 'e', 0: 'o', $: 's', 5: 's', 7: 't', 1: 'l', '!': 'i' };
const ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'];
const ROW_RUNS = [...ROWS, ...ROWS.map((r) => [...r].reverse().join(''))];
const LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];

function hasSequence(s, n = 4) {
  for (let i = 0; i <= s.length - n; i++) {
    const w = s.slice(i, i + n);
    if (ROW_RUNS.some((r) => r.includes(w))) return true;
    if (/^[a-z0-9]+$/.test(w)) {
      let up = true;
      let down = true;
      for (let k = 1; k < n; k++) {
        const d = w.charCodeAt(k) - w.charCodeAt(k - 1);
        if (d !== 1) up = false;
        if (d !== -1) down = false;
      }
      if (up || down) return true;
    }
  }
  return false;
}

export function assessStrength(pw) {
  if (!pw) return { score: 0, label: LABELS[0], bits: 0, issues: ['Password is empty'] };
  const issues = [];

  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;

  // Repeated characters add little: count them at 30%.
  const unique = new Set(pw).size;
  let bits = (unique + Math.max(0, pw.length - unique) * 0.3) * Math.log2(pool || 1);

  const lower = pw.toLowerCase();
  const deLeet = [...lower].map((c) => LEET[c] ?? c).join('');
  const base = (s) => s.replace(/[^a-z]+$/g, '').replace(/^[^a-z]+/g, '');

  if (COMMON.has(lower)) {
    bits = Math.min(bits, 5);
    issues.push('This is a very common password');
  } else if (COMMON.has(deLeet) || COMMON.has(base(lower)) || COMMON.has(base(deLeet))) {
    bits = Math.min(bits, 20);
    issues.push('Looks like a common password with small tweaks');
  }
  if (/(.)\1{2,}/.test(pw)) {
    bits *= 0.85;
    issues.push('Contains repeated characters');
  }
  if (hasSequence(lower)) {
    bits *= 0.75;
    issues.push('Contains a predictable sequence (e.g. abcd, 1234, qwer)');
  }
  if (/^\d+$/.test(pw)) issues.push('Only digits');
  if (/^[a-z]+$/i.test(pw)) issues.push('Only letters');
  if (pw.length < 8) issues.push('Shorter than 8 characters');
  else if (pw.length < 12) issues.push('Use 12 or more characters');

  let score = bits < 28 ? 0 : bits < 36 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  if (pw.length < 8) score = Math.min(score, 1);
  if (pw.length < 12) score = Math.min(score, 3);

  return { score, label: LABELS[score], bits, issues };
}

export const isWeak = (pw) => assessStrength(pw).score <= 1;
