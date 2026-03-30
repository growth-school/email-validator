const KNOWN = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "icloud.com",
  "protonmail.com",
  "live.com",
  "msn.com",
  "aol.com",
  "zoho.com",
  "ymail.com",
  "fastmail.com",
  "me.com",
  "mac.com",
  "googlemail.com",
];

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const row = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    let prev = row[0];
    row[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = row[j];
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + cost);
      prev = tmp;
    }
  }
  return row[n];
}

/**
 * @param {string} email
 * @returns {Promise<{ pass: boolean, suggestion: string | null }>}
 */
async function checkTypo(email) {
  const at = email.lastIndexOf("@");
  const domain = at >= 0 ? email.slice(at + 1).toLowerCase() : "";
  if (KNOWN.includes(domain)) {
    return { pass: true, suggestion: null };
  }

  let best = KNOWN[0];
  let dist = levenshtein(domain, best);
  for (let k = 1; k < KNOWN.length; k++) {
    const d = levenshtein(domain, KNOWN[k]);
    if (d < dist) {
      dist = d;
      best = KNOWN[k];
    }
  }

  if (dist === 1 || dist === 2) {
    return { pass: false, suggestion: best };
  }
  return { pass: true, suggestion: null };
}

module.exports = { checkTypo, levenshtein, KNOWN };
