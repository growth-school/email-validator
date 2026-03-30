// Local: a-z A-Z 0-9 . _ + -
const LOCAL_PART_MAX = 64;
const EMAIL_MAX = 254;

// Hostname-style domain: labels separated by dots, TLD >= 2
const DOMAIN_RE =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

const LOCAL_ALLOWED = /^[a-zA-Z0-9._+-]+$/;

/**
 * @param {string|null|undefined} email
 * @returns {Promise<{ pass: boolean, reason: string | null }>}
 */
async function checkSyntax(email) {
  if (email == null || String(email).trim() === "") {
    return { pass: false, reason: "empty" };
  }

  const s = String(email).trim();
  if (s.length > EMAIL_MAX) {
    return { pass: false, reason: "too_long" };
  }

  const atCount = (s.match(/@/g) || []).length;
  if (atCount !== 1) {
    return { pass: false, reason: atCount === 0 ? "missing_at" : "multiple_at" };
  }

  const [local, domain] = s.split("@");
  if (!local || !domain) {
    return { pass: false, reason: "invalid_split" };
  }

  if (local.length > LOCAL_PART_MAX) {
    return { pass: false, reason: "local_too_long" };
  }

  if (!LOCAL_ALLOWED.test(local)) {
    return { pass: false, reason: "local_invalid_chars" };
  }

  if (local.startsWith(".") || local.endsWith(".")) {
    return { pass: false, reason: "local_dot_edge" };
  }

  if (local.includes("..")) {
    return { pass: false, reason: "local_consecutive_dots" };
  }

  if (!domain.includes(".")) {
    return { pass: false, reason: "domain_no_dot" };
  }

  if (!DOMAIN_RE.test(domain)) {
    return { pass: false, reason: "domain_invalid" };
  }

  return { pass: true, reason: null };
}

module.exports = { checkSyntax };
