const https = require("https");
const fallbackDomains = require("../../data/disposable-domains");

const LIST_URL =
  "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf";

/** @type {Set<string> | null} */
let disposableSet = null;
let initPromise = null;

function fetchDisposableList() {
  return new Promise((resolve) => {
    const req = https.get(LIST_URL, { timeout: 8000 }, (res) => {
      if (res.statusCode !== 200) {
        resolve(null);
        res.resume();
        return;
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          const text = Buffer.concat(chunks).toString("utf8");
          const set = new Set();
          for (const line of text.split(/\r?\n/)) {
            const t = line.trim();
            if (!t || t.startsWith("#")) continue;
            set.add(t.toLowerCase());
          }
          resolve(set);
        } catch {
          resolve(null);
        }
      });
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

async function ensureDisposableSet() {
  if (disposableSet) return disposableSet;
  if (!initPromise) {
    initPromise = (async () => {
      const remote = await fetchDisposableList();
      if (remote && remote.size > 0) {
        disposableSet = remote;
        return disposableSet;
      }
      disposableSet = new Set(fallbackDomains.map((d) => d.toLowerCase()));
      return disposableSet;
    })();
  }
  return initPromise;
}

/**
 * @param {string} email
 * @returns {Promise<{ pass: boolean, reason: string | null }>}
 */
async function checkDisposable(email) {
  const set = await ensureDisposableSet();
  const at = email.lastIndexOf("@");
  const domain = at >= 0 ? email.slice(at + 1).toLowerCase() : "";
  if (set.has(domain)) {
    return { pass: false, reason: "disposable_domain" };
  }
  return { pass: true, reason: null };
}

module.exports = { checkDisposable, ensureDisposableSet };
