const dns = require("dns").promises;
const { cache } = require("../utils/cache");

const DNS_TIMEOUT_MS = 5000;
const MX_CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_PREFIX = "mx:";

function extractDomain(email) {
  const i = email.lastIndexOf("@");
  return i >= 0 ? email.slice(i + 1).toLowerCase() : "";
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(Object.assign(new Error("dns_timeout"), { code: "ETIMEDOUT" })), ms)
    ),
  ]);
}

function failAndCache(key, res) {
  cache.set(key, res, MX_CACHE_TTL_MS);
  return res;
}

/**
 * @param {string} email
 * @returns {Promise<{ pass: boolean, records: string[], reason: string | null }>}
 */
async function checkMX(email) {
  const domain = extractDomain(email);
  const key = CACHE_PREFIX + domain;
  const cached = cache.get(key);
  if (cached != null) {
    return cached;
  }

  let records = [];

  async function fallbackA() {
    const a4 = await withTimeout(dns.resolve4(domain), DNS_TIMEOUT_MS);
    return a4.length ? [`${a4[0]}`] : [];
  }

  try {
    const mxList = await withTimeout(dns.resolveMx(domain), DNS_TIMEOUT_MS);
    records = mxList
      .sort((a, b) => a.priority - b.priority)
      .map((r) => r.exchange.replace(/\.$/, "").toLowerCase());
    if (records.length === 0) {
      records = await fallbackA();
    }
  } catch (err) {
    const code = err && err.code;
    if (code === "ETIMEDOUT" || err.message === "dns_timeout") {
      return failAndCache(key, { pass: false, records: [], reason: "dns_timeout" });
    }
    if (code === "ENOTFOUND") {
      return failAndCache(key, { pass: false, records: [], reason: "nxdomain" });
    }
    if (code === "ENODATA") {
      try {
        records = await fallbackA();
      } catch (err2) {
        const c2 = err2 && err2.code;
        if (c2 === "ETIMEDOUT") {
          return failAndCache(key, { pass: false, records: [], reason: "dns_timeout" });
        }
        return failAndCache(key, {
          pass: false,
          records: [],
          reason: c2 === "ENOTFOUND" ? "nxdomain" : "dns_error",
        });
      }
    } else {
      try {
        records = await fallbackA();
      } catch (err2) {
        const c2 = err2 && err2.code;
        if (c2 === "ETIMEDOUT") {
          return failAndCache(key, { pass: false, records: [], reason: "dns_timeout" });
        }
        return failAndCache(key, {
          pass: false,
          records: [],
          reason: c2 === "ENOTFOUND" ? "nxdomain" : "dns_error",
        });
      }
    }
  }

  if (records.length === 0) {
    return failAndCache(key, { pass: false, records: [], reason: "no_mx" });
  }

  const res = { pass: true, records, reason: null };
  cache.set(key, res, MX_CACHE_TTL_MS);
  return res;
}

module.exports = { checkMX, extractDomain };
