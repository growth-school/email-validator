const dns = require("dns");
const { Resolver } = dns.promises;
const { cache } = require("../utils/cache");

/**
 * Spamhaus DNSBL lookups do not work reliably via many public resolvers (e.g. 8.8.8.8, 1.1.1.1)
 * or AWS’s default DNS: you may get NXDOMAIN (false “clean”) or policy IPs like 127.255.255.254.
 * Use dedicated resolvers (default Quad9) or Spamhaus Data Query Service from AWS:
 * https://www.spamhaus.org/resource-hub/email-security/if-you-query-the-legacy-dnsbls-via-amazon-web-services-dns-move-to-spamhaus-technologys-free-data-query-service/
 */

const QUERY_MS_DEFAULT = Number(process.env.SPAMHAUS_QUERY_MS) || 5000;
const CACHE_TTL_MS = 30 * 60 * 1000;
const PREFIX = "spamhaus:";

function extractDomain(email) {
  const i = email.lastIndexOf("@");
  return i >= 0 ? email.slice(i + 1).toLowerCase() : "";
}

function reverseIp(ip) {
  return ip.split(".").reverse().join(".");
}

function spamhausResolverIps() {
  const raw = process.env.SPAMHAUS_DNS_SERVERS || "9.9.9.9,149.112.112.112";
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function createSpamhausResolver() {
  const r = new Resolver();
  r.setServers(spamhausResolverIps());
  return r;
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })), ms)
    ),
  ]);
}

/** DBL positive: 127.0.1.2–127.0.1.254 (127.0.1.255 is meta: “IP queries prohibited”) + legacy 127.0.0.x mirrors. */
function isDblListingIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  const m1 = /^127\.0\.1\.(\d+)$/.exec(ip);
  if (m1) {
    const n = Number(m1[1]);
    return n >= 2 && n < 255;
  }
  const m0 = /^127\.0\.0\.(\d+)$/.exec(ip);
  if (m0) {
    const n = Number(m0[1]);
    return n >= 2 && n < 255;
  }
  return false;
}

/** Non-listing Spamhaus responses (blocked/unattributable resolver, etc.). */
function isSpamhausQueryErrorIp(ip) {
  if (!ip) return false;
  return ip.startsWith("127.255.255.");
}

function zenIpListed(zenIps) {
  return (zenIps || []).includes("127.0.0.2");
}

async function resolve4OrNotListed(resolver, host, queryMs) {
  try {
    return await withTimeout(resolver.resolve4(host), queryMs);
  } catch (e) {
    const c = e && e.code;
    if (c === "ENOTFOUND" || c === "ENODATA") return null;
    throw e;
  }
}

/**
 * @param {string} email
 * @returns {Promise<{ pass: boolean, listed: boolean, lists: string[], warning: string | null }>}
 */
async function checkSpamhaus(email) {
  const domain = extractDomain(email);
  const key = PREFIX + domain;
  const cached = cache.get(key);
  if (cached != null) return cached;

  const resolver = createSpamhausResolver();
  const queryMs = QUERY_MS_DEFAULT;

  const run = async () => {
    /** @type {string[]} */
    const lists = [];
    let dblListed = false;

    const [dblHosts, domainIps] = await Promise.all([
      resolve4OrNotListed(resolver, `${domain}.dbl.spamhaus.org`, queryMs),
      resolve4OrNotListed(resolver, domain, queryMs),
    ]);

    if (dblHosts && dblHosts.some(isSpamhausQueryErrorIp)) {
      throw Object.assign(new Error("spamhaus_policy"), { code: "SPAMHAUS_POLICY" });
    }
    if (dblHosts && dblHosts.some(isDblListingIp)) {
      dblListed = true;
      lists.push("DBL");
    }

    if (domainIps && domainIps.length) {
      const rev = reverseIp(domainIps[0]);
      const zenIps = await resolve4OrNotListed(resolver, `${rev}.zen.spamhaus.org`, queryMs);
      if (zenIps && zenIps.some(isSpamhausQueryErrorIp)) {
        throw Object.assign(new Error("spamhaus_policy"), { code: "SPAMHAUS_POLICY" });
      }
      if (zenIpListed(zenIps)) {
        lists.push("ZEN_SBL");
      }
    }

    const listed = dblListed || lists.includes("ZEN_SBL");
    return {
      pass: !listed,
      listed,
      lists,
      warning: null,
    };
  };

  try {
    const result = await run();
    cache.set(key, result, CACHE_TTL_MS);
    return result;
  } catch (e) {
    const policy = e && (e.code === "SPAMHAUS_POLICY" || e.message === "spamhaus_policy");
    const soft = {
      pass: true,
      listed: false,
      lists: [],
      warning: policy ? "spamhaus_resolver_blocked" : "spamhaus_unavailable",
    };
    cache.set(key, soft, CACHE_TTL_MS);
    return soft;
  }
}

module.exports = { checkSpamhaus, extractDomain, isDblListingIp, isSpamhausQueryErrorIp };
