const dns = require("dns").promises;

const DNS_MS = 3000;

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(Object.assign(new Error("dns_timeout"), { code: "ETIMEDOUT" })), ms)
    ),
  ]);
}

function txtChunksToStrings(chunks) {
  if (!chunks || !Array.isArray(chunks)) return [];
  return chunks.map((rec) => (Array.isArray(rec) ? rec.join("") : String(rec)));
}

/**
 * @param {string} domain
 * @returns {Promise<{ is_dmarc_enforced: boolean, is_spf_strict: boolean }>}
 */
async function checkDomainAuth(domain) {
  let is_dmarc_enforced = false;
  let is_spf_strict = false;

  try {
    const dmarcHost = `_dmarc.${domain}`;
    const dmarcTxts = await withTimeout(dns.resolveTxt(dmarcHost), DNS_MS);
    const text = txtChunksToStrings(dmarcTxts).join("");
    if (/v=DMARC1/i.test(text)) {
      const m = text.match(/;\s*p=(\w+)/i);
      const p = m ? m[1].toLowerCase() : "none";
      is_dmarc_enforced = p === "reject" || p === "quarantine";
    }
  } catch {
    /* no DMARC TXT */
  }

  try {
    const txts = await withTimeout(dns.resolveTxt(domain), DNS_MS);
    for (const s of txtChunksToStrings(txts)) {
      if (!/^v=spf1\b/i.test(s)) continue;
      if (/(^|\s)-all(\s|$)/i.test(s)) is_spf_strict = true;
      break;
    }
  } catch {
    /* no SPF or lookup failed */
  }

  return { is_dmarc_enforced, is_spf_strict };
}

module.exports = { checkDomainAuth };
