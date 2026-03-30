const { KNOWN: FREE_EMAIL_DOMAINS } = require("../validators/typo");

const RISKY_TLDS = new Set([
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "men",
  "loan",
  "work",
  "click",
]);

const ROLE_LOCALS = new Set([
  "admin",
  "administrator",
  "postmaster",
  "hostmaster",
  "webmaster",
  "abuse",
  "noreply",
  "no-reply",
  "donotreply",
  "support",
  "help",
  "info",
  "sales",
  "marketing",
  "team",
  "hello",
  "mail",
  "office",
  "contact",
]);

function extractDomain(email) {
  const i = email.lastIndexOf("@");
  return i >= 0 ? email.slice(i + 1).toLowerCase() : "";
}

function extractLocal(email) {
  const i = email.lastIndexOf("@");
  return i >= 0 ? email.slice(0, i) : "";
}

function isFreeEmailDomain(domain) {
  if (!domain) return false;
  return FREE_EMAIL_DOMAINS.includes(domain.toLowerCase());
}

function isSubaddress(email) {
  const local = extractLocal(email) || "";
  return local.includes("+");
}

function isRoleEmail(email) {
  const localRaw = extractLocal(email).toLowerCase();
  const local = localRaw.split("+")[0];
  if (ROLE_LOCALS.has(local)) return true;
  if (/^(support|sales|help|info)\d*$/i.test(local)) return true;
  return false;
}

/** Simple heuristics: very long locals, high digit ratio. */
function isUsernameSuspicious(email) {
  const local = extractLocal(email).split("+")[0] || "";
  if (local.length > 48) return true;
  const digits = (local.match(/\d/g) || []).length;
  if (local.length > 6 && digits / local.length > 0.55) return true;
  if (/^[a-z]{1,3}\d{6,}$/i.test(local)) return true;
  return false;
}

function isRiskyTld(domain) {
  const parts = domain.split(".");
  const tld = parts.length ? parts[parts.length - 1].toLowerCase() : "";
  return RISKY_TLDS.has(tld);
}

function guessProviderName(mxRecords) {
  const joined = (mxRecords || []).join(" ").toLowerCase();
  if (joined.includes("google") || joined.includes("l.google.com")) return "Google";
  if (joined.includes("outlook") || joined.includes("microsoft")) return "Microsoft";
  if (joined.includes("yahoo")) return "Yahoo";
  if (joined.includes("zoho")) return "Zoho";
  if (joined.includes("proton")) return "Proton";
  if (joined.includes("fastmail")) return "Fastmail";
  return null;
}

function capitalizeWord(w) {
  if (!w) return "";
  return w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
}

function guessSenderFromLocal(email) {
  const localRaw = extractLocal(email).split("+")[0] || "";
  const parts = localRaw.split(/[._-]+/).filter(Boolean);
  if (parts.length >= 2) {
    return {
      first_name: capitalizeWord(parts[0]),
      last_name: capitalizeWord(parts.slice(1).join(" ")),
    };
  }
  if (parts.length === 1) {
    return { first_name: capitalizeWord(parts[0]), last_name: null };
  }
  return { first_name: null, last_name: null };
}

function guessOrganizationName(domain) {
  if (!domain) return null;
  const base = domain.split(".")[0];
  if (!base || base.length < 2) return null;
  const words = base.split(/[-_]+/).filter(Boolean);
  return words.map(capitalizeWord).join(" ");
}

module.exports = {
  extractDomain,
  extractLocal,
  isFreeEmailDomain,
  isSubaddress,
  isRoleEmail,
  isUsernameSuspicious,
  isRiskyTld,
  guessProviderName,
  guessSenderFromLocal,
  guessOrganizationName,
};
