const {
  extractDomain,
  isFreeEmailDomain,
  isSubaddress,
  isRoleEmail,
  isUsernameSuspicious,
  isRiskyTld,
  guessProviderName,
  guessSenderFromLocal,
  guessOrganizationName,
} = require("./emailHeuristics");

function riskyFromChecks(checks) {
  const sp = checks.spamhaus;
  if (sp && sp.warning) return true;
  const sm = checks.smtp;
  if (!sm) return false;
  if (sm.catchAll) return true;
  if (sm.reason === "temp_failure") return true;
  return false;
}

/** Deliverability status: catch-all can still be "deliverable" (aligned with common enrichment APIs). */
function deliverabilityRiskyFlag(checks) {
  const sp = checks.spamhaus;
  if (sp && sp.warning) return true;
  const sm = checks.smtp;
  if (sm && sm.reason === "temp_failure") return true;
  return false;
}

function statusDetail(valid, reason, checks) {
  if (reason) return String(reason);
  const sm = checks.smtp;
  if (sm && sm.catchAll) return "catch_all_domain";
  if (valid && sm && sm.pass) return "valid_email";
  if (sm && sm.reason === "timeout") return "smtp_timeout";
  if (
    sm &&
    (sm.reason === "connection_refused" ||
      sm.reason === "connect_error" ||
      sm.reason === "smtp_disabled")
  ) {
    return sm.reason === "smtp_disabled" ? "smtp_not_configured" : "smtp_unreachable";
  }
  return valid ? "ok" : "invalid";
}

function deliverabilityBlock(valid, reason, checks) {
  const risky = deliverabilityRiskyFlag(checks);
  const syntax = checks.syntax && checks.syntax.pass;
  const mx = checks.mx && checks.mx.pass;
  const mxRecords = (checks.mx && checks.mx.records) || [];
  const smtp = checks.smtp;

  let is_smtp_valid;
  if (!smtp) is_smtp_valid = false;
  else if (
    smtp.reason === "timeout" ||
    smtp.reason === "connection_refused" ||
    smtp.reason === "connect_error" ||
    smtp.reason === "smtp_disabled"
  ) {
    is_smtp_valid = null;
  } else {
    is_smtp_valid = !!smtp.pass;
  }

  let status;
  if (!valid) {
    status = "undeliverable";
  } else if (!smtp) {
    status = "unknown";
  } else if (
    smtp.reason === "timeout" ||
    smtp.reason === "connection_refused" ||
    smtp.reason === "connect_error" ||
    smtp.reason === "smtp_disabled"
  ) {
    status = "unknown";
  } else if (risky) {
    status = "risky";
  } else if (smtp.pass) {
    status = "deliverable";
  } else {
    status = "undeliverable";
  }

  return {
    status,
    status_detail: statusDetail(valid, reason, checks),
    is_format_valid: !!syntax,
    is_smtp_valid,
    is_mx_valid: !!mx,
    mx_records: mxRecords,
  };
}

function qualityBlock(email, score, checks, domainAuth) {
  const domain = extractDomain(email);
  const smtp = checks.smtp;
  return {
    score: (Math.max(0, Math.min(100, score)) / 100).toFixed(2),
    is_free_email: isFreeEmailDomain(domain),
    is_username_suspicious: isUsernameSuspicious(email),
    is_disposable: checks.disposable ? !checks.disposable.pass : false,
    is_catchall: smtp ? !!smtp.catchAll : false,
    is_subaddress: isSubaddress(email),
    is_role: isRoleEmail(email),
    is_dmarc_enforced: domainAuth ? !!domainAuth.is_dmarc_enforced : false,
    is_spf_strict: domainAuth ? !!domainAuth.is_spf_strict : false,
    minimum_age: null,
  };
}

function senderBlock(email, checks) {
  const domain = extractDomain(email);
  const mx = (checks.mx && checks.mx.records) || [];
  const { first_name, last_name } = guessSenderFromLocal(email);
  return {
    first_name,
    last_name,
    email_provider_name: guessProviderName(mx),
    organization_name: guessOrganizationName(domain),
    organization_type: null,
  };
}

function domainBlock(email, checks) {
  const domain = extractDomain(email);
  return {
    domain,
    domain_age: null,
    is_live_site: null,
    registrar: null,
    registrar_url: null,
    date_registered: null,
    date_last_renewed: null,
    date_expires: null,
    is_risky_tld: isRiskyTld(domain),
  };
}

function riskBlock(email, valid, score, checks) {
  const risky = riskyFromChecks(checks);
  const spam = checks.spamhaus;
  const listed = spam && spam.listed;
  const warning = spam && spam.warning;

  let address_risk_status = "low";
  if (!valid || score < 40) address_risk_status = "high";
  else if (valid && (risky || score < 70)) address_risk_status = "medium";

  let domain_risk_status = "low";
  if (listed) domain_risk_status = "high";
  else if (
    warning ||
    (checks.typo && !checks.typo.pass) ||
    isRiskyTld(extractDomain(email)) ||
    !checks.mx ||
    !checks.mx.pass
  ) {
    domain_risk_status = "medium";
  }

  return {
    address_risk_status,
    domain_risk_status,
  };
}

function breachesBlock() {
  return {
    total_breaches: 0,
    date_first_breached: null,
    date_last_breached: null,
    breached_domains: [],
  };
}

/**
 * @param {string} email
 * @param {{ email: string, valid: boolean, score: number, checks: Record<string, unknown>, reason: string | null }} base
 * @param {{ is_dmarc_enforced: boolean, is_spf_strict: boolean } | null} domainAuth
 */
function buildExtendedResult(email, base, domainAuth) {
  const { valid, score, checks, reason } = base;
  const addr = String(email != null && email !== "" ? email : base.email || "");

  return {
    email_address: addr,
    email_deliverability: deliverabilityBlock(valid, reason, checks),
    email_quality: qualityBlock(addr, score, checks, domainAuth),
    email_sender: senderBlock(addr, checks),
    email_domain: domainBlock(addr, checks),
    email_risk: riskBlock(addr, valid, score, checks),
    email_breaches: breachesBlock(),
  };
}

module.exports = { buildExtendedResult, riskyFromChecks };
