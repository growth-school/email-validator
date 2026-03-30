/**
 * Rate limiting & scale (operational notes):
 *
 * 1) Lambda has no durable per-client state. IP- or key-based rate limiting belongs at API Gateway
 *    (usage plans / throttling in the AWS console), not inside this function.
 *
 * 2) At very high volume (e.g. millions of SMTP checks), avoid unbounded concurrent Lambdas. A
 *    typical pattern: enqueue addresses to SQS and use a Lambda consumer with reserved concurrency
 *    (e.g. 50) so outbound SMTP and DNS stay within acceptable rates and you limit blast radius if
 *    providers throttle or block your egress IP.
 *
 * 3) Per-domain SMTP polite-use: `utils/cache.js` tracks last SMTP attempt per MX hostname and
 *    enforces a minimum gap (10s) between connections to the same MX to reduce the chance of
 *    reputation blocks. Tune the gap if your throughput provider allows higher rates.
 *
 * 4) After syntax passes, MX, disposable, typo, domain auth (DMARC/SPF), and Spamhaus run in
 *    parallel (`Promise.all`). Failures still follow pipeline order (mx → disposable → typo →
 *    spamhaus) for scoring; SMTP runs last when all pass.
 */

const { checkSyntax } = require("./validators/syntax");
const { checkMX, extractDomain } = require("./validators/mx");
const { checkDisposable } = require("./validators/disposable");
const { checkTypo } = require("./validators/typo");
const { checkSpamhaus } = require("./validators/spamhaus");
const { checkSMTP } = require("./validators/smtp");
const { checkDomainAuth } = require("./validators/domainAuth");
const { buildExtendedResult, riskyFromChecks } = require("./utils/extendedResult");
const { createLogger } = require("./utils/logger");

let coldStart = true;

function json(statusCode, body, headers = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      ...headers,
    },
    body: JSON.stringify(body),
  };
}

function normalizePath(event) {
  const raw = event.rawPath || event.path || "";
  const parts = raw.split("/").filter(Boolean);
  if (parts.length && ["dev", "prod", "staging", "test"].includes(parts[0].toLowerCase())) {
    parts.shift();
  }
  return "/" + parts.join("/");
}

function isBatchRoute(path) {
  return /\/validate\/batch\/?$/.test(path);
}

function isValidateRoute(path) {
  return /\/validate\/?$/.test(path);
}

function computeRisky(checks) {
  return riskyFromChecks(checks);
}

function packResult(email, valid, score, checks, reason, domainAuth, logger, started) {
  const sc = finalizeScore(score);
  const base = { email, valid, score: sc, checks, reason };
  logger.info("validation_complete", {
    email,
    valid,
    score: sc,
    durationMs: Date.now() - started,
  });
  return { ...base, ...buildExtendedResult(email, base, domainAuth) };
}

function finalizeScore(score) {
  return Math.max(0, Math.min(100, score));
}

/** Default true. Set ENABLE_SMTP=false on standard Lambda (outbound TCP port 25 is blocked). */
function isSmtpEnabled() {
  const v = process.env.ENABLE_SMTP;
  if (v == null || v === "") return true;
  const s = String(v).toLowerCase();
  return s !== "false" && s !== "0" && s !== "no" && s !== "off";
}

async function validateOne(email, logger) {
  const started = Date.now();
  let score = 100;
  let valid = true;
  let reason = null;

  /** @type {Record<string, unknown>} */
  const checks = {};

  const syntax = await checkSyntax(email);
  checks.syntax = { pass: syntax.pass };
  logger.info("validation_step", { step: "syntax", email, pass: syntax.pass });

  if (!syntax.pass) {
    score -= 100;
    valid = false;
    reason = syntax.reason;
    return packResult(email, valid, score, checks, reason, null, logger, started);
  }

  const domain = extractDomain(email);
  const [mx, disposable, typo, domainAuth, spamhaus] = await Promise.all([
    checkMX(email),
    checkDisposable(email),
    checkTypo(email),
    checkDomainAuth(domain),
    checkSpamhaus(email),
  ]);

  checks.mx = { pass: mx.pass, records: mx.records || [] };
  checks.domain_auth = {
    is_dmarc_enforced: domainAuth.is_dmarc_enforced,
    is_spf_strict: domainAuth.is_spf_strict,
  };
  checks.disposable = { pass: disposable.pass };
  checks.typo = { pass: typo.pass, suggestion: typo.suggestion };
  checks.spamhaus = {
    pass: spamhaus.pass,
    listed: spamhaus.listed,
    lists: spamhaus.lists || [],
    warning: spamhaus.warning ?? null,
  };

  logger.info("validation_step", { step: "mx", email, pass: mx.pass });
  if (!mx.pass) {
    score -= 80;
    valid = false;
    reason = mx.reason;
    return packResult(email, valid, score, checks, reason, domainAuth, logger, started);
  }

  logger.info("validation_step", { step: "disposable", email, pass: disposable.pass });
  if (!disposable.pass) {
    score -= 60;
    valid = false;
    reason = disposable.reason;
    return packResult(email, valid, score, checks, reason, domainAuth, logger, started);
  }

  logger.info("validation_step", { step: "typo", email, pass: typo.pass });
  if (!typo.pass) {
    score -= 30;
    valid = false;
    reason = "likely_typo";
    return packResult(email, valid, score, checks, reason, domainAuth, logger, started);
  }

  logger.info("validation_step", { step: "spamhaus", email, pass: spamhaus.pass });
  if (!spamhaus.pass) {
    score -= 90;
    valid = false;
    reason = "spamhaus_listed";
    return packResult(email, valid, score, checks, reason, domainAuth, logger, started);
  }

  let smtp;
  if (!isSmtpEnabled()) {
    smtp = { pass: false, code: 0, catchAll: false, reason: "smtp_disabled" };
    checks.smtp = {
      pass: smtp.pass,
      code: smtp.code,
      catchAll: smtp.catchAll,
      reason: smtp.reason,
    };
    logger.info("validation_step", {
      step: "smtp",
      email,
      pass: smtp.pass,
      catchAll: smtp.catchAll,
      reason: smtp.reason,
      skipped: true,
    });
  } else {
    smtp = await checkSMTP(email, mx.records);
    checks.smtp = {
      pass: smtp.pass,
      code: smtp.code,
      catchAll: smtp.catchAll,
      reason: smtp.reason,
    };
    logger.info("validation_step", {
      step: "smtp",
      email,
      pass: smtp.pass,
      catchAll: smtp.catchAll,
      reason: smtp.reason,
    });
  }

  if (smtp.reason === "temp_failure") {
    score -= 0;
    // unknown deliverability; do not mark invalid
    valid = true;
    reason = null;
  } else if (smtp.reason === "timeout") {
    score -= 20;
    valid = true;
    reason = null;
  } else if (
    smtp.reason === "connection_refused" ||
    smtp.reason === "connect_error" ||
    smtp.reason === "smtp_disabled"
  ) {
    score -= 20;
    valid = true;
    reason = null;
  } else if (!smtp.pass) {
    score -= 70;
    valid = false;
    reason = smtp.reason || "smtp_rejected";
  } else {
    reason = null;
  }

  return packResult(email, valid, score, checks, reason, domainAuth, logger, started);
}

/**
 * @param {import('aws-lambda').APIGatewayProxyEvent} event
 * @param {import('aws-lambda').Context} context
 */
exports.handler = async (event, context) => {
  const requestId = (event.requestContext && event.requestContext.requestId) || context.awsRequestId;
  const logger = createLogger(requestId);

  if (coldStart) {
    logger.info("lambda_cold_start", { coldStart: true });
    coldStart = false;
  } else {
    logger.info("lambda_invoke", { coldStart: false });
  }

  const method = (event.httpMethod || event.requestContext?.http?.method || "GET").toUpperCase();
  const path = normalizePath(event);

  if (method === "OPTIONS") {
    return json(200, "", {
      "Access-Control-Allow-Methods": "POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization",
    });
  }

  if (method !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  let payload;
  try {
    payload = typeof event.body === "string" ? JSON.parse(event.body || "{}") : event.body || {};
  } catch {
    return json(400, { error: "Invalid JSON body" });
  }

  try {
    if (isBatchRoute(path)) {
      const emails = payload.emails;
      if (!Array.isArray(emails)) {
        return json(400, { error: "body.emails must be an array" });
      }
      if (emails.length > 100) {
        return json(400, { error: "Maximum 100 emails per batch" });
      }
      const results = [];
      for (const e of emails) {
        results.push(await validateOne(String(e), logger));
      }
      let valid = 0;
      let invalid = 0;
      let risky = 0;
      for (const r of results) {
        if (r.valid) valid += 1;
        else invalid += 1;
        if (computeRisky(r.checks)) risky += 1;
      }
      return json(200, {
        results,
        summary: { total: results.length, valid, invalid, risky },
      });
    }

    if (isValidateRoute(path)) {
      const email = payload.email;
      if (email == null || String(email).trim() === "") {
        return json(400, { error: "body.email is required" });
      }
      const result = await validateOne(String(email), logger);
      return json(200, result);
    }

    return json(404, { error: "Not found" });
  } catch (err) {
    logger.error("handler_error", { message: err.message, stack: err.stack });
    return json(500, { error: "Internal error" });
  }
};
