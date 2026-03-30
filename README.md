# Email Validator API

Production-oriented email validation service for **AWS Lambda** and **API Gateway**, built with **Node.js 20** and the **Serverless Framework**. It runs **no runtime npm dependencies** (only Node built-ins: `dns`, `net`, `https`, etc.).

**Pipeline (after syntax):** MX, disposable domain, typo detection, DMARC/SPF (TXT), and Spamhaus (DBL + ZEN) run **in parallel**. **SMTP** (optional `RCPT TO` probe, catch-all detection) runs **last** when earlier gates pass.

---

## Features

| Layer | What it does |
|--------|----------------|
| **Syntax** | RFC-style local/domain rules, length, TLD |
| **MX** | DNS MX → A fallback, cached, 5s DNS timeout |
| **Disposable** | Remote blocklist + local fallback list |
| **Typo** | Levenshtein vs major consumer domains |
| **Domain auth** | `_dmarc` + SPF TXT |
| **Spamhaus** | DBL + ZEN via dedicated DNS resolvers (Quad9 by default) |
| **SMTP** | TCP/25 handshake (optional on Lambda; see below) |

Structured **JSON logs** go to stdout (CloudWatch).

---

## Quick start

```bash
cd email-validator
npm install
npm test
npm run offline
```

**Local HTTP** (default from `serverless.yml`):

- `POST http://localhost:3000/dev/validate`
- `POST http://localhost:3000/dev/validate/batch`

Stage prefix (`/dev`, `/prod`, …) is stripped internally for routing.

---

## Deploy (AWS)

Requires AWS credentials with permissions for CloudFormation, Lambda, API Gateway, IAM, S3 (deployment artifacts), and Logs.

```bash
npm ci
npm run deploy:prod
# or: npx serverless deploy --stage prod --region ap-south-1
```

After deploy, note the **Invoke URL** from `npm run info` or the API Gateway console. Paths:

- `POST https://{api-id}.execute-api.{region}.amazonaws.com/{stage}/validate`
- `POST https://{api-id}.execute-api.{region}.amazonaws.com/{stage}/validate/batch`

---

## Environment variables

| Variable | Description |
|-----------|-------------|
| `NODE_ENV` | Set from stage in Serverless |
| `LOG_LEVEL` | `info` \| `warn` \| `error` \| `debug` |
| `SPAMHAUS_DNS_SERVERS` | Comma-separated DNS IPs for Spamhaus queries (default Quad9) |
| `SPAMHAUS_QUERY_MS` | Per-query timeout (default `5000`) |
| `ENABLE_SMTP` | `true` / `false` — on **standard Lambda**, outbound **port 25 is blocked**; prod defaults to `false` in `serverless.yml` |
| `SMTP_CONNECT_MS` | SMTP connect timeout (default `8000`) |
| `SMTP_CMD_MS` | SMTP per-command read timeout (default `5000`) |

Copy `.env.example` for local experiments (Serverless injects env from `serverless.yml` when deployed).

---

## API reference

### Common

- **Method:** `POST`
- **Headers:** `Content-Type: application/json`
- **CORS:** `Access-Control-Allow-Origin: *` on responses

---

### `POST /validate` — single email

#### Request body

```json
{
  "email": "user@example.com"
}
```

#### Success `200` — response shape

The body includes both the **core** fields and **enrichment-style** blocks (similar to common email APIs).

```json
{
  "email": "user@example.com",
  "valid": true,
  "score": 80,
  "reason": null,
  "checks": {
    "syntax": { "pass": true },
    "mx": {
      "pass": true,
      "records": ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]
    },
    "domain_auth": {
      "is_dmarc_enforced": false,
      "is_spf_strict": true
    },
    "disposable": { "pass": true },
    "typo": { "pass": true, "suggestion": null },
    "spamhaus": {
      "pass": true,
      "listed": false,
      "lists": [],
      "warning": null
    },
    "smtp": {
      "pass": false,
      "code": 0,
      "catchAll": false,
      "reason": "smtp_disabled"
    }
  },
  "email_address": "user@example.com",
  "email_deliverability": {
    "status": "unknown",
    "status_detail": "smtp_not_configured",
    "is_format_valid": true,
    "is_smtp_valid": null,
    "is_mx_valid": true,
    "mx_records": ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]
  },
  "email_quality": {
    "score": "0.80",
    "is_free_email": false,
    "is_username_suspicious": false,
    "is_disposable": false,
    "is_catchall": false,
    "is_subaddress": false,
    "is_role": false,
    "is_dmarc_enforced": false,
    "is_spf_strict": true,
    "minimum_age": null
  },
  "email_sender": {
    "first_name": "User",
    "last_name": null,
    "email_provider_name": "Google",
    "organization_name": "Example",
    "organization_type": null
  },
  "email_domain": {
    "domain": "example.com",
    "domain_age": null,
    "is_live_site": null,
    "registrar": null,
    "registrar_url": null,
    "date_registered": null,
    "date_last_renewed": null,
    "date_expires": null,
    "is_risky_tld": false
  },
  "email_risk": {
    "address_risk_status": "medium",
    "domain_risk_status": "low"
  },
  "email_breaches": {
    "total_breaches": 0,
    "date_first_breached": null,
    "date_last_breached": null,
    "breached_domains": []
  }
}
```

**Field notes**

- **`valid`:** High-level pass/fail for the pipeline (SMTP “unknown” / skipped may still allow `valid: true` with a lower **score**).
- **`score`:** Integer `0`–`100`. Starts at `100`; deductions include: syntax `−100`, MX `−80`, disposable `−60`, typo `−30`, Spamhaus listed `−90`, SMTP hard reject `−70`, SMTP timeout / unreachable / disabled `−20` (see code for edge cases).
- **`reason`:** Machine-oriented string when invalid, else `null`.
- **`checks.smtp.reason`:** e.g. `smtp_disabled` (Lambda), `connection_refused`, `timeout`, `mailbox_unavailable`, `temp_failure`, etc.
- **`email_quality.score`:** String, `core score / 100` (e.g. `"0.80"`).
- **`email_deliverability.status`:** `deliverable` | `undeliverable` | `risky` | `unknown`.
- **`email_deliverability.is_smtp_valid`:** `true` / `false` / `null` when SMTP could not be determined (timeout, blocked, disabled).

#### Error responses

| Status | Body |
|--------|------|
| `400` | `{ "error": "body.email is required" }` |
| `400` | `{ "error": "Invalid JSON body" }` |
| `405` | `{ "error": "Method not allowed" }` |
| `404` | `{ "error": "Not found" }` (wrong path) |
| `500` | `{ "error": "Internal error" }` |

---

### `POST /validate/batch` — up to 100 addresses

#### Request body

```json
{
  "emails": [
    "alice@example.com",
    "bob@company.org"
  ]
}
```

#### Success `200`

```json
{
  "results": [
    {
      "email": "alice@example.com",
      "valid": true,
      "score": 100,
      "reason": null,
      "checks": { },
      "email_address": "alice@example.com",
      "email_deliverability": { },
      "email_quality": { },
      "email_sender": { },
      "email_domain": { },
      "email_risk": { },
      "email_breaches": { }
    }
  ],
  "summary": {
    "total": 1,
    "valid": 1,
    "invalid": 0,
    "risky": 0
  }
}
```

Each element of **`results`** has the **same shape** as the single **`/validate`** response.

**`summary.risky`:** Count of results where checks indicate elevated risk (e.g. Spamhaus warning, SMTP catch-all, SMTP temp failure).

#### Error responses

| Status | Body |
|--------|------|
| `400` | `{ "error": "body.emails must be an array" }` |
| `400` | `{ "error": "Maximum 100 emails per batch" }` |

---

## Checks reference (`checks` object)

Present keys depend on how far the pipeline got (failures short-circuit later layers).

| Key | Meaning |
|-----|--------|
| `syntax` | `{ pass: boolean }` |
| `mx` | `{ pass, records?: string[] }` |
| `domain_auth` | `{ is_dmarc_enforced, is_spf_strict }` |
| `disposable` | `{ pass }` |
| `typo` | `{ pass, suggestion?: string \| null }` |
| `spamhaus` | `{ pass, listed, lists[], warning }` |
| `smtp` | `{ pass, code, catchAll, reason }` |

---

## SMTP on AWS Lambda

By default, **AWS blocks outbound TCP to port 25** from Lambda. Deployed **prod** uses **`ENABLE_SMTP=false`** in `serverless.yml` so the function does not wait on a doomed connection; responses include **`smtp_disabled`** and **deliverability** reflects DNS-only validation. For true SMTP checks in AWS you need a **VPC + NAT**, **relay**, or **off-Lambda worker**.

---

## Spamhaus note

Use **`SPAMHAUS_DNS_SERVERS`** (Quad9 default) because many public and AWS resolvers return misleading **NXDOMAIN** or policy answers for Spamhaus. For strict compliance in production on AWS, consider [Spamhaus Data Query Service](https://www.spamhaus.com/data-access/real-time-dns-blocklists/).

---

## Development

```bash
npm test                 # Jest
npm run offline          # Serverless offline
```

Postman: `postman/email-validator.postman_collection.json`

---

## License

MIT
