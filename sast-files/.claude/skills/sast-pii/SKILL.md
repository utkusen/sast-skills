---
name: sast-pii
description: >-
  Detect PII and credential leakage into logs, error messages, telemetry, and
  crash reporters (Sentry, Rollbar, APM breadcrumbs). Uses a three-phase
  approach: recon (find log/print sinks), batched verify (check sensitivity of
  what is logged, 3 sinks each), and merge (consolidate batch results). Covers
  passwords, tokens, session IDs, Authorization headers, and PII (emails,
  phone, SSN, DOB, credit card). Requires sast/architecture.md (run
  sast-analysis first). Outputs findings to sast/pii-results.md and
  sast/pii-results.json. Use when asked to find PII leakage, credential
  logging, or sensitive data in logs.
version: 0.1.0
---

# PII and Credential Log Leakage Detection

You are performing a focused security assessment to find cases where sensitive data — passwords, tokens, session IDs, Authorization headers, or PII (emails, phone numbers, SSN/TCKN, credit card PANs, dates of birth, precise geolocation) — leaks into logs, stdout, stderr, error responses, crash reporters, or APM telemetry. This skill uses a three-phase approach with subagents: **recon** (find all log/print/telemetry sinks), **batched verify** (check the sensitivity of what each sink emits, in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is PII / Credential Log Leakage

PII and credential log leakage occurs when sensitive data is written to a destination that is **persisted**, **aggregated**, or **shared with third parties** without the same access controls as the primary data store. Once a password lands in a CloudWatch log group or a Sentry event, every engineer with log-read access (and every third-party vendor downstream) has effectively seen it — even if the application's database is properly locked down.

Concretely, the sinks we care about are:

- **Application logs** — `console.log`, `console.error`, `console.warn`, `logger.info`, `logger.debug`, `log.warn`, `System.out.println`, `System.err.println`, `fmt.Println`, `fmt.Printf`, `print()`, `printf`, Python `logging.*`, Ruby `Rails.logger.*`, Go `log.Printf`, `slog.Info`, etc.
- **stdout / stderr** — any direct write to the process's standard streams
- **HTTP error responses** — stack traces, environment variables, or raw exception objects echoed back to the client in 500 pages
- **Crash reporters / error trackers** — `Sentry.captureException`, `Sentry.captureMessage`, `Rollbar.error`, `Bugsnag.notify`, `Raygun.send`, `Honeybadger.notify`, `Airbrake.notify`
- **APM / tracing / observability** — `tracer.addTags`, `span.setAttribute`, `newrelic.addCustomAttribute`, `datadog.addTags`, OpenTelemetry span attributes, `Honeycomb.addField`
- **Analytics / product telemetry** — `mixpanel.track`, `segment.track`, `amplitude.logEvent`, `posthog.capture`, `ga.send` — if sensitive data is passed as event properties
- **Audit logs / event streams** — Kafka producers, RabbitMQ publishers, event bus emitters that serialize full request objects
- **File-based logs** — direct writes to log files on disk, syslog, journald

The core question: *Does sensitive data reach a sink whose access-control boundary is different from — typically weaker than — the primary data store?*

### What PII Leakage IS

- A login handler that logs the full request body, which includes the plaintext password field
- An error handler that does `logger.error('payment failed', { user, order })` where `user` contains `passwordHash`, `sessionToken`, or `ssn`
- A global Express error middleware that responds with `err.stack` and `process.env` dumped into the JSON body on 500 errors
- A Sentry `beforeSend` hook that does not strip Authorization headers or cookies from the `request.headers` breadcrumb
- Request-id middleware that logs `req.headers` (including `Authorization: Bearer ...` and `Cookie: session=...`)
- Client-side `console.log(user)` in a React component where `user` contains a JWT or refresh token — visible in the browser console and often captured by session-replay tools
- An analytics `track('checkout', { card_number, cvv, email })` call that ships full PAN and CVV to a third-party analytics vendor
- An APM custom tag like `span.setAttribute('user.password', password)` — PII/credentials baked into traces visible to every engineer with APM access
- A `catch (e) { res.status(500).send(e) }` that returns the raw exception including database connection strings or SQL fragments

### What PII Leakage is NOT

This skill has a narrow scope. These are separate concerns handled by other skills:

- **Hardcoded secrets in source code** — an API key as a string literal in a React component is covered by `sast-hardcodedsecrets`, not here. This skill is about sensitive data that *flows through* code at runtime, not static string literals.
- **Response-body data disclosure via IDOR / broken authz** — returning another user's profile from `GET /users/:id` is an IDOR finding, not a logging finding. This skill only covers data written to *logs/telemetry/error* sinks, not primary API responses that are the intended shape of the endpoint.
- **SQL injection dumping data** — that's `sast-sqli`.
- **Secrets in `.env` files or config** — covered by infrastructure and secrets-management skills.
- **Verbose stack traces returned to clients during normal (non-error) flow** — generally an information disclosure issue but only reportable here if it includes PII or credentials.

If a finding is borderline, prefer reporting it here if the sensitive data reaches a **log/telemetry/error sink**, and prefer the other skill if it reaches a **primary response body** or lives as a **static literal**.

### Patterns That Prevent PII Leakage

When auditing, recognize these as *mitigations* — their presence usually means a log site is safe:

- **Structured logger with allowlist/denylist redaction** — `pino` with `redact: ['req.headers.authorization', 'password', '*.token']`, `winston` with a redact format, `bunyan` serializers, `logback` with `PatternLayout` scrubbers, Java `log4j2` pattern filters, Python `logging.Filter` subclasses that replace sensitive fields
- **DTO / view-model layer** — domain objects never go directly into logs; a `toLogSafe()` / `toPublic()` / `.toJSON()` serializer strips password hashes, tokens, and PII before logging
- **Audit-log allowlist** — the audit logger only accepts a whitelisted set of fields (`user_id`, `action`, `resource_id`, `timestamp`) and rejects everything else by design
- **Mask-by-default conventions** — helper functions like `maskEmail`, `maskCard`, `maskPhone` applied at the log site; the raw value never appears
- **Sentry / Rollbar `beforeSend` / `before_send` hooks** that scrub `request.headers.authorization`, `request.headers.cookie`, and known PII fields
- **Middleware-level redaction** — Express/Koa middleware that replaces `req.body.password`, `req.body.ssn`, etc. with `[REDACTED]` before any downstream logger sees the request
- **Explicit policy: never `JSON.stringify(req)` or `util.inspect(user)`** — code reviews reject full-object serialization into logs
- **Sampling + scrubbing for APM** — OpenTelemetry `SpanProcessor` that strips known-sensitive attribute keys before export

When verifying a candidate sink, the presence of one of these patterns near the call site — **and evidence that it actually covers the field in question** — is what moves a finding from "Vulnerable" to "Not Vulnerable".

---

## Vulnerable vs. Secure Examples

These examples illustrate the patterns to flag and the patterns to accept.

### Example 1: Full request/body logging

Vulnerable:

```js
// Express login route
app.post('/login', (req, res) => {
  console.log(req.body);  // logs { email, password } in plaintext
  // ...
});
```

```js
logger.info(req);  // logs headers including Authorization + Cookie, and body
```

```python
# Django
logger.debug("incoming request: %s", request.POST)  # includes password
```

Secure:

```js
logger.info({ email: req.body.email }, 'login attempt');  // explicit allowlist
```

### Example 2: Logging user objects with credentials

Vulnerable:

```js
// user contains passwordHash, sessionToken, mfaSecret
logger.error('login failed', user);
```

```java
log.error("auth failed for user: " + user);  // toString() includes passwordHash
```

Secure:

```js
logger.error({ userId: user.id, reason: 'bad_password' }, 'login failed');
```

```java
log.error("auth failed for user: " + user.toPublicView());  // DTO strips secrets
```

### Example 3: Error responses echoing internals

Vulnerable:

```js
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,          // leaks file paths, line numbers, sometimes secrets
    env: process.env,          // leaks all environment variables including DB URL
  });
});
```

```python
@app.errorhandler(Exception)
def handle(e):
    return str(e), 500  # raw exception often contains query with user data
```

Secure:

```js
app.use((err, req, res, next) => {
  logger.error({ err, reqId: req.id }, 'unhandled');
  res.status(500).json({ error: 'internal_error', requestId: req.id });
});
```

### Example 4: Sentry / APM with unfiltered breadcrumbs

Vulnerable:

```js
Sentry.init({ dsn: '...' });
// No beforeSend hook — breadcrumbs include full Authorization header,
// request bodies with passwords, and cookies.
```

```js
span.setAttribute('http.request.body', JSON.stringify(req.body));  // PII in traces
span.setAttribute('user.ssn', user.ssn);
```

Secure:

```js
Sentry.init({
  dsn: '...',
  beforeSend(event) {
    if (event.request?.headers) {
      delete event.request.headers.authorization;
      delete event.request.headers.cookie;
    }
    if (event.request?.data) {
      for (const k of ['password', 'ssn', 'card_number', 'cvv']) {
        if (event.request.data[k]) event.request.data[k] = '[REDACTED]';
      }
    }
    return event;
  },
});
```

### Example 5: Request-id / access middleware dumping headers

Vulnerable:

```js
app.use((req, res, next) => {
  logger.info({ headers: req.headers, url: req.url }, 'request');
  // headers include Authorization: Bearer ... and Cookie: session=...
  next();
});
```

Secure:

```js
app.use((req, res, next) => {
  logger.info({
    method: req.method,
    path: req.path,
    reqId: req.id,
    userAgent: req.headers['user-agent'],
  }, 'request');
  next();
});
```

### Example 6: Client-side console logs leaking credentials

Vulnerable:

```tsx
// React component
useEffect(() => {
  console.log('auth response:', authResponse);  // { accessToken, refreshToken, user }
}, [authResponse]);
```

```js
console.debug('form data', { email, password });
```

These are visible in the browser DevTools console, captured by session-replay tools (FullStory, LogRocket, Hotjar), and sometimes synced back to the server via error trackers.

Secure:

```tsx
// Don't log auth responses at all; or gate behind a dev-only flag that is stripped at build time.
if (import.meta.env.DEV) console.debug('auth ok');
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Log/Print Sinks

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where data is written to a log, stdout, stderr, error response, crash reporter, APM span, or analytics event. Write results to `sast/pii-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, logging library, error reporting configuration, and frontend/backend split.
>
> **What to search for**:
>
> Scan the entire codebase and flag ALL sink call sites regardless of what is being logged — the sensitivity analysis happens in Phase 2.
>
> 1. **Generic print/log functions**:
>    - JavaScript/TypeScript: `console.log`, `console.error`, `console.warn`, `console.info`, `console.debug`, `console.trace`, `console.dir`
>    - Node loggers: `logger.info`, `logger.error`, `logger.warn`, `logger.debug`, `logger.trace`, `log.info`, `log.error`, `pino(...)`, `winston.*`, `bunyan.*`, `debug(...)`
>    - Python: `print(...)`, `logging.info`, `logging.debug`, `logging.error`, `logging.warning`, `logging.exception`, `logger.*`, `log.*`, `sys.stdout.write`, `sys.stderr.write`
>    - Java: `System.out.println`, `System.err.println`, `log.info`, `log.error`, `log.debug`, `log.warn`, `logger.info`, SLF4J calls, `e.printStackTrace()`
>    - Go: `fmt.Println`, `fmt.Printf`, `fmt.Fprintln`, `log.Printf`, `log.Println`, `log.Fatal`, `slog.Info`, `slog.Error`
>    - Ruby: `puts`, `p`, `pp`, `Rails.logger.*`, `logger.*`
>    - PHP: `echo`, `print`, `print_r`, `var_dump`, `error_log`, `syslog`, `Log::info`, `Log::error`
>    - C#/.NET: `Console.WriteLine`, `ILogger.*`, `Trace.*`, `Debug.WriteLine`, `_logger.LogInformation`
>
> 2. **Error responses** — handlers that return error details to clients:
>    - `res.status(500).send(err)`, `res.json({ error: err })`, `res.send(err.stack)`, `res.send(process.env)`
>    - Express/Koa/Fastify error-handling middleware (functions with 4 args `(err, req, res, next)`)
>    - Flask `@app.errorhandler`, Django `DEBUG=True` responses, FastAPI `HTTPException(detail=...)`
>    - Spring `@ControllerAdvice`, `@ExceptionHandler`
>    - Generic `catch` blocks that echo the exception back in the HTTP response
>
> 3. **Crash reporters / error trackers**:
>    - `Sentry.captureException`, `Sentry.captureMessage`, `Sentry.setContext`, `Sentry.setUser`, `Sentry.addBreadcrumb`, `Sentry.configureScope`
>    - `Rollbar.error`, `Rollbar.critical`, `Rollbar.info`
>    - `Bugsnag.notify`, `Bugsnag.leaveBreadcrumb`
>    - `Raygun.send`, `Honeybadger.notify`, `Airbrake.notify`
>    - Uncaught exception / unhandled rejection handlers that forward to a remote service
>
> 4. **APM / tracing / observability**:
>    - `tracer.addTags`, `tracer.startSpan`, `span.setAttribute`, `span.setTag`, `span.addEvent`
>    - `newrelic.addCustomAttribute`, `newrelic.setTransactionName`, `newrelic.noticeError`
>    - `datadog.addTags`, `dd-trace` span additions
>    - OpenTelemetry `span.setAttribute`, `span.setAttributes`, `baggage.setMember`
>    - `Honeycomb.addField`, `honeycomb.addContext`
>
> 5. **Analytics / product telemetry**:
>    - `mixpanel.track`, `mixpanel.people.set`
>    - `segment.track`, `analytics.track`, `analytics.identify`
>    - `amplitude.logEvent`, `amplitude.setUserProperties`
>    - `posthog.capture`, `posthog.identify`
>    - `ga`, `gtag`, `dataLayer.push`
>
> 6. **Stringify-like helpers** often used with the above:
>    - `JSON.stringify(...)`, `util.inspect(...)`, `inspect(...)`
>    - Python `repr(...)`, `str(request)`, `pprint.pformat`, f-strings dumping entire objects
>    - Java `toString()` called on domain objects in log statements
>    - Ruby `.inspect`, `.to_json`
>    - These are *not* sinks by themselves, but when combined with a log/telemetry call they dramatically increase the chance of leaking everything in the object.
>
> 7. **Audit / event publishers** — if the project has them:
>    - Kafka `producer.send`, RabbitMQ `channel.publish`, SQS `sendMessage`, event bus `emit` — only flag if the payload clearly includes request/user objects rather than a narrow allowlist.
>
> **What to skip during recon**:
>
> - Test files (`*.test.*`, `*.spec.*`, `__tests__/`, `tests/`) unless the test fixtures are used in production
> - Comments and documentation strings that only *mention* a log call
> - Build tooling logs (webpack, vite, rollup config scripts) that run at build time only
> - Files in `.git/`, `node_modules/`, `vendor/`, `venv/`, `__pycache__/`, `dist/`, `build/`
> - String literals that only contain "log" or "print" as substrings without being a call
>
> **Output format** — write to `sast/pii-recon.md`:
>
> ```markdown
> # PII / Credential Log Leakage Recon: [Project Name]
>
> ## Summary
> Found [N] log/telemetry/error sink call sites.
>
> ## Logging stack (from architecture.md + code inspection)
> - Primary logger: [pino / winston / log4j2 / python logging / etc.]
> - Error reporter: [Sentry / Rollbar / none detected]
> - APM: [Datadog / New Relic / OpenTelemetry / none]
> - Analytics: [Segment / Mixpanel / none]
> - Global redaction config found: [yes/no, with file:line reference]
>
> ## Candidates
>
> ### 1. [Descriptive name — e.g., "Express request middleware logs full req.headers"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Sink type**: [console.log / logger.info / Sentry.captureException / span.setAttribute / res.send / analytics.track / etc.]
> - **What is passed to the sink**: [whole request / whole user object / specific field / exception with message+stack / event properties object / etc.]
> - **Stringify present**: [yes — JSON.stringify(req) / no / n/a]
> - **Code snippet**:
>   ```
>   [The line(s) containing the sink call, with a few lines of surrounding context]
>   ```
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/pii-recon.md`. If the recon found **zero candidates**, **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/pii-results.md` and the corresponding empty `sast/pii-results.json`, then stop:

```markdown
# PII / Credential Log Leakage Results

No vulnerabilities found.
```

```json
{ "findings": [] }
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Sensitivity Check (Batched)

After Phase 1 completes, read `sast/pii-recon.md` and split candidates into **batches of up to 3**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned sinks and writes to its own batch file.

**Batching procedure** (you, the orchestrator, do this):

1. Read `sast/pii-recon.md` and count numbered candidate sections.
2. Divide into batches of up to 3 (e.g., 8 candidates -> 3+3+2).
3. For each batch, extract the full text of those candidate sections.
4. Launch batch subagents **in parallel**, passing each only its assigned candidates.
5. Each subagent writes to `sast/pii-batch-N.md`.

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: Verify the following log/telemetry sink candidates for PII or credential leakage. For each, determine what sensitive data (if any) actually flows into the sink, and whether existing redaction mitigates it. Write results to `sast/pii-batch-[N].md`.
>
> **Your assigned candidates**:
>
> [Paste the full text of the assigned candidate sections from `sast/pii-recon.md`, preserving original numbering]
>
> **Context**: You will be given `sast/architecture.md`. Use it to understand the data model (which fields on the user/account/session objects are sensitive), the logger configuration (any global `redact` / `beforeSend` / filter), and the deployment target (where logs end up — CloudWatch, Datadog, Sentry, plain files).
>
> **For each candidate, answer these four questions in order:**
>
> **Question 1: What data type reaches the sink?**
>
> Classify the argument(s) passed to the sink:
> - **Whole request object** — `req`, `request`, `ctx.request`. Almost always contains headers (Authorization, Cookie) and body (password, ssn, card_number). Presumed high-risk.
> - **Whole response object** — `res`, `response` — sometimes contains the body about to be sent; treat like a whole request.
> - **Whole user / account / session domain object** — look up the model/schema. If it has `password`, `passwordHash`, `token`, `refreshToken`, `mfaSecret`, `apiKey`, `sessionId`, `ssn`, `tckn`, `dob`, `cardNumber` — high-risk.
> - **Specific named field** — e.g., `user.email`, `order.total`. Check the field name against the severity rubric below.
> - **Exception / error object** — `err`, `e`, `ex`, `error`. Exception messages frequently include the offending value (SQL with user input, HTTP with Authorization header, filesystem path with session id).
> - **Analytics event properties object** — check every property key; ships to third-party vendors.
> - **String that interpolates sensitive fields** — `` `login for ${user.email} with pw ${user.password}` ``.
>
> Note: `JSON.stringify(obj)` and `util.inspect(obj)` escalate "whole object" risk because they serialize every own-enumerable property including ones that would not be logged by a default `toString()`.
>
> **Question 2: What known-sensitive fields are present?**
>
> Use this severity rubric:
>
> | Severity | Fields |
> |---|---|
> | **Critical** | `password`, `password_hash`, `passwordHash`, `token`, `accessToken`, `refreshToken`, `apiKey`, `authToken`, `bearer`, `Authorization` header, `Cookie` header, `session_id`, `sessionId`, `sessionToken`, `csrfToken`, `mfaSecret`, `totpSecret`, `otp`, `otpCode`, `cvv`, `cvc`, `privateKey`, `signingKey`, `webhookSecret`, `clientSecret` |
> | **High** | `email`, `phone`, `phoneNumber`, `mobile`, `ssn`, `social_security`, `tckn` (Turkish national ID), `taxId`, `ein`, `passportNumber`, `nationalId`, `dob`, `dateOfBirth`, `birthDate`, `creditCard`, `cardNumber`, `pan`, `iban`, `accountNumber`, `routingNumber` |
> | **Medium** | Full name combined with other identifiers (name + email + address), IP address + timestamp together, precise geolocation (lat/lon with >3 decimals), device fingerprint combined with user id, health/medical fields (`diagnosis`, `prescription`), sexual orientation, religion, political affiliation |
> | **Info** | Last-4 of card (`last4`, `cardLast4`), already-masked phone (`(+90) *** *** **45`), already-hashed email-for-analytics, anonymized user id without cross-reference |
>
> If a domain object is logged as a whole, assume every field on its schema is logged — look at the model/schema definition to enumerate sensitive fields. If the architecture notes a DTO layer (`toPublicView`, `toJSON` that strips), verify the DTO actually excludes the sensitive fields.
>
> **Question 3: Is there effective redaction at this sink?**
>
> A sink is mitigated if **all** sensitive fields identified in Question 2 are provably removed before they leave the process. Check:
> - **Logger-level redact config**: does `pino({ redact: [...] })` / `winston.format(...)` / `logback.xml` scrubbers name the field (or a wildcard that covers it)? Confirm by reading the config file.
> - **Sentry `beforeSend` / `before_send` hook**: does it strip the field? Read the hook implementation.
> - **APM / OpenTelemetry attribute processor** that drops matching keys.
> - **Inline masking** at the call site: `maskCard(card)`, `user.toPublicView()`, destructured allowlist `{ id, email: maskEmail(user.email) }`.
> - **Middleware that mutates `req.body` before any logger sees it** — rare but valid.
>
> A sink is **not** mitigated if:
> - No redact config exists for the logger.
> - The redact config does not cover the specific field (e.g., `redact: ['password']` does not cover `req.body.user.password` unless a wildcard is used).
> - The sink is `console.log` / `System.out.println` / direct `print` — these bypass logger-level redaction entirely.
> - The field arrives via an exception message (redact configs generally only match structured fields, not exception `.message` strings).
>
> **Question 4: Where do these logs actually go?**
>
> Use `sast/architecture.md` and deployment config to determine the destination:
> - **Local stdout only, ephemeral** (dev mode) — lower impact.
> - **Centralized log aggregator** (CloudWatch, Datadog, Loki, Splunk, ELK) — broader access.
> - **Third-party SaaS** (Sentry, Rollbar, LogRocket, FullStory) — data leaves the organization's boundary; treat as highest impact.
> - **Browser console** (client-side `console.log`) — visible to any user plus session-replay capture.
>
> **Classification**:
> - **Vulnerable**: A known-sensitive field (Question 2, Critical or High) provably reaches the sink (Question 1) and is not mitigated (Question 3), and the destination (Question 4) is persistent / shared / third-party.
> - **Likely Vulnerable**: A sensitive field *probably* reaches the sink based on type/shape, but the exact runtime value cannot be fully confirmed, or redaction is partial.
> - **Not Vulnerable**: Either no sensitive field reaches the sink (explicit allowlist is used), OR effective redaction covers all identified fields, OR the data is Info-severity only.
> - **Needs Manual Review**: The shape of the logged object is dynamic and cannot be reasoned about from the code alone.
>
> **Output format** — write to `sast/pii-batch-[N].md`:
>
> ```markdown
> # PII / Credential Log Leakage Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Sink**: [logger.info / console.log / Sentry.captureException / etc.]
> - **What flows in**: [whole req / user object with passwordHash / exception message that includes SQL + user email / etc.]
> - **Sensitive fields identified**: [list, with severity tags, e.g., "password (critical), email (high)"]
> - **Severity**: [critical / high / medium / info — take the max of all identified fields]
> - **Redaction status**: [none / partial — covers X but not Y / full but bypassed because the sink is console.log]
> - **Destination**: [Sentry SaaS / CloudWatch / local stdout / browser console]
> - **Issue**: [One-sentence summary — e.g., "Login route logs the full request body including plaintext password to Datadog"]
> - **Impact**: [Who can see this data, what they could do with it — e.g., "Every engineer with Datadog access sees plaintext passwords; an attacker with read access to logs can take over accounts"]
> - **Evidence**:
>   ```
>   [Code snippet — REDACT any real secret values if they appear as literals]
>   ```
> - **Remediation**: [Specific fix — "Replace `logger.info(req.body)` with `logger.info({ email: req.body.email }, 'login')`. Add `redact: ['password', '*.password', 'req.headers.authorization']` to pino config."]
> - **Verification Steps**:
>   ```
>   [How to confirm — e.g., "Trigger a login in staging, then query Datadog for the request's log entry and confirm `password` is absent"]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Sink**: [type]
> - **What probably flows in**: [best guess]
> - **Why uncertain**: [e.g., "Object is built dynamically from spread arguments; cannot confirm whether `password` is excluded"]
> - **Evidence**:
>   ```
>   [Code snippet]
>   ```
> - **Remediation**: [Fix recommendation]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Reason**: [e.g., "Only logs `req.id` and `req.method`, no sensitive fields reach the sink" / "Pino redact config at src/logger.ts:12 covers all identified fields" / "Field is already Info-severity (last4 of card)"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [Why it cannot be resolved statically]
> - **Suggestion**: [What to check manually — e.g., "Trace where `event.properties` is assembled across the pipeline"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/pii-batch-*.md` file and merge them into a single `sast/pii-results.md`, and also emit the canonical `sast/pii-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/pii-batch-1.md`, `sast/pii-batch-2.md`, ... files.
2. Collect all findings, preserving classification and detail fields.
3. Count totals across batches for the executive summary.
4. Write the merged markdown report to `sast/pii-results.md`:

```markdown
# PII / Credential Log Leakage Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

By severity (Vulnerable + Likely Vulnerable only):
- Critical: [N]
- High: [N]
- Medium: [N]
- Info: [N]

## Findings

[All findings, grouped by classification: VULNERABLE first (sorted by severity
 critical -> info), then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then
 NOT VULNERABLE. Preserve every field from the batch results exactly.]
```

5. Write the machine-readable `sast/pii-results.json` with one entry per **Vulnerable** or **Likely Vulnerable** finding:

```json
{
  "findings": [
    {
      "id": "pii-1",
      "skill": "sast-pii",
      "severity": "critical",
      "title": "Login route logs plaintext password via logger.info(req.body)",
      "description": "The POST /login handler passes the full request body to the pino logger with no redact config. Plaintext passwords are shipped to Datadog and retained for 30 days. Any engineer with Datadog access can harvest credentials.",
      "location": { "file": "src/routes/auth.ts", "line": 42, "column": 5 },
      "remediation": "Replace logger.info(req.body) with an explicit allowlist (logger.info({ email: req.body.email })). Add redact: ['password', '*.password', 'req.headers.authorization', 'req.headers.cookie'] to the pino config."
    }
  ]
}
```

If there are zero Vulnerable and zero Likely Vulnerable findings, still emit:

```json
{ "findings": [] }
```

6. After writing `sast/pii-results.md` and `sast/pii-results.json`, **delete all intermediate files** (`sast/pii-recon.md` and `sast/pii-batch-*.md`).

---

## Findings Template

Each Vulnerable finding in `sast/pii-results.md` follows this exact shape (repeat fields as needed):

```markdown
### [VULNERABLE] <short descriptive name>
- **File**: `<relative/path.ext>` (lines X-Y)
- **Sink**: <logger.info | console.log | Sentry.captureException | span.setAttribute | analytics.track | res.send | ...>
- **What flows in**: <whole req / user domain object / exception message / event props>
- **Sensitive fields identified**: <field1 (severity), field2 (severity), ...>
- **Severity**: <critical | high | medium | info>
- **Redaction status**: <none | partial (covers X but not Y) | bypassed (sink ignores logger config)>
- **Destination**: <Sentry | Datadog | CloudWatch | local stdout | browser console | Kafka topic>
- **Issue**: <one-sentence summary>
- **Impact**: <who can read it, what they can do with it>
- **Evidence**:
  ```
  <code snippet with real secrets redacted>
  ```
- **Remediation**: <specific code change + config change>
- **Verification Steps**:
  ```
  <how to confirm the fix works>
  ```
```

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context. Pay particular attention to the logger library, Sentry/APM config, and the user/account/session model definitions.
- Phase 2 must run AFTER Phase 1 completes — it depends on recon output.
- Phase 3 must run AFTER all Phase 2 batches complete.
- Batch size is **3 candidates per subagent**. Launch all batches **in parallel**.
- **Severity is driven by the field, not the sink.** A `password` logged to `console.log` is still critical. An already-masked `last4` logged to Sentry is info-severity.
- **`JSON.stringify(x)` + log = presume whole object leakage** unless you can prove the object schema has no sensitive fields.
- **Exception messages leak too.** `logger.error(err)` where `err.message` contains the raw SQL or HTTP headers is vulnerable even if the surrounding object is narrow.
- **Client-side `console.log` is persistent for the user** (browser history, session-replay tools, support-tool screenshots) — report it.
- **Don't double-report hardcoded secrets.** If the sensitive data is a string literal in source code, that's `sast-hardcodedsecrets`, not this skill. This skill is about data flowing through code at runtime.
- **Redact real values in the results file.** If a snippet happens to include a real token or email, mask the middle (e.g., `Bearer abcd****wxyz`, `alice@****.com`) — the results file itself must not become a leakage vector.
- When in doubt, prefer "Needs Manual Review" over "Not Vulnerable". False negatives on PII logging are hard to recover from once logs are aggregated.
- Clean up intermediate files: delete `sast/pii-recon.md` and all `sast/pii-batch-*.md` after `sast/pii-results.md` and `sast/pii-results.json` are written.
