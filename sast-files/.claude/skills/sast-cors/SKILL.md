---
name: sast-cors
description: >-
  Detect CORS misconfiguration vulnerabilities in a codebase using a three-phase
  approach: recon (find CORS middleware, header setters, and preflight handlers),
  batched verify (analyze each configuration in parallel batches of 3), and merge
  (consolidate batch results). Flags wildcard-with-credentials, reflected Origin,
  unescaped regex origin checks, null-origin acceptance, and missing `Vary: Origin`.
  Requires sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/cors-results.md. Use when asked to find CORS misconfigurations or
  cross-origin credential theft risks.
version: 0.1.0
---

# CORS Misconfiguration Detection

You are performing a focused security assessment to find CORS (Cross-Origin Resource Sharing) misconfiguration vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find CORS configuration sites), **batched verify** (analyze each configuration in parallel batches of 3 sites each), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is CORS Misconfiguration

CORS is the browser-enforced protocol that decides whether a script running on origin A may read a response fetched from origin B. The server declares the policy via response headers — primarily `Access-Control-Allow-Origin` (ACAO), `Access-Control-Allow-Credentials` (ACAC), `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers`.

A **CORS misconfiguration** occurs when the server's policy is too permissive. The two most dangerous flavors:

1. **Permissive ACAO combined with credentials** — a wildcard or near-wildcard origin together with `Access-Control-Allow-Credentials: true` instructs browsers to send cookies/Authorization headers on cross-origin reads and to expose the authenticated response to the attacker's page.
2. **Reflective ACAO** — the server copies the request's `Origin` header verbatim into the response without validating it against an allowlist. Combined with credentials, this is equivalent to a wildcard: any attacker-controlled origin is trusted.

The result is cross-origin credential theft: an attacker page at `https://evil.example` can trigger an authenticated `fetch('https://victim.example/api/me', {credentials: 'include'})`, read the JSON response, and exfiltrate session-bound data (profile, tokens, CSRF tokens, private content).

### What CORS Misconfig IS

- Server permits any origin (`*`, reflected, or broad regex) to read authenticated responses.
- Server returns `Access-Control-Allow-Credentials: true` for untrusted origins.
- Origin allowlist check is bypassable (substring match, prefix/suffix match, unescaped-dot regex, `null` origin accepted, stale subdomain).
- CDN or reverse proxy caches a response with a permissive ACAO computed for one origin and replays it to others (missing `Vary: Origin`).

### What CORS Misconfig is NOT

Do not conflate with:
- **CSRF (Cross-Site Request Forgery)**: A state-changing request is triggered by the browser while authenticated, but the attacker never needs to read the response. CSRF is about request forgery; CORS misconfiguration is about *reading* cross-origin responses. They have different defenses (CSRF tokens / SameSite cookies vs. origin allowlists) and are tracked by the **sast-csrf** skill.
- **SSRF (Server-Side Request Forgery)**: The server itself is tricked into making outbound requests to attacker-chosen URLs. This has nothing to do with browser-enforced CORS; it is a separate class covered by **sast-ssrf**.
- **Open redirect**: The server 302-redirects to an attacker URL. Covered by **sast-openredirect**.
- **postMessage / WebSocket origin checks**: These are related but live outside the `Access-Control-*` header protocol.

### Patterns That Prevent CORS Misconfig

When you see these patterns, the configuration is likely **not vulnerable**:

1. **Explicit origin allowlist** — the server compares the request `Origin` against a hard-coded list of trusted origins and only echoes back matches.
2. **NEVER `*` combined with credentials** — either credentials are disabled OR the origin is a specific value (never `*`). Browsers reject `ACAO: *` with `ACAC: true`, but the code intent is still wrong and is often accompanied by a reflected-origin fallback elsewhere.
3. **Do not echo the `Origin` request header** — the server must not take `req.headers.origin` or `request.META['HTTP_ORIGIN']` and place it directly in ACAO without a membership check.
4. **Explicit `null` origin handling** — the `null` origin (sent by `file://`, sandboxed iframes, `data:` URLs, some redirects) must be rejected unless there is a clear documented reason to accept it.
5. **Full string equality on origin, not substring / prefix / suffix / loose regex** — allowlist checks must compare the entire origin, scheme + host + port, using equality, not `startsWith`, `endsWith`, or regex-with-unescaped-dots.
6. **`Vary: Origin` on any response whose ACAO depends on the request Origin** — prevents CDNs and reverse proxies from caching one origin's ACAO and serving it to another.
7. **Credentials only where actually required** — public, unauthenticated endpoints should use `ACAC: false` (or omit the header) so that even a permissive origin cannot leak user data.

---

## Vulnerable vs. Secure Examples

### Node.js — Express (`cors` middleware)

```javascript
// VULNERABLE: origin:true reflects any origin; with credentials this is cross-origin credential theft.
const cors = require('cors');
app.use(cors({ origin: true, credentials: true }));

// VULNERABLE: dynamic origin callback that always accepts.
app.use(cors({
    origin: (origin, cb) => cb(null, true),   // echoes whatever came in
    credentials: true,
}));

// VULNERABLE: wildcard with credentials (browsers reject, but the intent is wrong and
// often paired with a reflected fallback elsewhere).
app.use(cors({ origin: '*', credentials: true }));

// SECURE: explicit allowlist, exact match.
const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);
app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, false);           // reject null / same-origin tools
        if (ALLOWED.has(origin)) return cb(null, true);
        return cb(new Error('origin not allowed'));
    },
    credentials: true,
}));
```

### Node.js — Raw header setting

```javascript
// VULNERABLE: reflects the request Origin verbatim.
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});

// VULNERABLE: prefix/suffix string match — 'evil-example.com' matches endsWith('example.com').
if (origin && origin.endsWith('example.com')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// SECURE: exact match against allowlist, and Vary: Origin so caches stay correct.
const ALLOWED = new Set(['https://app.example.com']);
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (ALLOWED.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');
    }
    next();
});
```

### Node.js — Fastify

```javascript
// VULNERABLE: origin:true reflects everything.
await app.register(require('@fastify/cors'), {
    origin: true,
    credentials: true,
});

// VULNERABLE: regex with unescaped dots — '.' matches any character.
await app.register(require('@fastify/cors'), {
    origin: /^https:\/\/.*example.com$/,   // matches https://evil-example.com
    credentials: true,
});

// SECURE: exact allowlist; escaped dots; no credential leak to third parties.
await app.register(require('@fastify/cors'), {
    origin: ['https://app.example.com', 'https://admin.example.com'],
    credentials: true,
});
```

### Python — Django (`django-cors-headers`)

```python
# VULNERABLE: allows any origin AND sends credentials.
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# VULNERABLE: regex that matches attacker-controlled subdomain of a takeoverable host.
CORS_ALLOWED_ORIGIN_REGEXES = [r"^https://.*\.example\.com$"]
CORS_ALLOW_CREDENTIALS = True
# → if an old unclaimed subdomain like 'abandoned.example.com' can be registered on the
#   CDN/PaaS, the attacker now has a fully trusted origin.

# SECURE: fixed allowlist.
CORS_ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]
CORS_ALLOW_CREDENTIALS = True
```

### Python — Flask (`Flask-CORS`)

```python
# VULNERABLE: wildcard with credentials.
from flask_cors import CORS
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# VULNERABLE: hand-rolled after_request that echoes the Origin.
@app.after_request
def add_cors(resp):
    resp.headers['Access-Control-Allow-Origin']      = request.headers.get('Origin', '')
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp

# SECURE: exact allowlist, credentials only where required.
CORS(
    app,
    resources={r"/api/*": {"origins": ["https://app.example.com"]}},
    supports_credentials=True,
)
```

### Java — Spring (`@CrossOrigin` / `CorsConfiguration`)

```java
// VULNERABLE: wildcard combined with credentials on a data-returning controller.
@CrossOrigin(origins = "*", allowCredentials = "true")
@RestController
public class MeController { ... }

// VULNERABLE: pattern with a wildcard subdomain.
CorsConfiguration cfg = new CorsConfiguration();
cfg.setAllowedOriginPatterns(List.of("https://*.example.com"));
cfg.setAllowCredentials(true);
// → any subdomain takeover becomes a trusted origin.

// SECURE: exact origins, credentials enabled only deliberately.
CorsConfiguration cfg = new CorsConfiguration();
cfg.setAllowedOrigins(List.of("https://app.example.com"));
cfg.setAllowCredentials(true);
cfg.addAllowedMethod("GET");
cfg.addAllowedHeader("Authorization");
```

### Go — `rs/cors` and `gin-contrib/cors`

```go
// VULNERABLE: AllowAllOrigins with AllowCredentials.
r.Use(cors.New(cors.Config{
    AllowAllOrigins:  true,
    AllowCredentials: true,  // library may ignore, but intent is wrong
}))

// VULNERABLE: AllowOriginFunc that always returns true.
r.Use(cors.New(cors.Config{
    AllowOriginFunc:  func(origin string) bool { return true },
    AllowCredentials: true,
}))

// SECURE: explicit origins.
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"https://app.example.com"},
    AllowCredentials: true,
    AllowMethods:     []string{"GET", "POST"},
}))
```

### PHP — Laravel (`fruitcake/laravel-cors`)

```php
// VULNERABLE: wildcard origin + credentials.
// config/cors.php
return [
    'paths'                    => ['api/*'],
    'allowed_origins'          => ['*'],
    'allowed_origins_patterns' => [],
    'supports_credentials'     => true,
];

// SECURE
return [
    'paths'                    => ['api/*'],
    'allowed_origins'          => ['https://app.example.com'],
    'allowed_origins_patterns' => [],
    'supports_credentials'     => true,
];
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: AllowAnyOrigin with credentials (framework throws, but reflected variants exist).
services.AddCors(o => o.AddPolicy("permissive", b =>
    b.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

// VULNERABLE: SetIsOriginAllowed always true.
services.AddCors(o => o.AddPolicy("reflect", b =>
    b.SetIsOriginAllowed(_ => true).AllowAnyHeader().AllowCredentials()));

// SECURE
services.AddCors(o => o.AddPolicy("app", b =>
    b.WithOrigins("https://app.example.com").AllowCredentials()));
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find CORS Configuration Sites

Launch a subagent with the following instructions:

> **Goal**: Build a complete map of every place the application configures CORS — middleware registration, dedicated CORS libraries, hand-rolled header setters, and framework-level annotations. Write results to `sast/cors-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the web framework, reverse proxy (if any), and how HTTP responses are produced.
>
> **What to search for**:
>
> 1. **CORS middleware registration** — library-level configuration:
>    - Node.js: `cors` package (`app.use(cors(...))`, `require('cors')`), `@fastify/cors`, `@koa/cors`, NestJS `enableCors`
>    - Python: `flask_cors.CORS(...)`, `CORS_ALLOWED_ORIGINS`, `CORS_ALLOW_ALL_ORIGINS`, `CORS_ALLOW_CREDENTIALS`, `CORS_ALLOWED_ORIGIN_REGEXES` (django-cors-headers), FastAPI `CORSMiddleware`, Starlette `CORSMiddleware`
>    - Java/Spring: `@CrossOrigin`, `CorsConfiguration`, `CorsConfigurationSource`, `addCorsMappings`, `WebMvcConfigurer`
>    - Go: `rs/cors.New`, `gin-contrib/cors`, custom middleware writing `Access-Control-*` headers
>    - Ruby/Rails: `rack-cors` `Rack::Cors` block, `allow`, `resource`, `origins`
>    - PHP/Laravel: `config/cors.php`, `fruitcake/laravel-cors`
>    - ASP.NET: `AddCors`, `UseCors`, `CorsPolicyBuilder`, `WithOrigins`, `AllowAnyOrigin`, `SetIsOriginAllowed`
>
> 2. **Hand-rolled header setters** — direct writes to CORS response headers:
>    - `Access-Control-Allow-Origin`
>    - `Access-Control-Allow-Credentials`
>    - `Access-Control-Allow-Methods`
>    - `Access-Control-Allow-Headers`
>    - `Access-Control-Expose-Headers`
>    - `Access-Control-Max-Age`
>    - `Vary: Origin` (presence/absence matters for caching)
>
>    Look for: `setHeader`, `res.header`, `response.headers[...] =`, `response.setHeader`, `add_header`, `HttpContext.Response.Headers.Add`, reverse-proxy config (`nginx.conf`, `httpd.conf`, `Caddyfile`).
>
> 3. **Origin allowlist data** — where the list of trusted origins lives:
>    - Environment variables, config files (`config/cors.php`, `application.yml`, `settings.py`)
>    - Hard-coded arrays / sets / regexes in source
>    - Dynamic sources (database, feature flags)
>
> 4. **Reverse proxy / edge** — CORS can be added outside the app:
>    - `nginx` `add_header Access-Control-Allow-Origin ...`
>    - CloudFront / Cloudflare / API Gateway response-header rules
>    - Service-mesh filters (Envoy, Istio `CorsPolicy`)
>
> **What to ignore**:
> - Static-asset hosts that serve no credentials (e.g., pure image CDNs where no cookies exist on the origin).
> - Completely public, stateless APIs with no cookies / no `Authorization` usage — though still worth noting.
>
> **Output format** — write to `sast/cors-recon.md`:
>
> ```markdown
> # CORS Recon: [Project Name]
>
> ## Summary
> - CORS libraries detected: [e.g., cors, django-cors-headers, @fastify/cors]
> - Reverse proxies adding CORS headers: [e.g., nginx, CloudFront / none]
> - Credentials-bearing endpoints (cookies or Authorization header): [yes / no / partial]
>
> ## Configuration Sites
>
> ### 1. [Short description, e.g. "Express global cors() middleware"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Mechanism**: [library call / raw header setter / annotation / proxy config]
> - **Origin policy**: [literal value or callback summary — wildcard / reflect / allowlist / regex]
> - **Credentials**: [ACAC true / false / not set]
> - **Applies to**: [route prefix or global / per-controller / specific method]
> - **Code snippet**:
>   ```
>   [relevant lines including origin configuration and credentials flag]
>   ```
>
> [Repeat for each configuration site]
> ```

### Phase 2: Verify — Configuration Analysis (Batched)

After Phase 1 completes, read `sast/cors-recon.md` and split the configuration inventory into **batches of up to 3 sites each** (each numbered `### N.` under **Configuration Sites**). Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/cors-recon.md` and count the numbered configuration sections.
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1–3, 4–6, 7).
3. For each batch, extract the full text of those configuration sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/cors-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: Analyze the following CORS configuration sites for misconfiguration vulnerabilities that enable cross-origin credential theft. Write results to `sast/cors-batch-[N].md`.
>
> **Your assigned configuration sites** (from the recon phase):
>
> [Paste the full text of the assigned configuration sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to determine whether endpoints under this configuration actually carry user credentials (cookies / `Authorization` header) and therefore whether a CORS leak is exploitable.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Footguns to check for each site**:
>
> 1. **Wildcard ACAO with credentials**: `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. Browsers reject this combination, but its presence in code strongly signals confusion about the threat model and almost always co-exists with a reflected-origin fallback — flag it.
>
> 2. **Reflected origin without allowlist**: any pattern that copies the request `Origin` into the response without membership check:
>    - `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)`
>    - `cors({ origin: true, credentials: true })`
>    - `cors({ origin: (o, cb) => cb(null, true) })`
>    - `SetIsOriginAllowed(_ => true)`
>    - `AllowOriginFunc: func(origin string) bool { return true }`
>    - Django `CORS_ALLOW_ALL_ORIGINS = True` + `CORS_ALLOW_CREDENTIALS = True`
>
> 3. **`null` origin accepted**: allowlists that include `"null"` as a string, or reflective configurations that will happily echo back `Origin: null`. The `null` origin is sent by sandboxed iframes, `data:` URIs, some redirect chains, and local `file://` — accepting it lets any attacker page create a `null`-origin context.
>
> 4. **Substring / prefix / suffix string match**:
>    - `origin.endsWith('example.com')` → `evil-example.com` matches
>    - `origin.startsWith('https://app.example')` → `https://app.example.evil.com` matches
>    - `origin.includes('example.com')` → `evil.com?example.com` or host-header tricks
>
> 5. **Regex with unescaped dots**:
>    - `^https://.*example.com$` → `.` matches any char, so `evil-example!com` and `evilXexampleXcom` match depending on the regex engine; more practically `evil-example.com` matches because `-` matches `.*` and `.` matches `.`
>    - `^https://.+\.example\.com$` with wildcard subdomain — combined with a dangling / takeoverable subdomain, the attacker effectively owns a trusted origin
>
> 6. **Subdomain wildcard + subdomain takeover**: any pattern like `*.example.com`, `https://*.example.com`, or `setAllowedOriginPatterns("https://*.example.com")`. This is only as safe as the weakest subdomain — review whether the project uses CDN/PaaS hosts (S3, GitHub Pages, Heroku, Azure, Netlify, Vercel, Shopify) where an unclaimed subdomain could be registered by an attacker.
>
> 7. **`Vary: Origin` missing**: when ACAO depends on the request Origin (reflective or allowlist-echoed) but the response does not carry `Vary: Origin`, a shared cache (CDN, reverse proxy, browser cache) may store the response for one origin and serve it to a different origin — effectively creating a CORS leak even against a correctly-configured allowlist.
>
> 8. **Credentials on an endpoint that does not need them**: `Access-Control-Allow-Credentials: true` applied broadly on a route group that includes public endpoints — this turns any permissive-origin mistake into a credential leak even for endpoints that logically should not care about sessions.
>
> 9. **Edge / proxy overrides**: the framework has a safe allowlist but nginx / CloudFront / API Gateway adds an `Access-Control-Allow-Origin: *` header at the edge — the edge wins. Check both layers.
>
> 10. **Preflight-only vs. actual response**: some configurations apply strict checks only on `OPTIONS` but the actual `GET`/`POST` response has its own header writer that is permissive. The attack browser cares about the *actual* response headers on the credentialed request.
>
> **Classification**:
> - **Vulnerable**: Credentials are enabled (`ACAC: true`) AND the effective origin policy is wildcard, reflective, or bypassable (substring, regex-with-unescaped-dots, `null` accepted, wildcard subdomain of a takeoverable parent). Reading authenticated responses from an attacker origin is possible.
> - **Likely Vulnerable**: Configuration is permissive but the exploit requires an auxiliary condition (e.g., a subdomain takeover, a cache poisoning step, an endpoint that actually sets cookies). Also: wildcard + credentials combinations (rejected by browsers but indicative of broken intent, usually paired with a reflected fallback elsewhere).
> - **Not Vulnerable**: Explicit exact-match allowlist, credentials only where required, `Vary: Origin` present, no `null` acceptance.
> - **Needs Manual Review**: Cannot determine with confidence — origin allowlist is dynamic, loaded from an untraced data source, or the configuration spans multiple layers (framework + nginx + CDN) that need coordinated review.
>
> **Output format** — write to `sast/cors-batch-[N].md`:
>
> ```markdown
> # CORS Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Configuration site name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Mechanism**: [library / raw header / annotation / proxy]
> - **Footgun**: [wildcard+credentials / reflected origin / unescaped-dot regex / null accepted / subdomain wildcard / missing Vary]
> - **Impact**: [What an attacker page can read — e.g., "authenticated /api/me response from any origin, exposing email, role, CSRF token"]
> - **Proof**: [Show the offending line(s) and the credential flag]
> - **Remediation**: [Concrete fix — replace with exact allowlist / remove credentials / escape regex / add Vary: Origin]
> - **Dynamic Test**:
>   ```
>   [curl command showing the server echoing an attacker-controlled Origin and returning
>    Access-Control-Allow-Credentials: true. Example:
>      curl -i -H 'Origin: https://evil.example' <URL_WITH_CREDENTIALED_COOKIE>
>    Confirm the response contains:
>      Access-Control-Allow-Origin: https://evil.example
>      Access-Control-Allow-Credentials: true]
>   ```
>
> ### [LIKELY VULNERABLE] Configuration site name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Concern**: [Why the configuration is risky but not trivially exploitable]
> - **Preconditions**: [What the attacker additionally needs — subdomain takeover, cache poisoning, victim visiting a specific URL]
> - **Proof**: [Snippet]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [curl command or steps to confirm the weak behavior]
>   ```
>
> ### [NOT VULNERABLE] Configuration site name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Protection**: [Exact-match allowlist / no credentials / Vary: Origin present / etc.]
>
> ### [NEEDS MANUAL REVIEW] Configuration site name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [Why automated analysis cannot conclude — dynamic allowlist source / multi-layer config / unclear credential surface]
> - **Suggestion**: [What to inspect manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/cors-batch-*.md` file and merge them into a single `sast/cors-results.md` plus the canonical machine-readable `sast/cors-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/cors-batch-1.md`, `sast/cors-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/cors-results.md` using the **Findings** template below.
5. Write the canonical machine-readable view to `sast/cors-results.json`. Each finding follows the schema:

```json
{
  "findings": [
    {
      "id": "cors-1",
      "skill": "sast-cors",
      "severity": "critical|high|medium|low|info",
      "title": "short one-line description",
      "description": "full explanation including exploitability and preconditions",
      "location": { "file": "relative/path.ext", "line": 123, "column": 1 },
      "remediation": "how to fix"
    }
  ]
}
```

If no findings are confirmed, still write `sast/cors-results.json` with `"findings": []` so the aggregator can verify the scan ran.

6. After writing both files, **delete all intermediate files**: `sast/cors-recon.md` and `sast/cors-batch-*.md`.

---

## Findings

Use this template for `sast/cors-results.md`:

```markdown
# CORS Misconfiguration Analysis Results: [Project Name]

## Executive Summary
- Configuration sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification in this order:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written — File, Mechanism, Footgun,
 Impact, Proof, Remediation, Dynamic Test.]
```

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 configuration sites per subagent**. If there are 1–3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file.
- **Credentials matter**: a permissive ACAO on a truly public, credential-free endpoint is usually low-impact. The severe vulnerability is ACAO + `Access-Control-Allow-Credentials: true`. Always verify whether the endpoints under this policy actually receive cookies or Authorization headers.
- **`null` is not safe**: rejecting `null` is almost always correct; accepting it lets sandboxed iframes and `data:` URIs reach your API with credentials.
- **String matching is not allowlisting**: `endsWith`, `startsWith`, `includes`, and regex with unescaped dots are not equivalent to exact match. Flag them.
- **Check the edge**: nginx, CloudFront, API Gateway, and service-mesh configs can add or override CORS headers; a safe framework config can be undone at the edge.
- **`Vary: Origin`**: whenever ACAO is computed from the request Origin, `Vary: Origin` must be present; otherwise a shared cache can leak one user's ACAO to another origin.
- Do not confuse CORS misconfiguration with CSRF or SSRF — those are separate classes with their own skills (`sast-csrf`, `sast-ssrf`).
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete `sast/cors-recon.md` and all `sast/cors-batch-*.md` files after the final `sast/cors-results.md` and `sast/cors-results.json` are written.
