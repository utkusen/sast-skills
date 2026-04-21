---
name: sast-csrf
description: >-
  Detect Cross-Site Request Forgery (CSRF) vulnerabilities in a codebase using
  a three-phase approach: recon (find state-changing cookie-authenticated
  endpoints), batched verify (check CSRF protections in parallel subagents,
  3 endpoints each), and merge (consolidate batch results). Covers classic
  form/JSON CSRF, login CSRF, GraphQL mutation CSRF, and GET-based state
  changes. Requires sast/architecture.md (run sast-analysis first). Outputs
  findings to sast/csrf-results.md. Use when asked to find CSRF or
  cross-site request forgery bugs.
version: 0.1.0
---

# Cross-Site Request Forgery (CSRF) Detection

You are performing a focused security assessment to find Cross-Site Request Forgery (CSRF) vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find state-changing endpoints that authenticate via cookies/session), **batched verify** (check CSRF protections in parallel batches of 3 endpoints each), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is CSRF

CSRF is a client-side attack where an attacker's page causes a victim's browser to send an authenticated, state-changing request to a target application. The browser automatically attaches ambient credentials (session cookies, HTTP Basic auth, client certs), so if the target has no way to distinguish an attacker-initiated request from a legitimate same-origin one, the action executes under the victim's identity.

The vulnerability has three required preconditions. Remove any one and CSRF is not possible:

1. A **state-changing action** exists (writes data, triggers side effects, changes configuration).
2. The action authenticates via **ambient credentials the browser attaches automatically** — cookies, HTTP Basic, NTLM, client certificates, or TLS session state. Bearer tokens in `Authorization` headers are NOT ambient.
3. The server has **no origin-discriminating check** — no CSRF token, no SameSite cookie attribute, no `Origin`/`Referer` validation, no custom header requirement.

### What CSRF IS

CSRF is specifically a **state-changing, authenticated, cross-origin** request triggered by a victim's browser without their intent. Canonical examples:

- `POST /account/email` on a banking app with only a session cookie — attacker embeds `<form action="https://bank.example/account/email" method="POST">` on evil.com and auto-submits it. The browser attaches the victim's session cookie and the email is changed.
- `POST /api/transfer` accepting JSON via `Content-Type: application/json` but with no custom header check, no token, and `SameSite=None` cookies — attacker's page uses `fetch` with `credentials: 'include'`.
- `POST /login` with no CSRF token — **login CSRF** — attacker logs the victim into the attacker's own account so the victim's subsequent actions are recorded against the attacker's identity.
- `GET /user/delete?id=42` — state change over GET is always CSRF-able regardless of SameSite because top-level GETs are exempt from most default protections.
- `POST /graphql` mutation with cookie auth and no CSRF token or custom header requirement.

### What CSRF is NOT

Do not conflate CSRF with these other vulnerability classes:

- **SSRF (Server-Side Request Forgery)**: The server, not the browser, is coerced into making a request. Covered by sast-ssrf.
- **XSS (Cross-Site Scripting)**: Attacker-controlled script runs in the origin of the target app. If XSS is present, CSRF protections are irrelevant — the attacker script can read tokens. Covered by sast-xss.
- **IDOR**: Authenticated user A accessing user B's resource by changing an ID. The request is same-origin and intentional; the bug is missing authorization. Covered by sast-idor.
- **Public APIs with no cookie authentication**: If an endpoint is intentionally unauthenticated or authenticates exclusively via a Bearer token that the browser does NOT attach automatically, there is nothing for CSRF to steal. Missing auth altogether is covered by sast-missingauth.
- **CORS misconfiguration enabling credentialed cross-origin reads**: That is a data exfiltration issue (covered by sast-cors), not CSRF. CSRF exploits write actions without needing to read the response.
- **Sub-resource integrity**: SRI protects against tampered CDN scripts. Unrelated.

### Patterns That Prevent CSRF

When you see these patterns applied correctly to a state-changing endpoint, the endpoint is likely **not vulnerable**:

**1. Synchronizer CSRF token (server-stored, per-session or per-request)**
The server issues a random token tied to the session. The client must submit it in a hidden form field or custom header on every state-changing request. The server compares the submitted token to the stored token and rejects on mismatch.

```python
# Django — built-in middleware; forms include {% csrf_token %}
MIDDLEWARE = [..., 'django.middleware.csrf.CsrfViewMiddleware', ...]
```

```ruby
# Rails — on by default in ApplicationController
protect_from_forgery with: :exception
```

**2. Double-submit cookie**
The server sets a random value in a cookie AND requires the same value to appear in a request header (or form field). The attacker's page cannot read the cookie (same-origin policy), so it cannot copy the value into the header.

```javascript
// Express with csurf in double-submit mode, or custom implementation
app.use(csrf({ cookie: true }));
// Client JS reads XSRF-TOKEN cookie and sets X-XSRF-TOKEN header
```

**3. SameSite cookie attribute (`Lax` or `Strict`)**
The browser refuses to attach the cookie on cross-site requests.
- `Strict` — cookie never sent on any cross-site request, including top-level navigations.
- `Lax` — cookie sent on top-level GET navigations only. POST/PUT/PATCH/DELETE from another site get no cookie.

```
Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax
```

**Caveat**: `SameSite=Lax` does NOT protect state-changing GETs because top-level GET navigations still carry the cookie. An endpoint like `GET /admin/delete_user?id=42` is still CSRF-able even with `SameSite=Lax`. Treat any state-changing GET as vulnerable regardless of SameSite.

**4. Origin / Referer header check**
The server verifies that the `Origin` (preferred) or `Referer` header matches the app's own origin.

```go
if r.Header.Get("Origin") != "https://app.example.com" {
    http.Error(w, "forbidden", 403)
    return
}
```

**5. Custom request header requirement (for JSON APIs)**
Browsers cannot set arbitrary headers on a simple cross-origin form submission; adding a header like `X-Requested-With: XMLHttpRequest` triggers a CORS preflight, which the attacker origin will fail. If the server requires a non-standard header on all state-changing requests, cross-origin forms cannot reach it.

```javascript
// Server rejects requests without the custom header
if (!req.headers['x-requested-with']) return res.sendStatus(403);
```

This is only safe if the endpoint rejects `Content-Type: application/x-www-form-urlencoded`, `multipart/form-data`, and `text/plain` — the three "simple" content types that bypass preflight.

**6. Bearer token in `Authorization` header (not cookie auth)**
A pure Bearer-token API where the client pulls the token from `localStorage`/`sessionStorage` and sets `Authorization: Bearer ...` is typically **not vulnerable to CSRF**. The browser does not attach this header automatically on cross-origin requests, and reading the token requires same-origin JS access. CORS further blocks cross-origin credentialed requests unless explicitly allowed. **This only holds if the app does not ALSO accept the same session via a cookie** — mixed auth (cookie OR bearer) is still CSRF-able via the cookie path.

**7. CSRF-protective framework defaults**
Some frameworks protect all state-changing routes by default and require opt-out rather than opt-in.
- Django: `CsrfViewMiddleware` on, unless `@csrf_exempt`.
- Rails: `protect_from_forgery` on via generated `ApplicationController`.
- Spring Security: `CsrfFilter` on by default since 4.x for browser-facing apps.
- ASP.NET Core MVC: `AutoValidateAntiforgeryToken` filter or `[ValidateAntiForgeryToken]`.

Always verify the default was not disabled.

---

## Vulnerability Sub-Classes

### Sub-class 1: Classic State-Change CSRF
The most common form. A POST/PUT/PATCH/DELETE endpoint is cookie-authenticated and lacks a token, origin check, SameSite protection, or custom header requirement.

### Sub-class 2: Login CSRF
`POST /login` accepts credentials, authenticates, and sets the session cookie — with no CSRF token. The attacker logs the victim into the attacker's own account. Subsequent actions by the victim (adding a credit card, saving search history, uploading a document) are stored under the attacker's identity and visible to the attacker. Login CSRF is often overlooked because the endpoint "doesn't have a session yet" — but the side effect (session assignment) is itself a state change.

### Sub-class 3: GET-Based State Change
Any `GET` that writes state is CSRF-able unconditionally. `SameSite=Lax` does not help because Lax still sends cookies on top-level GET navigations, and `<img src="...">` / `<link>` / `<script src="...">` elements auto-fire GETs. Flag every state-changing GET handler.

### Sub-class 4: GraphQL Mutation CSRF
A `POST /graphql` (or `/api/graphql`) endpoint with cookie auth. GraphQL clients typically send `Content-Type: application/json`, which *would* trigger a CORS preflight — BUT if the server also accepts `Content-Type: application/x-www-form-urlencoded` or `text/plain` with a mutation in the body, an attacker form can bypass preflight. Also flag GraphQL endpoints that accept mutations over GET (some servers do, via `?query=mutation...`).

### Sub-class 5: Incomplete or Bypassable Protection
Protection is present in code but broken in practice:
- CSRF middleware applied to some routes but not others (e.g., `@csrf_exempt` on a sensitive mutation).
- Token check only on form submissions (`Content-Type: application/x-www-form-urlencoded`) but not on JSON bodies.
- Token validated only when present — missing token silently accepted.
- SameSite attribute missing because a framework default was overridden to `None` without re-adding other defenses.
- Custom header check that accepts the header from any value, including empty strings.
- Origin check that uses substring match (`if "example.com" in origin`) — matches `evil-example.com` too.
- Token tied to no session, or token value is predictable (sequential, timestamp-based, weak hash).

### Sub-class 6: Cookie + Bearer Dual Auth
The endpoint accepts EITHER a cookie OR a Bearer token. Even if the JS client uses Bearer, an attacker page can still exploit the cookie path cross-origin.

---

## Vulnerable vs. Secure Examples

### Node.js — Express

```javascript
// VULNERABLE: state-changing POST with cookie auth, no CSRF protection
app.use(session({ secret: 'x', cookie: { sameSite: 'none' } }));
app.post('/account/email', requireLogin, async (req, res) => {
    await User.updateOne({ _id: req.user.id }, { email: req.body.email });
    res.sendStatus(200);
});

// VULNERABLE: state-changing GET — CSRF-able even with SameSite=Lax
app.get('/account/delete', requireLogin, async (req, res) => {
    await User.deleteOne({ _id: req.user.id });
    res.redirect('/');
});

// SECURE: csurf middleware issues and validates a per-session token
const csrfProtection = csrf({ cookie: true });
app.post('/account/email', requireLogin, csrfProtection, async (req, res) => {
    await User.updateOne({ _id: req.user.id }, { email: req.body.email });
    res.sendStatus(200);
});

// SECURE: SameSite=Strict cookie + Origin check for defense in depth
app.use(session({
    secret: 'x',
    cookie: { sameSite: 'strict', httpOnly: true, secure: true }
}));
app.use((req, res, next) => {
    const unsafe = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
    if (unsafe && req.headers.origin !== 'https://app.example.com') {
        return res.sendStatus(403);
    }
    next();
});
```

### Node.js — Fastify

```javascript
// VULNERABLE: no @fastify/csrf-protection, cookie session
fastify.register(require('@fastify/session'));
fastify.post('/settings/password', async (req, reply) => {
    await updatePassword(req.session.userId, req.body.password);
    return { ok: true };
});

// SECURE: @fastify/csrf-protection
await fastify.register(require('@fastify/csrf-protection'));
fastify.post('/settings/password', {
    onRequest: fastify.csrfProtection
}, async (req, reply) => {
    await updatePassword(req.session.userId, req.body.password);
    return { ok: true };
});
```

### Python — Django

```python
# VULNERABLE: @csrf_exempt disables the default protection
@csrf_exempt
def update_email(request):
    if request.method == 'POST':
        request.user.email = request.POST['email']
        request.user.save()
        return HttpResponse(status=200)

# VULNERABLE: state-changing GET
def delete_account(request):
    request.user.delete()
    return redirect('/')

# SECURE: default middleware is on; @csrf_protect is explicit
@csrf_protect
@require_POST
@login_required
def update_email(request):
    request.user.email = request.POST['email']
    request.user.save()
    return HttpResponse(status=200)
```

### Python — Flask

```python
# VULNERABLE: no Flask-WTF/CSRFProtect, cookie session
@app.route('/account/email', methods=['POST'])
@login_required
def update_email():
    current_user.email = request.form['email']
    db.session.commit()
    return '', 200

# SECURE: Flask-WTF CSRFProtect applied app-wide
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

@app.route('/account/email', methods=['POST'])
@login_required
def update_email():
    # CSRFProtect validates X-CSRFToken header or csrf_token form field
    current_user.email = request.form['email']
    db.session.commit()
    return '', 200
```

### Ruby on Rails

```ruby
# VULNERABLE: CSRF protection disabled for an API controller that still uses cookies
class Api::SettingsController < ActionController::Base
  skip_before_action :verify_authenticity_token   # <-- dangerous if cookies are still in play

  def update_email
    current_user.update!(email: params[:email])
    head :ok
  end
end

# SECURE: default protection kept; authenticity_token required on all non-GET
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

class SettingsController < ApplicationController
  before_action :authenticate_user!
  def update_email
    current_user.update!(email: params[:email])
    head :ok
  end
end
```

### Java — Spring Boot (Spring Security)

```java
// VULNERABLE: CSRF explicitly disabled but cookie-based session still used
@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())        // <-- removes CsrfFilter
            .formLogin(Customizer.withDefaults())
            .build();
    }
}

// SECURE: CsrfFilter kept on; token stored in cookie for SPA double-submit
@Bean
SecurityFilterChain chain(HttpSecurity http) throws Exception {
    return http
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
        .build();
}
```

### Go — net/http + gorilla/csrf

```go
// VULNERABLE: cookie-auth state change, no CSRF middleware
r := chi.NewRouter()
r.Use(sessionMiddleware)
r.Post("/account/email", updateEmail)

// SECURE: gorilla/csrf wraps the handler tree
CSRF := csrf.Protect([]byte(key), csrf.Secure(true), csrf.SameSite(csrf.SameSiteStrictMode))
http.ListenAndServe(":8080", CSRF(r))

// SECURE: manual Origin check for a JSON API
func requireOrigin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet && r.Method != http.MethodHead {
            if r.Header.Get("Origin") != "https://app.example.com" {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
            }
        }
        next.ServeHTTP(w, r)
    })
}
```

### PHP — Laravel

```php
// VULNERABLE: route excluded from VerifyCsrfToken middleware
// app/Http/Middleware/VerifyCsrfToken.php
protected $except = [
    'account/email',   // <-- bypasses CSRF, still uses session cookie
];

// SECURE: route stays inside the 'web' group which includes VerifyCsrfToken
Route::middleware('web')->group(function () {
    Route::post('/account/email', [AccountController::class, 'updateEmail'])
        ->middleware('auth');
});
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: antiforgery filter not applied, cookie auth in use
[HttpPost("account/email")]
public async Task<IActionResult> UpdateEmail([FromForm] string email) {
    await _users.UpdateEmailAsync(User.GetId(), email);
    return Ok();
}

// SECURE: AutoValidateAntiforgeryTokenAttribute applied globally
services.AddControllersWithViews(options => {
    options.Filters.Add<AutoValidateAntiforgeryTokenAttribute>();
});

// SECURE: explicit attribute per action
[HttpPost("account/email")]
[ValidateAntiForgeryToken]
public async Task<IActionResult> UpdateEmail([FromForm] string email) {
    await _users.UpdateEmailAsync(User.GetId(), email);
    return Ok();
}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find State-Changing Endpoints

Launch a subagent with the following instructions:

> **Goal**: Build an inventory of every state-changing endpoint that authenticates via ambient browser credentials (cookies, HTTP Basic, client cert), along with the CSRF protections (if any) currently applied. Write results to `sast/csrf-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, auth mechanism, session/cookie configuration, and framework CSRF defaults.
>
> **What to search for**:
>
> 1. **Auth mechanism determination** — before listing endpoints, figure out how the app authenticates:
>    - Session cookie (`express-session`, `cookie-session`, `flask-login`, `Django SESSION`, `Rails session`, `Spring SESSION`, ASP.NET Core `CookieAuthentication`)
>    - HTTP Basic / NTLM / client certificates (rare but equally ambient)
>    - Pure Bearer JWT in `Authorization` header (usually immune to CSRF — note but deprioritize)
>    - Mixed: cookie AND Bearer (still vulnerable via the cookie path)
>    - Record the cookie name(s), `SameSite` attribute, `Secure` flag, `HttpOnly` flag, and domain/path.
>
> 2. **State-changing route handlers** — collect every route whose HTTP method is POST/PUT/PATCH/DELETE, OR a GET that performs a write. Search patterns:
>    - Express/Koa: `app.post`, `app.put`, `app.patch`, `app.delete`, `router.post`, etc.
>    - Fastify: `fastify.post`, `fastify.route({ method: 'POST' })`
>    - Django: `@require_POST`, `@require_http_methods(["POST"])`, views checking `request.method`
>    - Flask: `methods=['POST']`, `methods=['PUT']`, etc.
>    - Rails: `routes.rb` — `post`, `put`, `patch`, `delete`, `resources` (generates write actions)
>    - Spring: `@PostMapping`, `@PutMapping`, `@PatchMapping`, `@DeleteMapping`
>    - Go (Chi/Gorilla): `r.Post`, `r.Put`, `r.Patch`, `r.Delete`, `r.MethodFunc`
>    - Laravel: `Route::post`, `Route::put`, `Route::patch`, `Route::delete`
>    - FastAPI: `@router.post/put/patch/delete`
>    - ASP.NET: `[HttpPost]`, `[HttpPut]`, `[HttpPatch]`, `[HttpDelete]`
>    - GraphQL: any `Mutation` resolver reachable via `/graphql`, `/api/graphql`, or similar
>
> 3. **Suspicious GETs that change state** — flag any GET handler that:
>    - Contains `delete`, `remove`, `update`, `set`, `add`, `create`, `enable`, `disable`, `activate`, `cancel`, `confirm`, `approve`, `reject` in the route path or function name
>    - Writes to the database (`User.delete`, `session.save`, `.update()`, `.destroy`)
>    - Sends emails, queues jobs, or triggers billing/payment actions
>
> 4. **Login and session-assignment endpoints** — flag every endpoint that authenticates the user and sets a session cookie (for login CSRF):
>    - `POST /login`, `POST /auth/login`, `POST /sessions`, `POST /signin`, OAuth callbacks that establish session
>
> 5. **CSRF protection currently applied** — for each endpoint, record:
>    - Framework-level default (Django CsrfViewMiddleware on, Rails `protect_from_forgery`, Spring CsrfFilter on, ASP.NET `AutoValidateAntiforgeryToken`)
>    - Explicit middleware/decorator (`csurf`, `@fastify/csrf-protection`, `CSRFProtect`, `@csrf_protect`, `[ValidateAntiForgeryToken]`, `gorilla/csrf`)
>    - Explicit opt-out (`@csrf_exempt`, `skip_before_action :verify_authenticity_token`, `csrf.disable()`, `$except` list, route outside the protected group)
>    - Cookie attributes: `SameSite`, `Secure`, `HttpOnly`
>    - Any Origin/Referer check, custom-header requirement, or token check visible in the handler
>
> 6. **GraphQL endpoints** — if the project has GraphQL:
>    - Locate the GraphQL HTTP endpoint(s)
>    - Check the content-type whitelist (does it accept `application/x-www-form-urlencoded` or `text/plain`?)
>    - Check if mutations are reachable over GET
>    - Note whether a CSRF-prevention middleware wraps the GraphQL route
>
> **What to ignore**:
> - Read-only GET endpoints with no side effects (listing, search, fetching public data)
> - Endpoints authenticated purely via a Bearer header that the browser would not attach automatically — note them but do NOT include them in the verify queue unless dual cookie/Bearer auth is detected
> - Health checks, static assets, webhooks from trusted signed senders (Stripe, GitHub) that authenticate by HMAC signature rather than cookie
>
> **Output format** — write to `sast/csrf-recon.md`:
>
> ```markdown
> # CSRF Recon: [Project Name]
>
> ## Auth Mechanism Summary
> - Primary auth: [session cookie / Bearer JWT / mixed]
> - Session cookie name(s): [list]
> - SameSite attribute: [Strict / Lax / None / not set]
> - Secure flag: [true / false / not set]
> - Framework CSRF default: [on / off / disabled in config]
> - Global CSRF middleware: [name + file location, or "none"]
>
> ## Endpoint Inventory
>
> ### 1. [Endpoint name / description]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Sub-class**: [classic / login CSRF / GET state change / GraphQL mutation]
> - **Cookie auth in use**: [yes / no / mixed]
> - **CSRF protection visible**: [token / SameSite=Strict / Origin check / custom header / none]
> - **Code snippet**:
>   ```
>   [route registration + handler signature + any middleware]
>   ```
>
> [Repeat for each endpoint]
> ```

### Phase 2: Verify — CSRF Protection Check (Batched)

After Phase 1 completes, read `sast/csrf-recon.md` and split the endpoint inventory into **batches of up to 3 endpoints each** (each numbered `### N.` under **Endpoint Inventory**). Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned endpoints and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/csrf-recon.md` and count the numbered endpoint sections under **Endpoint Inventory** (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 8 endpoints → 3 batches (1–3, 4–6, 7–8).
3. For each batch, extract the full text of those endpoint sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned endpoints.
5. Each subagent writes to `sast/csrf-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: Verify the following endpoints for CSRF vulnerabilities. Write results to `sast/csrf-batch-[N].md`.
>
> **Your assigned endpoints** (from the recon phase):
>
> [Paste the full text of the assigned endpoint sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand session config, framework defaults, and CORS policy.
>
> **CSRF preconditions — all three must hold for the endpoint to be vulnerable**:
> 1. State-changing action (write, side effect, config change, session assignment for login CSRF).
> 2. Authenticates via ambient credentials (cookie, Basic, client cert) — NOT purely Bearer.
> 3. No origin-discriminating check: no valid CSRF token, no `SameSite=Strict` (or `Lax` on non-GET), no Origin/Referer check, no custom-header requirement.
>
> **What this skill is NOT** — do NOT flag these here:
> - Missing authentication altogether → sast-missingauth
> - SSRF, XSS, IDOR → their dedicated skills
> - Pure Bearer-token APIs with no cookie fallback → not CSRF-able
> - CORS misconfiguration allowing credentialed reads → sast-cors
>
> **Protective patterns that make the endpoint safe**:
> 1. Synchronizer token validated on every state-changing request
> 2. Double-submit cookie with matching header
> 3. `SameSite=Strict` cookie (or `Lax` for non-GET methods only)
> 4. Origin header verified against allowed origin list (exact match, not substring)
> 5. Required custom header + JSON content-type enforcement (cross-origin forms cannot add custom headers)
> 6. Pure Bearer-token auth with no cookie session accepted
> 7. Framework default (Django CsrfViewMiddleware, Rails `protect_from_forgery`, Spring CsrfFilter, ASP.NET `AutoValidateAntiforgeryToken`) not disabled for this route
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each assigned endpoint, evaluate**:
>
> 1. **Confirm the state change** — does the handler write data, send a message, change config, or assign a session?
>
> 2. **Confirm cookie auth** — is a session cookie (or other ambient credential) required? If the only auth is `Authorization: Bearer ...` and no cookie path exists, the endpoint is likely safe; classify as Not Vulnerable with reason.
>
> 3. **Check every CSRF defense, in order**:
>    - **Token**: Is a token validated? Where is it stored? Is it per-session, per-request, or unbound? Is the check skipped when the token is missing (silent accept)? Does it only cover `application/x-www-form-urlencoded` and not JSON?
>    - **SameSite**: What value is set on the auth cookie? If `Strict`, most classic CSRF is blocked. If `Lax`, only non-GET cross-site is blocked — a state-changing GET is still vulnerable. If `None` or unset (defaults vary by browser), no protection.
>    - **Origin/Referer check**: Is the check an exact string match against an allowlist, or a substring/regex that can be bypassed (`"example.com" in origin` matches `evil-example.com`)?
>    - **Custom header**: Is a non-standard header required AND does the endpoint reject simple content types (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`)?
>
> 4. **Sub-class-specific checks**:
>    - **Login CSRF**: Is a CSRF token required on `POST /login`? If not, the app is vulnerable to login CSRF even if other endpoints are protected.
>    - **GET state change**: Any write in a GET handler is vulnerable unconditionally. SameSite=Lax is not enough.
>    - **GraphQL**: Does `/graphql` accept `text/plain` or `application/x-www-form-urlencoded`? Does it accept mutations over GET? Is the whole endpoint wrapped by a CSRF middleware, or only selected resolvers?
>    - **Dual cookie/Bearer**: Does the endpoint accept a cookie session in addition to Bearer? If yes, treat as cookie-auth for CSRF purposes.
>
> 5. **Edge cases and bypasses**:
>    - Route inside an `@csrf_exempt` / `skip_before_action :verify_authenticity_token` / `$except` list / `csrf.disable()` configuration
>    - Route mounted before the CSRF middleware in the chain
>    - Token check bypassed when the request body is JSON (older csurf configs)
>    - Origin check performed only when the header is present (request with no Origin header slips through)
>    - Token generated but never validated
>    - Token compared with `==` in a language where timing attacks matter (minor, but worth noting)
>    - CORS set to `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — the browser blocks this combo, but any misconfiguration that reflects the Origin with credentials re-opens CSRF vectors
>
> **Classification**:
> - **Vulnerable**: All three preconditions hold and no effective defense is present.
> - **Likely Vulnerable**: A defense is partially applied but can plausibly be bypassed (incomplete coverage, weak token scheme, substring Origin check, SameSite=Lax on a state-changing GET, dual auth).
> - **Not Vulnerable**: A recognized defense is correctly applied, OR the endpoint does not use cookie auth, OR the endpoint does not change state.
> - **Needs Manual Review**: Cannot determine with confidence (e.g., dynamic middleware composition, token validated in a service layer not fully traceable, complex GraphQL schema).
>
> **Output format** — write to `sast/csrf-batch-[N].md`:
>
> ```markdown
> # CSRF Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Sub-class**: [classic / login CSRF / GET state change / GraphQL mutation / dual auth]
> - **Issue**: [Specific reason — no token, SameSite=None, csrf_exempt, Origin not checked, etc.]
> - **Impact**: [What an attacker's page can cause the victim to do]
> - **Proof**: [Show the route definition, handler, and session/cookie config — highlight the missing check]
> - **Remediation**: [Concrete fix — enable middleware, add token, set SameSite=Strict, remove exempt entry, require custom header, etc.]
> - **Dynamic Test**:
>   ```html
>   <!-- attacker.html — host on evil.example and visit while logged into the target -->
>   <form action="https://TARGET/path" method="POST">
>     <input name="email" value="attacker@evil.example">
>   </form>
>   <script>document.forms[0].submit()</script>
>   ```
>   or for JSON:
>   ```javascript
>   fetch('https://TARGET/path', {
>     method: 'POST',
>     credentials: 'include',
>     headers: { 'Content-Type': 'text/plain' },
>     body: JSON.stringify({ email: 'attacker@evil.example' })
>   });
>   ```
>
> ### [LIKELY VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Sub-class**: [...]
> - **Issue**: [What's incomplete — partial defense, bypass hypothesis]
> - **Concern**: [Why the partial defense can still be defeated]
> - **Proof**: [Code path showing the weak check]
> - **Remediation**: [Specific hardening]
> - **Dynamic Test**:
>   ```
>   [HTML/fetch snippet tailored to the weakness]
>   ```
>
> ### [NOT VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Protection**: [Which defense applies — token validated, SameSite=Strict, Origin check, Bearer-only auth, etc.]
>
> ### [NEEDS MANUAL REVIEW] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Uncertainty**: [Why automated analysis couldn't determine]
> - **Suggestion**: [What to inspect manually]
> ```
>
> **Canonical JSON output**: In addition to the markdown batch file, append your findings to `sast/csrf-results.json` (or create it if missing) as an object with a `findings` array. Each finding must follow the canonical schema:
>
> ```json
> {
>   "id": "csrf-<sequential>",
>   "skill": "sast-csrf",
>   "severity": "critical|high|medium|low|info",
>   "title": "short one-line description",
>   "description": "full explanation including exploitability",
>   "location": { "file": "relative/path.ext", "line": 123, "column": 10 },
>   "remediation": "how to fix"
> }
> ```
>
> The merge step (Phase 3) will consolidate per-batch JSON contributions into the final `sast/csrf-results.json`. If your batch has no findings, still contribute an empty list.

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/csrf-batch-*.md` file and merge them into a single `sast/csrf-results.md`. You (the orchestrator) do this directly — no subagent needed. Also consolidate the per-batch JSON contributions into a single canonical `sast/csrf-results.json`.

**Merge procedure**:

1. Read all `sast/csrf-batch-1.md`, `sast/csrf-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and every detail field.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/csrf-results.md` using the format in the **Findings** section below.
5. Write the canonical machine-readable view to `sast/csrf-results.json` as `{ "findings": [...] }` using the canonical schema. Map classifications to severities: VULNERABLE → high or critical (critical for auth/account takeover or financial actions), LIKELY VULNERABLE → medium, NEEDS MANUAL REVIEW → info. NOT VULNERABLE findings are not emitted to JSON. If no findings exist, still write `{ "findings": [] }` so the aggregator can confirm the scan ran.
6. After writing `sast/csrf-results.md` and `sast/csrf-results.json`, **delete all intermediate files**: `sast/csrf-recon.md` and `sast/csrf-batch-*.md`.

---

## Findings

Final human-readable report template for `sast/csrf-results.md`:

```markdown
# CSRF Analysis Results: [Project Name]

## Executive Summary
- Endpoints analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]
- Auth mechanism: [session cookie / Bearer / mixed]
- Global CSRF defense status: [framework default on / off / disabled]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first (further sorted by sub-class: login CSRF > GET state change > classic > GraphQL > dual auth),
 then LIKELY VULNERABLE,
 then NEEDS MANUAL REVIEW,
 then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

The canonical `sast/csrf-results.json` is emitted alongside, matching the project schema defined in `sast-files/CLAUDE.md`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 endpoints per subagent**. If there are 1–3 endpoints total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned endpoints' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- CSRF requires cookie/ambient auth. Pure `Authorization: Bearer` APIs with no cookie fallback are generally not CSRF-able — note them but classify as Not Vulnerable.
- `SameSite=Lax` does NOT protect state-changing GETs. Flag every GET handler that writes state regardless of SameSite.
- Login CSRF is a real vulnerability — a missing token on `POST /login` is a finding even though there is no session yet.
- GraphQL mutations are POSTs and inherit the same CSRF exposure; additionally check for content-type whitelisting and GET-mutation support.
- Substring or regex Origin checks are a bypass risk — require exact match against an allowlist.
- A framework default (Django/Rails/Spring/ASP.NET) being ON does NOT mean every endpoint is protected — explicit opt-outs (`@csrf_exempt`, `skip_before_action`, `csrf.disable()`, `$except` lists) remove protection per-route.
- Dual cookie/Bearer auth is CSRF-able via the cookie path; Bearer-only is not enough to save it.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete `sast/csrf-recon.md` and all `sast/csrf-batch-*.md` files after the final `sast/csrf-results.md` and `sast/csrf-results.json` are written.
