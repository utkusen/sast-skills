---
name: sast-openredirect
description: >-
  Detect Open Redirect vulnerabilities in a codebase using a three-phase
  approach: recon (find redirect sinks in Location headers, client-side
  window.location, meta-refresh tags, and href attributes), batched verify
  (trace user input to redirect destinations in parallel subagents, 3 sites
  each), and merge (consolidate batch results). Requires sast/architecture.md
  (run sast-analysis first). Outputs findings to sast/openredirect-results.md
  and sast/openredirect-results.json. Use when asked to find open redirect,
  unvalidated redirect, or forwarding bugs.
version: 0.1.0
---

# Open Redirect Detection

You are performing a focused security assessment to find Open Redirect vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find all redirect sinks — server 302/303/307 Location, client-side `window.location` writes, HTML meta-refresh, and `<a href>` attributes built from user input), **batched verify** (trace whether user-supplied input reaches those sinks without effective validation, in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Open Redirect

Open Redirect (also called "Unvalidated Redirects and Forwards") occurs when an attacker can cause the application to redirect a victim's browser to an attacker-controlled destination — because the redirect target is built from user-supplied input (query string, form field, cookie, path parameter, referrer) without validation against an allow-list of permitted destinations.

The core pattern: *unvalidated, user-controlled input reaches the target argument of a browser-side redirect sink (HTTP `Location` header, HTML meta refresh, `window.location`, or `<a href>` used as a redirect).*

Unlike SSRF, the request that follows the redirect is issued by the **victim's browser**, not the server. The impact is therefore delivered through the victim: phishing (landing on a look-alike login page), OAuth/OIDC token theft (stealing `code` or `access_token` from the fragment by swapping the `redirect_uri`), session/credential harvesting, bypass of URL-based security controls (SSO allow-lists, CSP, Safe Browsing warnings, trusted-domain email filters), and as a second-stage gadget for escalating other bugs (CRLF injection, reflected XSS via `javascript:` URLs, OAuth code interception).

Open redirects frequently appear at: login/logout flows with a `next=` / `returnTo=` / `continue=` parameter, post-checkout redirects, password-reset confirmation pages, OAuth/OIDC authorization endpoints, "exit page" link trackers, legacy URL-shortener handlers, and generic redirect middleware.

### What Open Redirect IS

- Server-side redirect where the `Location` header's value comes from user input: `res.redirect(req.query.next)`, `HttpResponseRedirect(request.GET['url'])`, `redirect_to params[:next]`
- Client-side navigation driven by user input: `window.location = new URLSearchParams(location.search).get('redirect')`
- HTML `<meta http-equiv="refresh" content="0; url={{user_input}}">` with user input in the URL
- `<a href="{{user_input}}">` used as a navigation target (click-redirect), especially inside logout/login landing pages
- OAuth/OIDC `redirect_uri` parameter that is not strictly matched against a pre-registered list of allowed URIs
- Framework helpers that accept raw URLs: Flask `redirect(request.args.get('next'))`, Spring `new RedirectView(target)`, Rails `redirect_to(params[:return_to])`
- Protocol-relative URLs accepted as "paths": `/login?next=//evil.com/` — the browser treats `//evil.com` as an absolute URL to `https://evil.com`
- CRLF injection into a redirect target that lets the attacker inject a new `Location:` header or a full response (HTTP Response Splitting)
- `javascript:` / `data:` / `vbscript:` URLs accepted as redirect targets (these execute script in the app's origin when clicked, which is worse than a plain redirect)
- `target="_blank"` links that point to user-supplied URLs without `rel="noopener"` — tabnabbing: the opened page can call `window.opener.location = "https://phish.example"` and replace the original tab

### What Open Redirect is NOT

Do not flag these:

- **SSRF**: A server-side HTTP client fetching a user-supplied URL (`requests.get(user_url)`) — that's SSRF, covered by the `sast-ssrf` skill. Open Redirect is about the *browser* following a redirect, not the server making an outbound request.
- **XSS via URL**: Rendering a user-supplied URL into HTML without escaping — that's reflected XSS, covered by the `sast-xss` skill. (Exception: if the redirect sink itself accepts `javascript:` URLs, flag it as Open Redirect + note the XSS escalation.)
- **CSRF**: Forging a state-changing request on behalf of the user — separate class.
- **Fully hardcoded redirects**: `res.redirect('/dashboard')` — no user influence, not a vulnerability.
- **Redirects to a fixed set of internal paths** derived from an integer ID (e.g., `redirect(DESTINATIONS[int(id)])`) — the attacker does not control the destination URL.

### Patterns That Prevent Open Redirect

When you see these patterns, the code is likely **not vulnerable**:

**1. Allow-list of target hosts (exact match)**
```python
ALLOWED_HOSTS = {"app.example.com", "admin.example.com"}
parsed = urlparse(user_next)
if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
    return redirect("/")
return redirect(user_next)
```

**2. Relative-path-only validation** — reject anything with a scheme or host
```python
# Safe: only allow redirects that are clearly relative to our site
if not user_next.startswith("/") or user_next.startswith("//"):
    user_next = "/"
return redirect(user_next)
```
The `//` check is critical — without it, `//evil.com/path` would be accepted as "relative" by a naive `startswith("/")` check but is actually a protocol-relative URL to `evil.com`.

**3. Framework-native safe-URL helpers**
```python
# Django
from django.utils.http import url_has_allowed_host_and_scheme
if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
    next_url = "/"
```
```python
# Flask / Werkzeug
from urllib.parse import urlparse, urljoin
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc
```

**4. Signed redirect tokens (OAuth `state`, signed `next` parameter)**
```python
# The "next" target is signed server-side; tampering breaks the signature.
signed_next = signer.loads(request.args["next"])  # raises on tamper
return redirect(signed_next)
```

**5. Redirect ID lookup instead of raw URL**
```python
# Attacker supplies an opaque ID; server maps it to a known-safe destination.
target = REDIRECT_TABLE.get(request.args.get("rid"), "/")
return redirect(target)
```

**6. OAuth/OIDC `redirect_uri` exact-match against pre-registered list**
```python
client = lookup_client(client_id)
if request.args["redirect_uri"] not in client.registered_redirect_uris:
    return error("invalid_request")
```

> **Note**: The following are **insufficient** on their own — classify as Likely Vulnerable:
> - `startswith("/")` without a `//` check (bypass: `//evil.com/`)
> - `startswith("https://example.com")` without trailing-slash enforcement (bypass: `https://example.com.evil.com/`)
> - `contains("example.com")` (bypass: `https://evil.com/?x=example.com`)
> - Regex on the URL without anchoring to the host component (easy to bypass with `@` authority trick: `https://example.com@evil.com/`)
> - Blocking only `javascript:` without also blocking `data:`, `vbscript:`, protocol-relative, and CRLF

---

## Vulnerable vs. Secure Examples

### Node.js — Express `res.redirect`

```javascript
// VULNERABLE: redirect target read straight from the query string
app.get('/login', (req, res) => {
  // ...authenticate...
  res.redirect(req.query.next || '/');
});
// Attack: /login?next=https://evil.com/login

// VULNERABLE: protocol-relative bypass — startsWith('/') is not enough
app.get('/logout', (req, res) => {
  let next = req.query.next || '/';
  if (!next.startsWith('/')) next = '/';
  res.redirect(next);
});
// Attack: /logout?next=//evil.com/  → browser navigates to https://evil.com/

// SECURE: only allow same-origin relative paths
app.get('/login', (req, res) => {
  let next = req.query.next || '/';
  if (typeof next !== 'string' || !next.startsWith('/') || next.startsWith('//')) {
    next = '/';
  }
  res.redirect(next);
});
```

### Python — Django `HttpResponseRedirect`

```python
# VULNERABLE: raw user input flows into HttpResponseRedirect
def login_view(request):
    # ...authenticate...
    return HttpResponseRedirect(request.GET.get('next', '/'))

# SECURE: Django's built-in safe-URL helper
from django.utils.http import url_has_allowed_host_and_scheme

def login_view(request):
    next_url = request.GET.get('next', '/')
    if not url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = '/'
    return HttpResponseRedirect(next_url)
```

### Ruby on Rails — `redirect_to`

```ruby
# VULNERABLE: Rails 6 and earlier allowed raw params in redirect_to.
def after_sign_in
  redirect_to params[:return_to]
end
# Attack: /after_sign_in?return_to=https://evil.com

# VULNERABLE: Rails 7+ blocks external hosts by default, but allow_other_host re-opens it
def after_sign_in
  redirect_to params[:return_to], allow_other_host: true
end

# SECURE: allow-list of known paths
ALLOWED_RETURN_PATHS = %w[/ /dashboard /settings].freeze
def after_sign_in
  target = ALLOWED_RETURN_PATHS.include?(params[:return_to]) ? params[:return_to] : '/'
  redirect_to target
end
```

### Python — Flask `redirect`

```python
# VULNERABLE: redirect takes the user's URL directly
@app.route('/go')
def go():
    return redirect(request.args.get('url'))
# Attack: /go?url=https://evil.com

# VULNERABLE: url_for looks safe, but the endpoint name is user-controlled — and
# the fallback path concatenates request.args into a redirect.
@app.route('/go')
def go():
    target = request.args.get('to')
    if target:
        return redirect(target)  # unvalidated
    return redirect(url_for('home'))

# SECURE: is_safe_url check before redirecting
from urllib.parse import urlparse, urljoin
def is_safe_url(target):
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return test.scheme in ('http', 'https') and ref.netloc == test.netloc

@app.route('/go')
def go():
    target = request.args.get('url', '/')
    if not is_safe_url(target):
        target = '/'
    return redirect(target)
```

### Java — Spring `RedirectView` / `sendRedirect`

```java
// VULNERABLE: RedirectView built from request parameter
@GetMapping("/redirect")
public RedirectView redirect(@RequestParam String url) {
    return new RedirectView(url);
}

// VULNERABLE: HttpServletResponse.sendRedirect with user input
@GetMapping("/login-complete")
public void loginComplete(@RequestParam String next, HttpServletResponse resp) throws IOException {
    resp.sendRedirect(next);
}

// SECURE: allow-list of path prefixes on the same host
private static final List<String> ALLOWED = List.of("/dashboard", "/settings", "/home");

@GetMapping("/redirect")
public RedirectView redirect(@RequestParam String url) {
    if (url == null || !url.startsWith("/") || url.startsWith("//")) {
        return new RedirectView("/");
    }
    boolean ok = ALLOWED.stream().anyMatch(url::startsWith);
    return new RedirectView(ok ? url : "/");
}
```

### Client-side JavaScript — `window.location` sink

```javascript
// VULNERABLE: URL fragment / query param assigned directly to window.location
const params = new URLSearchParams(location.search);
window.location = params.get('redirect');
// Attack: https://app.example.com/page?redirect=https://evil.com

// VULNERABLE: document.location and location.href are equivalent sinks
document.location.href = new URL(location).searchParams.get('next');

// VULNERABLE: accepts javascript: URLs — escalates to XSS
function go() {
  location = document.getElementById('target').value;  // attacker can enter javascript:alert(1)
}

// SECURE: parse + allow-list, reject absolute URLs, reject non-http schemes
function safeRedirect(target) {
  try {
    // Resolve against current origin; absolute URLs to other hosts will surface in .origin
    const u = new URL(target, location.origin);
    if (u.origin !== location.origin) return '/';
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return '/';
    return u.pathname + u.search + u.hash;
  } catch {
    return '/';
  }
}
window.location = safeRedirect(params.get('redirect') || '/');
```

### HTML meta refresh tag

```html
<!-- VULNERABLE: server-side template puts user input into meta refresh -->
<meta http-equiv="refresh" content="0; url={{ request.args.get('next') }}">
<!-- Attack: /page?next=https://evil.com -->

<!-- VULNERABLE: same issue, JSP/ERB/Razor flavors -->
<meta http-equiv="refresh" content="0; url=<%= params[:next] %>">

<!-- SECURE: emit a fixed refresh target, OR omit meta-refresh and use a signed
     server-side redirect with validation. -->
<meta http-equiv="refresh" content="2; url=/dashboard">
```

### `<a href>` used as a redirect target

```html
<!-- VULNERABLE: user-supplied URL in href with no validation -->
<a href="{{ user_url }}">Continue</a>
<!-- If user_url is attacker-controlled, they can supply:
       - https://evil.com/login       (phishing)
       - javascript:alert(document.cookie)   (XSS in app origin)
       - data:text/html;base64,...    (origin-less scripting)
-->

<!-- VULNERABLE: target="_blank" without rel="noopener" — tabnabbing
     The opened page can do: window.opener.location = "https://phish.example"
     and replace the user's original tab while they are on the attacker page. -->
<a href="{{ user_url }}" target="_blank">View</a>

<!-- SECURE: validated URL + rel attributes that block opener access -->
<a href="{{ safe_url(user_url) }}" target="_blank" rel="noopener noreferrer">View</a>
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Redirect Sinks

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where the application issues a browser redirect or navigates the browser to a URL — HTTP `Location` header, HTML meta refresh, client-side `window.location` / `document.location` / `location.href` writes, and `<a href>` attributes whose value is dynamic — regardless of whether that destination is currently user-controlled. Write results to `sast/openredirect-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, web frameworks in use, templating engine, and authentication flows (login/logout/password-reset/OAuth).
>
> **What to search for — redirect sinks**:
>
> You are looking for any code that causes the browser to navigate to a URL. Flag ANY call where the destination is a non-trivially-hardcoded string (a variable, expression, concatenation, template interpolation, or query/body/header field). You are not yet tracing whether that value is user-controlled; that is Phase 2's job.
>
> 1. **Node.js / Express server redirects**:
>    - `res.redirect(url)`, `res.redirect(status, url)`, `res.location(url)`
>    - `response.writeHead(302, { Location: url })`, `response.setHeader('Location', url)`
>    - Koa: `ctx.redirect(url)`, `ctx.response.redirect(url)`
>    - Fastify: `reply.redirect(url)`, `reply.header('Location', url)`
>    - NestJS: `@Redirect(url)`, `res.redirect(url)`
>    - Next.js: `res.redirect(url)`, `NextResponse.redirect(url)`, `{ redirect: { destination: url } }` in `getServerSideProps`
>
> 2. **Python server redirects**:
>    - Django: `redirect(url)`, `HttpResponseRedirect(url)`, `HttpResponsePermanentRedirect(url)`
>    - Flask: `redirect(url)`, `flask.redirect(url)`, `make_response(..., 302, {'Location': url})`
>    - FastAPI / Starlette: `RedirectResponse(url)`, `Response(..., status_code=302, headers={'Location': url})`
>    - Pyramid: `HTTPFound(location=url)`, `HTTPSeeOther(location=url)`
>    - Tornado: `self.redirect(url)`
>
> 3. **Ruby / Rails redirects**:
>    - `redirect_to url`, `redirect_to(url, allow_other_host: true)`
>    - `head :found, location: url`, `response.headers['Location'] = url`
>    - Sinatra: `redirect url`, `redirect to(url)`
>
> 4. **Java / JVM redirects**:
>    - `response.sendRedirect(url)`
>    - `new RedirectView(url)`, `return "redirect:" + url`
>    - `ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build()`
>    - `HttpServletResponse.setHeader("Location", url)`
>    - Play Framework: `Redirect(url)`, `Results.Redirect(url)`
>
> 5. **PHP redirects**:
>    - `header("Location: $url")`, `header('Location: ' . $url)`
>    - Laravel: `redirect($url)`, `redirect()->to($url)`, `Redirect::to($url)`, `return back($url)`
>    - Symfony: `new RedirectResponse($url)`, `$this->redirect($url)`, `$this->redirectToRoute(...)` with dynamic route params
>
> 6. **Go redirects**:
>    - `http.Redirect(w, r, url, http.StatusFound)`
>    - `w.Header().Set("Location", url)` + explicit status
>    - Gin: `c.Redirect(http.StatusFound, url)`
>    - Echo: `c.Redirect(http.StatusFound, url)`
>
> 7. **C# / .NET redirects**:
>    - `Response.Redirect(url)`, `Response.RedirectPermanent(url)`
>    - `return Redirect(url)`, `return LocalRedirect(url)` (note: `LocalRedirect` is the safe variant — still record it but note it in the sink description)
>    - `return new RedirectResult(url)`, `return new RedirectToRouteResult(...)` with dynamic values
>    - Razor Pages: `return RedirectToPage(...)` with dynamic target
>
> 8. **Client-side JavaScript navigation sinks**:
>    - `window.location = expr`, `window.location.href = expr`, `window.location.assign(expr)`, `window.location.replace(expr)`
>    - `document.location = expr`, `document.location.href = expr`
>    - `location = expr`, `location.href = expr`, `location.assign(expr)`, `location.replace(expr)`
>    - `window.open(expr, ...)` when the opened URL may be user-controlled
>    - React Router: `navigate(expr)`, `<Navigate to={expr} />`, `history.push(expr)`, `history.replace(expr)`
>    - Next.js client: `router.push(expr)`, `router.replace(expr)`
>    - Vue Router: `this.$router.push(expr)`, `router.replace(expr)`
>
> 9. **HTML meta-refresh in templates**:
>    - `<meta http-equiv="refresh" content="...; url={{ ... }}">` — any server-side template (Jinja, ERB, Blade, Twig, Thymeleaf, Razor, JSP, EJS, Handlebars, Mustache, Pug)
>    - Any string that assembles `<meta http-equiv="refresh" ... url=...>` dynamically in code
>
> 10. **`<a href>` built from dynamic values** — include when the href expression is non-literal and looks like it could be a redirect (e.g., on a logout landing page, confirmation page, or link-tracker / "exit" page):
>     - `<a href="{{ user_url }}">`, `<a href=${userUrl}>`, `<a :href="userUrl">` (Vue), `<a href={props.url}>` (React)
>     - Also flag `target="_blank"` without `rel="noopener"` on any dynamic href — tabnabbing risk
>
> 11. **OAuth / OIDC `redirect_uri` handling** — find code that reads the `redirect_uri` parameter from an authorization request and uses it as the target of a post-auth redirect. This is a redirect sink that also needs Phase 2 to confirm whether exact-match validation against the pre-registered list is performed.
>
> 12. **Response header writes that set `Location`** — any code that builds a `Location:` header from a variable (already partially covered above, but also check generic response-header-write helpers in custom middleware).
>
> 13. **Custom redirect middleware / utilities** — project-specific helpers named `redirectTo`, `safeRedirect`, `doRedirect`, `forward`, `continue_to`, etc. Record the helper and who calls it; Phase 2 will trace whether validation inside the helper is effective.
>
> **What to skip** (these are safe — do not flag):
> - Redirects to a fully hardcoded string with no dynamic parts: `res.redirect('/dashboard')`, `redirect('/login')`
> - `LocalRedirect` in ASP.NET Core where the argument is clearly a hardcoded string — record other uses since the safety depends on framework-version behavior with dynamic input
> - Redirects where the destination is a URL built purely from server-side config / env vars with no user influence
> - Route changes triggered by form submission to a static action URL (i.e., the URL in the `action` attribute is hardcoded)
>
> **Output format** — write to `sast/openredirect-recon.md`:
>
> ```markdown
> # Open Redirect Recon: [Project Name]
>
> ## Summary
> Found [N] redirect sinks.
>
> ## Redirect Sinks
>
> ### 1. [Descriptive name — e.g., "Post-login redirect in /login handler"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Sink type**: [server Location header (Express res.redirect) / client window.location / meta refresh / <a href> / OAuth redirect_uri]
> - **Framework / API**: [res.redirect / HttpResponseRedirect / sendRedirect / window.location.href / etc.]
> - **Destination argument**: `var_name` or `url_expression` — [brief note, e.g., "from req.query.next" or "concatenation of base + user path"]
> - **Flow context**: [e.g., "login success", "logout landing", "password-reset confirm", "OAuth authorize callback", "exit-link tracker"]
> - **Code snippet**:
>   ```
>   [the redirect call and the lines immediately before it that construct the destination]
>   ```
>
> [Repeat for each sink]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/openredirect-recon.md`. If the recon found **zero redirect sinks** (the summary reports "Found 0" or the "Redirect Sinks" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/openredirect-results.md` and `sast/openredirect-results.json`, then stop:

```markdown
# Open Redirect Analysis Results

No vulnerabilities found.
```

```json
{ "findings": [] }
```

Only proceed to Phase 2 if Phase 1 found at least one redirect sink.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/openredirect-recon.md` and split the redirect sinks into **batches of up to 3 sinks each**. Launch **one subagent per batch in parallel**. Each subagent traces taint only for its assigned sinks and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/openredirect-recon.md` and count the numbered site sections (### 1., ### 2., etc.) under "Redirect Sinks".
2. Divide them into batches of up to 3. For example, 8 sinks → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those sink sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sinks.
5. Each subagent writes to `sast/openredirect-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Django, include only the "Python — Django" example plus the "Client-side JavaScript" and meta-refresh examples if the project also has frontend templates. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned redirect sink, determine whether a user-supplied value controls or influences the redirect destination without effective allow-list validation. Write results to `sast/openredirect-batch-[N].md`.
>
> **Your assigned redirect sinks** (from the recon phase):
>
> [Paste the full text of the assigned sink sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand entry points, middleware, authentication flows, and how user input reaches handlers.
>
> **Open Redirect reference — what to look for**:
>
> Open Redirect occurs when user-controlled input reaches the destination argument of a browser redirect sink without being validated against an allow-list of permitted destinations.
>
> **What Open Redirect is NOT** — do not flag these as Open Redirect:
> - **SSRF**: A server-side HTTP client fetching a user URL — covered by sast-ssrf.
> - **Reflected XSS in a URL**: User URL rendered into HTML — covered by sast-xss. (Exception: if the redirect sink accepts `javascript:` URLs, flag it here and note the XSS escalation.)
> - **CSRF**: Forged state-changing request — separate class.
> - **Fully hardcoded redirects** with no user influence — not Open Redirect.
>
> **For each sink, trace the destination argument backwards to its origin**:
>
> 1. **Direct user input** — destination assigned straight from a request source with no transformation:
>    - Query params: `req.query.next`, `request.GET.get('url')`, `params[:return_to]`, `$_GET['redirect']`, `c.Query("to")`
>    - Request body / form fields: `req.body.redirect_url`, `request.form['next']`, `params[:target]`
>    - Path parameters: `req.params.dest`, `params[:slug]` used as a URL
>    - Cookies / headers: `req.cookies.next`, `request.headers['Referer']` used as the redirect target, `X-Forwarded-Host`-derived values
>    - HTML form `hidden` fields that echo back user input
>
> 2. **Indirect / assembled destination** — the URL is built by concatenating a hardcoded prefix with a user-supplied suffix, path, or query:
>    - `"https://app.example.com" + user_path` — bypassable via `@` trick (`@evil.com`) or backslash on some parsers
>    - `base_url + "?" + user_query` — usually safe for host bypass, but check for `javascript:` injection or CRLF
>    - Flag these as Likely Vulnerable and identify the user-controlled portion.
>
> 3. **User input round-tripped through storage** — the destination was saved earlier (e.g., a stored "next URL" in the session after a registration attempt) and is now read back into the redirect:
>    - Trace where the stored value was written — was it validated at write time?
>    - Was there any validation at read time?
>
> 4. **Server-side / hardcoded value** — destination comes from config, enum lookup, signed token, or pre-registered list — NOT exploitable.
>
> **For each sink, also check for mitigations**:
> - **Strict same-origin / path-only check** (`startsWith("/")` AND NOT `startsWith("//")`, OR framework helper like Django's `url_has_allowed_host_and_scheme`, OR Flask `is_safe_url`): effective. Mark Not Vulnerable.
> - **Exact host allow-list** on parsed URL's netloc against a fixed set: effective. Mark Not Vulnerable.
> - **`startsWith("/")` only, without the `//` check**: bypassable with `//evil.com/`. Likely Vulnerable.
> - **`startsWith("https://example.com")` without a trailing slash**: bypassable with `https://example.com.evil.com/`. Likely Vulnerable.
> - **`contains("example.com")`**: bypassable trivially. Likely Vulnerable.
> - **Blocking only `javascript:`**: does not stop external-host phishing, `data:`, `vbscript:`, or protocol-relative. Likely Vulnerable.
> - **Signed redirect tokens** (HMAC, itsdangerous, JWT-wrapped): effective. Mark Not Vulnerable.
> - **Redirect ID → lookup**: effective. Mark Not Vulnerable.
>
> **Special cases to check**:
>
> - **OAuth/OIDC `redirect_uri`**: if the sink is an OAuth authorize/callback, the only safe validation is **exact string match** against a pre-registered list for the `client_id`. Flag as Likely Vulnerable if the match is prefix-based, wildcard-based, or uses `startsWith`/`contains`. Flag as Vulnerable if there is no allow-list at all. Successful exploitation can steal `code` / `access_token` / `id_token` values from the authorization response.
> - **Protocol-relative URL `//evil.com`**: if the check is `startsWith("/")` without also rejecting `startsWith("//")`, flag Likely Vulnerable and include `//attacker.example` as the dynamic test payload.
> - **CRLF injection into the Location header**: if the redirect target is passed into a framework that does not encode CR/LF and the input can include `%0d%0a` or raw `\r\n`, the attacker can inject additional response headers or a full fake response (HTTP Response Splitting). Flag Vulnerable if the underlying framework/server is known to allow this (older PHP, older Node versions, raw `Transfer-Encoding: chunked` response paths), and Needs Manual Review otherwise.
> - **`javascript:` / `data:` / `vbscript:` URL schemes**: if the redirect sink is a client-side `window.location` write, or a server-side redirect that a browser will follow without scheme filtering, supplying a `javascript:` URL results in script execution in the app's origin — worse than a plain redirect. Flag Vulnerable and note the XSS escalation.
> - **Login / logout / password-reset flows with `next=`** (or `returnTo`, `continue`, `redirect`, `callback`, `service`, `target`, `dest`, `url`): these are the canonical high-impact locations for Open Redirect because users have just completed an authentication action and are primed to accept the destination as trusted. Prioritize these in the Findings ordering.
> - **`target="_blank"` + missing `rel="noopener"`**: if the `<a>` has both `target="_blank"` AND a dynamic `href` AND no `rel="noopener"` (or `rel="noreferrer"`), flag Likely Vulnerable for **tabnabbing**: the opened page can overwrite `window.opener.location`, silently replacing the original tab with a phishing page while the user is on the attacker's site.
>
> **Vulnerable vs. secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the redirect destination with no validation, or with only blocklist-style protection (e.g., blocking `javascript:` while still allowing arbitrary external hosts).
> - **Likely Vulnerable**: User input probably reaches the destination, OR validation exists but is bypassable (protocol-relative, prefix-without-trailing-slash, contains-check, prefix-match-based OAuth `redirect_uri`, missing `rel="noopener"` tabnabbing, etc.).
> - **Not Vulnerable**: Destination is fully server-side, OR a strict same-origin / exact-host allow-list / signed token / ID-lookup is enforced.
> - **Needs Manual Review**: Cannot determine the destination's origin (opaque helpers, complex conditional flows, CRLF behavior dependent on server version).
>
> **Output format** — write to `sast/openredirect-batch-[N].md`:
>
> ```markdown
> # Open Redirect Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Flow context**: [login / logout / password-reset / OAuth / exit link / generic]
> - **Issue**: [e.g., "Query param `next` flows directly into res.redirect()"]
> - **Taint trace**: [Step-by-step from entry point to the sink — e.g., "req.query.next → nextUrl → res.redirect(nextUrl)"]
> - **Impact**: [e.g., "Phishing: attacker can send https://app.example.com/login?next=https://evil.com/fake-login and harvest credentials once the user submits the login form. OAuth code theft if used in an authorize callback."]
> - **Mitigation present**: [None / startsWith('/') only / blocks javascript: only / etc. — explain why it's insufficient]
> - **Remediation**: [Allow-list hosts, or use framework safe-URL helper, or only accept relative paths + reject `//`]
> - **Dynamic Test**:
>   ```
>   [curl / browser URL to confirm the finding.
>    Example: curl -I "https://app.example.com/login?next=https://evil.com"
>    Look for: Location: https://evil.com
>    For tabnabbing, open the rendered page and check window.opener access.]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Flow context**: [login / logout / etc.]
> - **Issue**: [e.g., "startsWith('/') check without rejecting protocol-relative URLs"]
> - **Taint trace**: [Best-effort trace with the uncertain step identified]
> - **Concern**: [Why it's still a risk — e.g., "`//evil.com/path` bypasses the `startsWith('/')` check"]
> - **Remediation**: [Reject `//` prefix, use framework safe-URL helper]
> - **Dynamic Test**:
>   ```
>   [payload to attempt — e.g., /login?next=//evil.com/]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "URL is fully hardcoded" or "url_has_allowed_host_and_scheme enforces same-origin"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the destination's origin / validation could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Inspect `safeRedirect()` helper in utils/redirect.js; confirm whether the regex anchors on the host"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/openredirect-batch-*.md` file and merge them into a single `sast/openredirect-results.md`, plus a canonical `sast/openredirect-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/openredirect-batch-1.md`, `sast/openredirect-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (total sinks analyzed equals the number from recon / sum of assigned sinks).
4. Write the merged human-readable report to `sast/openredirect-results.md` using this format:

```markdown
# Open Redirect Analysis Results: [Project Name]

## Executive Summary
- Redirect sinks analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Within each group, order by flow context (login/logout/password-reset/OAuth first, then generic).
 Preserve every field from the batch results exactly as written.]
```

5. Also write the canonical machine-readable view to `sast/openredirect-results.json`:

```json
{
  "findings": [
    {
      "id": "openredirect-1",
      "skill": "sast-openredirect",
      "severity": "high",
      "title": "Unvalidated redirect in /login via next parameter",
      "description": "The `next` query parameter flows unvalidated into res.redirect(), allowing an attacker to redirect post-login users to an attacker-controlled host for phishing.",
      "location": { "file": "src/routes/auth.js", "line": 42, "column": 5 },
      "remediation": "Validate `next` as a same-origin path: reject any value not starting with '/' or starting with '//'. Alternatively, use an allow-list of known paths."
    }
  ]
}
```

Severity mapping:
- **critical**: OAuth `redirect_uri` with no allow-list / prefix-only match (token theft), or any sink that also accepts `javascript:` URLs in a high-trust page.
- **high**: Login / logout / password-reset redirect with no validation or bypassable validation (phishing + credential harvesting).
- **medium**: Generic unvalidated redirect outside auth flows; tabnabbing on dynamic `<a target="_blank">` without `rel="noopener"`.
- **low**: Validation exists but has a minor bypass (e.g., trailing-slash confusion) with limited impact.
- **info**: Needs-manual-review entries where a real finding cannot yet be confirmed.

If there are no findings at all, still write `{"findings": []}` so the aggregator can confirm the scan ran.

6. After writing both `sast/openredirect-results.md` and `sast/openredirect-results.json`, **delete all intermediate batch files** (`sast/openredirect-batch-*.md`) and the recon file (`sast/openredirect-recon.md`).

---

## Findings

The final merged report lives in two files:

- `sast/openredirect-results.md` — human-readable, grouped by classification and flow context, with taint traces, impact, remediation, and a dynamic test payload for each finding.
- `sast/openredirect-results.json` — machine-readable canonical view consumed by `sast-skills export` to build SARIF / HTML / JSON aggregate reports alongside other SAST skill outputs.

Each finding in the `.md` file follows the template below (copy exactly when synthesizing):

```markdown
### [VULNERABLE] Short descriptive title
- **File**: `path/to/file.ext` (lines X-Y)
- **Endpoint / function**: [route or function name]
- **Flow context**: [login / logout / password-reset / OAuth / exit link / generic]
- **Issue**: [one-sentence summary of what is wrong]
- **Taint trace**: [source → intermediate assignments → sink]
- **Impact**: [phishing / OAuth token theft / credential harvesting / tabnabbing / XSS escalation via javascript: / response splitting]
- **Mitigation present**: [None / bypassable check — explain why]
- **Remediation**: [concrete fix — same-origin check, allow-list, signed token, ID lookup]
- **Dynamic Test**:
  ```
  [payload that demonstrates the issue — e.g., curl -I "https://.../login?next=//evil.com/"
   and what to look for in the response]
  ```
```

The JSON `findings` array uses the canonical schema defined in the project CLAUDE.md (`id`, `skill`, `severity`, `title`, `description`, `location {file,line,column}`, `remediation`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 redirect sinks per subagent**. If there are 1-3 sinks total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sinks' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any sink where the destination is dynamic (variable, expression, assembled string, template interpolation). Do not attempt taint analysis in Phase 1.
- **Phase 2 is purely taint analysis + mitigation review**: trace each sink's destination back to its origin and evaluate any validation against the bypass classes listed above.
- **Do not confuse with SSRF**: the server making an outbound HTTP request with a user URL is SSRF; the server returning a 302 that the *browser* follows to a user URL is Open Redirect. If the same value is used for both, file both findings (one in `ssrf-results.md`, one here).
- **Protocol-relative URLs** (`//evil.com`) are one of the most common bypasses — explicitly test for them.
- **OAuth `redirect_uri`** requires *exact* string match, not prefix or wildcard. Prefix-match OAuth flows are the classic "authorization code theft" gadget.
- **Login / logout / password-reset** paths are high-impact — flag aggressively and rank these first in the final report.
- **`target="_blank"` tabnabbing** is a real, routinely-exploited finding even though the formal redirect itself is static — classify it as Likely Vulnerable (Medium severity) when the `href` is dynamic and `rel="noopener"` is missing.
- **`javascript:` and `data:` URLs** in redirect sinks escalate the impact from "redirect" to "XSS in app origin" — flag Vulnerable and note the escalation in the Impact field.
- **CRLF in Location headers** can split the response and inject a fake page or new headers — include in Phase 2 checks when the target argument can contain raw bytes and the underlying framework does not strip them.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete `sast/openredirect-recon.md` and all `sast/openredirect-batch-*.md` files after the final `sast/openredirect-results.md` and `sast/openredirect-results.json` are written.
