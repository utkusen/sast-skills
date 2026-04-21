---
name: sast-jwt
description: >-
  Detect insecure JWT (JSON Web Token) implementations in a codebase using a
  two-phase approach: first map all JWT issuance and verification sites to
  understand the token lifecycle and signing configuration, then check each
  verification site for exploitable weaknesses such as algorithm confusion,
  missing signature verification, weak secrets, header injection, and missing
  claim validation. Requires sast/architecture.md (run sast-analysis first).
  Outputs findings to sast/jwt-results.md. If no JWT usage is found in Phase 1,
  Phase 2 is skipped. Use when asked to find JWT, token forgery, or
  authentication bypass bugs.
version: 0.1.0
---

# JWT Vulnerability Detection

You are performing a focused security assessment to find insecure JSON Web Token (JWT) implementations. This skill uses a two-phase approach with subagents: **recon** (map the full JWT lifecycle — issuance, verification, and configuration) then **analysis** (identify every exploitable weakness in those verification sites).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is an Insecure JWT Implementation

JWTs consist of three Base64URL-encoded parts: `header.payload.signature`. The header declares the signing algorithm (`alg`), the payload carries claims (e.g., `sub`, `role`, `exp`), and the signature is a cryptographic proof of integrity. Vulnerabilities arise when the server trusts the token's own claims about how it was signed, fails to verify the signature at all, uses a guessable secret, or trusts attacker-controlled key material embedded in the token itself.

The core pattern: *the server does not fully verify the JWT's authenticity and integrity before trusting its claims.*

### What JWT Vulnerabilities ARE

**1. Algorithm confusion — `alg: none`**
The server accepts a JWT whose header declares `"alg": "none"`, bypassing signature verification entirely. An attacker crafts an arbitrary payload, sets `alg` to `none`, and omits the signature. If the library processes it, the forged token is accepted.

**2. Algorithm confusion — RS256 → HS256**
A server configured for RS256 (asymmetric: sign with private key, verify with public key) can be tricked into HS256 mode if the library allows the algorithm to be specified by the token. Since the public key is often retrievable, the attacker signs a forged token with HS256 using the server's public key as the HMAC secret. The server verifies the HMAC using the same public key and accepts the token.

**3. Missing or disabled signature verification**
The server decodes the JWT payload without actually verifying the signature. Common patterns:
- Python (PyJWT): `jwt.decode(token, options={"verify_signature": False})`
- Node.js (jsonwebtoken): `jwt.decode(token)` instead of `jwt.verify(token, secret)`
- Manual base64 decode of the payload with no signature check
- `algorithms=["none"]` accepted in the decode call

**4. Weak or hardcoded HMAC secret**
The server signs tokens with a short, guessable, or hardcoded secret (e.g., `"secret"`, `"password"`, `"changeme"`, `"jwt-secret-key"`). An attacker who captures a valid token can brute-force the secret offline with tools like `hashcat` or `jwt_tool`, then forge arbitrary tokens.

**5. Embedded JWK (`jwk` header injection)**
The token header contains an embedded JSON Web Key (`jwk` parameter). If the verification code trusts the embedded key to verify the token's own signature, an attacker generates their own key pair, signs a forged token with their private key, and embeds their public key in the header. The server verifies the signature using the attacker's embedded public key and accepts the token.

**6. JKU / X5U header injection**
The `jku` (JWK Set URL) or `x5u` (X.509 certificate URL) header value is used to fetch the verification key from a URL. If the server does not validate the URL against an allowlist, the attacker can point it to their own server hosting a crafted key set.

**7. Key ID (`kid`) header injection**
The `kid` header is used to look up the signing key, often from a database or the filesystem. If the `kid` value is interpolated into a SQL query without sanitization, it becomes an SQL injection vector. If it is concatenated into a file path, it becomes a path traversal vector.

**8. Missing claim validation**
- `exp` not checked → expired tokens remain valid forever
- `iss` (issuer) not checked → tokens issued by other services are accepted
- `aud` (audience) not checked → tokens intended for other services are accepted
- `nbf` (not-before) not checked → tokens used before their valid window

**9. No token revocation**
There is no token blacklist or revocation mechanism. Stolen or logged-out tokens remain valid until they expire. This matters most when token lifetimes are long.

### What JWT Vulnerabilities are NOT

Do not flag these as JWT vulnerabilities:

- **IDOR**: Changing a `user_id` claim to access another user's data is an authorization flaw, not a JWT forgery — only flag if the token itself can be forged
- **XSS via JWT payload**: Injecting `<script>` into a claim that is later rendered unescaped — that's XSS, not a JWT bug
- **CSRF**: JWT in cookies without `SameSite` — that's a CSRF concern, not a JWT integrity issue
- **Properly restricted verification**: `jwt.verify(token, secret, { algorithms: ['HS256'] })` with a strong secret — not vulnerable

### Patterns That Prevent JWT Vulnerabilities

**1. Algorithm allowlist in verification call**
```python
# Python — PyJWT: explicitly specify allowed algorithms
payload = jwt.decode(token, secret, algorithms=["HS256"])

# Node.js — jsonwebtoken: restrict algorithms
jwt.verify(token, secret, { algorithms: ['HS256'] })

# Java — jjwt: specify expected algorithm
Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)
# (jjwt does not use the header's alg; it uses the key type)
```

**2. Strong, randomly generated secret**
```python
# Strong secret: at least 256 bits of entropy, not hardcoded
import secrets
SECRET_KEY = secrets.token_hex(32)  # load from env in production
```

**3. Full claim validation**
```python
payload = jwt.decode(
    token, secret, algorithms=["HS256"],
    options={"require": ["exp", "iss", "aud"]},
    issuer="https://myapp.example.com",
    audience="myapp-api"
)
```

**4. Asymmetric keys with no algorithm ambiguity**
```javascript
// Use RS256 with public key for verification; never accept HS256 on the same endpoint
jwt.verify(token, publicKey, { algorithms: ['RS256'] })
```

**5. JWK/JKU URL allowlist**
```python
# Only fetch keys from a known, trusted JWKS endpoint
ALLOWED_JWKS_URLS = {"https://accounts.google.com/.well-known/jwks.json"}
if jku not in ALLOWED_JWKS_URLS:
    raise ValueError("Untrusted JWK URL")
```

---

## Vulnerable vs. Secure Examples

### Python — PyJWT

```python
# VULNERABLE: signature verification disabled
def get_current_user(token: str):
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload["user_id"]

# VULNERABLE: accepts alg:none because no algorithm restriction
def get_current_user(token: str):
    payload = jwt.decode(token, SECRET_KEY)  # PyJWT < 2.x default: accepts any alg
    return payload["user_id"]

# VULNERABLE: weak hardcoded secret
SECRET_KEY = "secret"
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

# SECURE: algorithm restricted, strong secret from env
SECRET_KEY = os.environ["JWT_SECRET"]  # strong, random, from environment
def get_current_user(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    return payload["user_id"]
```

### Node.js — jsonwebtoken

```javascript
// VULNERABLE: jwt.decode() — no signature verification
function getUser(token) {
  const payload = jwt.decode(token);  // decode only, never verify
  return payload.userId;
}

// VULNERABLE: algorithms not restricted — susceptible to alg:none or RS256→HS256
function getUser(token) {
  const payload = jwt.verify(token, SECRET);  // no algorithms option
  return payload.userId;
}

// VULNERABLE: weak hardcoded secret
const SECRET = "password123";
jwt.verify(token, SECRET, { algorithms: ['HS256'] });

// SECURE: algorithm restricted, strong secret from env
const SECRET = process.env.JWT_SECRET;
function getUser(token) {
  const payload = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
  return payload.userId;
}
```

### Java — jjwt

```java
// VULNERABLE: deprecated parser (accepts alg from header)
Jwts.parser().setSigningKey(key).parseClaimsJws(token);

// VULNERABLE: no expiry check — the library default may not enforce exp
Claims claims = Jwts.parserBuilder()
    .setSigningKey(key).build()
    .parseClaimsJws(token).getBody();
// claims.getExpiration() never checked

// SECURE: parserBuilder (does not trust header alg; uses key type)
Claims claims = Jwts.parserBuilder()
    .requireIssuer("myapp")
    .requireAudience("myapp-api")
    .setSigningKey(key)
    .build()
    .parseClaimsJws(token)
    .getBody();
```

### Go — golang-jwt / dgrijalva/jwt-go

```go
// VULNERABLE: accepts any algorithm including "none"
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return []byte(secret), nil  // no algorithm check
})

// VULNERABLE: weak secret
var jwtKey = []byte("secret")

// SECURE: validate signing method before returning key
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return jwtKey, nil
})
```

### kid header SQL injection

```python
# VULNERABLE: kid used in SQL query without sanitization
def get_signing_key(kid):
    result = db.execute(f"SELECT key FROM jwt_keys WHERE id = '{kid}'")
    return result.fetchone()[0]

token_header = jwt.get_unverified_header(token)
key = get_signing_key(token_header["kid"])  # attacker controls kid
jwt.decode(token, key, algorithms=["HS256"])

# SECURE: kid validated against allowlist or parameterized lookup
def get_signing_key(kid):
    result = db.execute("SELECT key FROM jwt_keys WHERE id = %s", (kid,))
    row = result.fetchone()
    if not row:
        raise ValueError("Unknown key id")
    return row[0]
```

### Embedded JWK injection

```javascript
// VULNERABLE: trusts the jwk embedded in the token header
const { publicKey } = getPublicKeyFromHeader(decoded.header);  // attacker-supplied
jwt.verify(token, publicKey);

// SECURE: only use keys from a pre-configured, trusted source
const trustedKey = loadKeyFromConfig();
jwt.verify(token, trustedKey, { algorithms: ['RS256'] });
```

---

## Execution

This skill runs in two phases using subagents. Pass the contents of `sast/architecture.md` to both subagents as context.

### Phase 1: Map the JWT Lifecycle

Launch a subagent with the following instructions:

> **Goal**: Map how the application creates, transmits, and verifies JWTs. Identify every JWT issuance and verification site, the library used, the signing algorithm and key/secret configuration, and the claims that are used for authorization. Write results to `sast/jwt-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, authentication layer, and middleware patterns.
>
> **What to search for**:
>
> **1. JWT library imports** — identify which JWT library is in use:
> - Python: `import jwt`, `from jose import`, `from authlib import`, `import python_jose`
> - Node.js: `require('jsonwebtoken')`, `import jwt from 'jsonwebtoken'`, `jose`, `@nestjs/jwt`
> - Java: `io.jsonwebtoken`, `com.auth0.jwt`, `nimbus-jose-jwt`
> - Go: `github.com/golang-jwt/jwt`, `github.com/dgrijalva/jwt-go`, `github.com/lestrrat-go/jwx`
> - Ruby: `jwt` gem (`require 'jwt'`)
> - PHP: `firebase/php-jwt`, `lcobucci/jwt`
> - C#: `System.IdentityModel.Tokens.Jwt`, `Microsoft.AspNetCore.Authentication.JwtBearer`
>
> **2. JWT signing / issuance sites** — where tokens are created:
> - `jwt.encode(...)`, `jwt.sign(...)`, `Jwts.builder().signWith(...)`, `JWT.create().sign(...)`
> - Note the algorithm used (`HS256`, `RS256`, etc.) and where the secret/key comes from (env var, config, hardcoded)
>
> **3. JWT verification / decoding sites** — where tokens are consumed:
> - `jwt.decode(...)`, `jwt.verify(...)`, `Jwts.parserBuilder()...parseClaimsJws(...)`, `JWT::decode(...)`
> - Note what options are passed: `algorithms`, `options`, `verify_signature`, `verify_exp`
> - Note if it's a raw `decode` (no verification) vs. a `verify` call
>
> **4. Token extraction** — where the token is read from the incoming request:
> - Authorization header: `request.headers.get("Authorization")`, `req.headers['authorization']`
> - Cookie: `request.cookies.get("token")`, `req.cookies.token`
> - Query parameter: `request.args.get("token")`, `req.query.token`
>
> **5. Authorization middleware / decorators** — centralized JWT checks:
> - `@jwt_required`, `@login_required`, `requireAuth`, `JwtAuthGuard`, `[Authorize]`, middleware functions
> - Note which routes are protected and which are unprotected
>
> **6. Signing secret / key configuration**:
> - Where the HMAC secret or RSA/EC key is defined and loaded (env var, config file, hardcoded string)
> - Whether it looks strong (long random string) or weak (short, common word)
>
> **7. Claim usage**:
> - Which claims are extracted and used for authorization (`user_id`, `role`, `permissions`, `sub`)
> - Whether `exp`, `iss`, `aud`, `nbf` are checked
>
> **Output format** — write to `sast/jwt-recon.md`:
>
> ```markdown
> # JWT Recon: [Project Name]
>
> ## Summary
> JWT is [used / not used] in this codebase.
> Library: [library name and version if visible]
> Algorithm(s): [HS256 / RS256 / etc.]
>
> ## Issuance Sites
>
> ### 1. [Descriptive name — e.g., "Token generation in login endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Algorithm**: [e.g., HS256]
> - **Secret/key source**: [env var name / hardcoded string / config key]
> - **Claims set**: [list of claims added to the payload]
> - **Code snippet**:
>   ```
>   [the signing call]
>   ```
>
> ## Verification Sites
>
> ### 1. [Descriptive name — e.g., "Token verification in auth middleware"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / middleware**: [function name]
> - **Verification call**: [jwt.decode / jwt.verify / parseClaimsJws / etc.]
> - **Algorithm restriction**: [algorithms=["HS256"] / no restriction / unknown]
> - **Signature verification**: [enabled / disabled / unclear]
> - **Claims validated**: [exp / iss / aud / none / unknown]
> - **Token source**: [Authorization header / cookie / query param]
> - **kid/jwk/jku used**: [yes — describe how / no]
> - **Code snippet**:
>   ```
>   [the verification call and surrounding context]
>   ```
>
> ## Secret / Key Configuration
> - **Secret source**: [env var / hardcoded / config file]
> - **Apparent strength**: [strong (long random) / weak (short/common) / unknown]
> - **Code snippet** (if hardcoded or suspicious):
>   ```
>   [relevant code]
>   ```
>
> ## Authorization Middleware Coverage
> - **Protected routes**: [list or description]
> - **Unprotected routes**: [list or "none observed"]
> ```

### After Phase 1: Check for JWT Usage Before Proceeding

After Phase 1 completes, read `sast/jwt-recon.md`. If the summary states JWT is **not used** (no issuance or verification sites were found), **skip Phase 2 entirely**. Instead, write the following content to `sast/jwt-results.md` and stop:

```markdown
# JWT Analysis Results

No JWT usage detected in this codebase.
```

Only proceed to Phase 2 if Phase 1 found at least one JWT verification site.

### Phase 2: Analyze JWT Verification Sites for Vulnerabilities

Launch a second subagent **after Phase 1 completes** with the following instructions:

> **Goal**: For each JWT verification site in `sast/jwt-recon.md`, determine whether it is exploitable. Check for algorithm confusion, missing signature verification, weak secrets, header injection attacks, and missing claim validation. Write final results to `sast/jwt-results.md`.
>
> **Context**: You will be given the project's architecture summary and the Phase 1 recon output. Use both to understand the full token lifecycle before analyzing each site.
>
> **For each verification site, check the following**:
>
> **Check 1 — Algorithm restriction**
> - Is the allowed algorithm explicitly specified in the verification call?
> - If no algorithm restriction is present, can the token's `alg` header be set to `none` to skip signature verification?
> - If the server uses an asymmetric algorithm (RS256, ES256), does the verification code also accept HMAC algorithms (HS256)? If so, the server may be vulnerable to the RS256→HS256 confusion attack.
>
> **Check 2 — Signature verification enabled**
> - Is the token passed through a verify/parse call that actually checks the signature, or only through a decode-only call?
> - Look for options like `verify_signature: False`, `complete=False`, or the use of `jwt.decode()` (Node.js) instead of `jwt.verify()`
> - Manual base64-decode of the payload without any signature check is always vulnerable
>
> **Check 3 — HMAC secret strength**
> - Is the secret hardcoded in source code? If so, is it a common word or short string?
> - Is the secret loaded from an environment variable or config? Even then, note if the default or example value is weak
> - A secret shorter than 32 characters or composed of dictionary words is likely brute-forceable
>
> **Check 4 — Embedded JWK / JKU / X5U header injection**
> - Does the verification code read the `jwk` field from the token header and use it to verify the same token?
> - Does the code fetch a key from a URL specified in the `jku` or `x5u` header without validating the URL against an allowlist?
> - If either is true, the verification is fully bypassable
>
> **Check 5 — `kid` header injection**
> - Is the `kid` header value extracted from the token before verification and used to look up a key?
> - Is the `kid` value interpolated into a SQL query without parameterization? → SQL injection
> - Is the `kid` value used to construct a file path without sanitization? → path traversal / key substitution
>
> **Check 6 — Claim validation**
> - Is `exp` (expiry) checked? If not, expired tokens are valid forever
> - Is `iss` (issuer) checked? If not, tokens from other issuers are accepted
> - Is `aud` (audience) checked? If not, tokens for other services are accepted
> - Are security-sensitive claims like `role` or `permissions` present but not validated against a server-side source?
>
> **Check 7 — Token revocation**
> - Is there a token blacklist, revocation endpoint, or short-lived token + refresh-token pattern?
> - If tokens are long-lived (hours or more) with no revocation mechanism, stolen tokens remain valid
>
> **Classification**:
> - **Vulnerable**: The weakness is clearly present with no effective mitigation — the attack path is directly exploitable.
> - **Likely Vulnerable**: The weakness is probably present but requires confirming a secondary condition (e.g., library version behavior, default option value).
> - **Not Vulnerable**: The implementation correctly addresses this check.
> - **Needs Manual Review**: Cannot determine the vulnerability status with confidence from static analysis alone.
>
> **Output format** — write to `sast/jwt-results.md`:
>
> ```markdown
> # JWT Analysis Results: [Project Name]
>
> ## Executive Summary
> - Verification sites analyzed: [N]
> - Vulnerable: [N]
> - Likely Vulnerable: [N]
> - Not Vulnerable: [N]
> - Needs Manual Review: [N]
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Vulnerability class**: [e.g., "Missing signature verification" / "alg:none accepted" / "Weak HMAC secret" / "JWK header injection" / "kid SQL injection" / "Missing exp validation"]
> - **Issue**: [Clear description of what is wrong]
> - **Attack scenario**: [Step-by-step: what the attacker does, what token they craft or modify, what access they gain]
> - **Impact**: [What an attacker can achieve — forge arbitrary identity, escalate privileges, access other users' data, etc.]
> - **Remediation**: [Specific fix — add algorithms restriction, enable verify_signature, load secret from env, pin JWKS URL, parameterize kid lookup, add exp validation, etc.]
> - **Dynamic Test**:
>   ```
>   [Proof-of-concept using jwt_tool, hashcat, or curl.
>    Show the exact command to reproduce the issue.
>    Examples:
>    - jwt_tool <token> -X a   (test alg:none)
>    - jwt_tool <token> -X s   (test RS256→HS256 confusion)
>    - hashcat -a 0 -m 16500 <token> wordlist.txt   (brute-force HMAC secret)
>    - Manual: modify payload, set alg:none, send to endpoint]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Vulnerability class**: [class]
> - **Issue**: [What appears to be wrong]
> - **Uncertainty**: [What needs to be confirmed — e.g., "Library version determines default behavior"]
> - **Remediation**: [Fix]
> - **Dynamic Test**:
>   ```
>   [payload or command to attempt exploitation]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Algorithm restricted to HS256 with strong env-loaded secret; exp validated"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the vulnerability status cannot be determined statically]
> - **Suggestion**: [What to inspect manually — e.g., "Confirm what JWT library version is installed; older versions of PyJWT accept alg:none by default"]
> ```

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to both subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- **Phase 1 is purely discovery**: locate every JWT issuance, verification, and configuration site. Do not attempt to assess security in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely analysis**: for each verification site found in Phase 1, systematically check every vulnerability class. Do not search for new sites in Phase 2 — focus on what Phase 1 found.
- If no JWT usage is found in Phase 1, skip Phase 2 entirely and write a "No JWT usage detected" result file.
- The most critical checks are: signature verification disabled, algorithm not restricted (alg:none / RS256→HS256 confusion), and weak or hardcoded HMAC secret. These lead directly to full authentication bypass.
- `jwt.decode()` in Node.js's `jsonwebtoken` library is a decode-only function — it never verifies the signature. Only `jwt.verify()` validates the signature. Confusing the two is a common and critical mistake.
- In Python's PyJWT, versions before 2.0 accepted `alg: none` by default and did not require an `algorithms` parameter. If the codebase does not pin the version or restrict algorithms, flag it.
- Algorithm confusion (RS256→HS256) requires: (a) the server uses RS256 with a key pair, (b) the public key is accessible, and (c) the verification code does not restrict the algorithm. All three must be present.
- `kid` injection is often overlooked: always check how the key lookup is implemented when `kid` is present in the token header.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
