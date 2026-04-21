---
name: sast-redos
description: >-
  Detect Regular Expression Denial of Service (ReDoS) vulnerabilities caused
  by catastrophic backtracking in a codebase using a three-phase approach:
  recon (find suspicious regex literals and user-input sinks), batched verify
  (analyze regex ambiguity and exposure in parallel subagents, 3 candidates
  each), and merge (consolidate batch results). Covers nested quantifiers,
  overlapping alternation, and regex engines without linear-time guarantees.
  Requires sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/redos-results.md and sast/redos-results.json. Use when asked to find
  ReDoS, catastrophic backtracking, or regex DoS bugs.
version: 0.1.0
---

# Regular Expression Denial of Service (ReDoS) Detection

You are performing a focused security assessment to find Regular Expression Denial of Service (ReDoS) vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find suspicious regex literals and the code paths where they match against user-controlled input), **batched verify** (analyze each candidate's ambiguity, reachable input surface, and mitigations in parallel batches of 3), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is ReDoS

Regular Expression Denial of Service (ReDoS) occurs when a regular expression with nested quantifiers or ambiguous alternation runs in exponential (or super-linear) time on a crafted input. Backtracking-based regex engines (PCRE, Python `re`, Java `Pattern`, JavaScript/V8 `RegExp`, .NET `Regex`, Ruby `Regexp`) attempt every combination of how repeated or alternative sub-patterns can match. When the grammar of the pattern permits the same input prefix to be matched in many different ways, the engine explores all of them before reporting failure. A single malicious input string of only a few hundred characters can make the engine run for seconds, minutes, or hours — pinning a CPU core, blocking the Node.js event loop, stalling a worker thread, and starving concurrent requests.

The vulnerability lives in the **intersection** of three things: a pattern that has super-linear worst-case behaviour, a regex engine that does not guarantee linear time (i.e., not RE2/Rust `regex`), and an input path where an attacker can supply an arbitrarily long or arbitrarily structured string that actually reaches the match call. Missing any of the three usually removes the real risk.

ReDoS arises from four primary root causes:

1. **Nested quantifiers**: `(a+)+`, `(a*)*`, `(\d+)+`, `([0-9]+)*` — the inner group and the outer group both repeat over the same characters, so the engine has a combinatorial number of ways to partition the input between them.
2. **Overlapping alternation under repetition**: `(a|a)*`, `(a|aa)+`, `(foo|fo+)*` — branches that both match the same prefix force the engine to try each branch on every iteration.
3. **Quantified groups with a greedy suffix**: `^(.*a){N,}`, `(.*,)+$`, `.*.*.*x` — consecutive quantifiers over the same character class create a partitioning explosion when the anchor cannot be satisfied.
4. **Long disjunctions of overlapping literals**: `(word1|word1s|word|words|...)+` — common in naive dictionary-style validators and blocklists.

### What ReDoS IS

- A regex pattern with nested or overlapping quantifiers that is evaluated against attacker-controlled input under a backtracking engine
- A pattern compiled once at load time but matched on every request against an unbounded user string (headers, cookies, JSON bodies, file contents)
- A pattern that runs synchronously on the event loop (Node.js) or inside a request handler (Python/Java/Ruby) with no timeout, such that a single slow match stalls other requests
- A seemingly innocuous validator (email, URL, hostname, UUID, semver) whose quirks produce catastrophic backtracking on a crafted near-match
- A blocklist / sanitizer regex applied to HTML, HTTP headers, filenames, or file bytes (file-type sniffing) where the attacker controls the content being sniffed
- A regex anchored only at the start or only at the end — allowing the engine to try every starting (or ending) position when the anchor cannot be satisfied

### What ReDoS is NOT

Do not flag these as ReDoS:

- **General DoS**: large file uploads, unbounded loops, memory exhaustion via JSON parsing, fork bombs, zip bombs — these are separate availability issues. Flag memory-exhaustion and algorithmic-complexity issues elsewhere (e.g., in a DoS-focused review), not as ReDoS.
- **Memory exhaustion via `String.repeat`, giant arrays, or recursive parsers**: not regex-related.
- **Slow network I/O, slow DB queries, or N+1 queries**: performance issues, not ReDoS.
- **RE2 / Rust `regex` / Go `regexp` patterns**: these engines are linear-time by construction. Even a pattern that looks exponential cannot backtrack here. Do not flag regex use in Go's standard `regexp` package or crates like Rust `regex` / `fancy-regex`'s linear mode. (Note: `fancy-regex` supports lookarounds/backrefs which *can* be exponential — treat it like a backtracking engine.)
- **Patterns that only match against bounded server-generated strings**: e.g., a regex run over `os.environ['HOME']`, a constant, or the server's own config value. No attacker-controlled input → no ReDoS.
- **Patterns run asynchronously on a worker pool with a hard timeout / cancellation**: the worst case is a cancelled worker, not a server stall. Lower the severity, but note the mitigation.
- **Patterns that are anchored on both sides and bounded in length** (see "benign patterns" below): frequently safe in practice.

### Patterns That Prevent ReDoS

When you see these patterns, the code is likely **not vulnerable** or the severity should be downgraded:

**1. Linear-time regex engines (RE2, Rust `regex`, Go `regexp`)**
```go
// Go — regexp package is RE2-based, linear time
matched, _ := regexp.MatchString(`(a+)+b`, userInput)  // safe even with "evil" pattern
```

```rust
// Rust — `regex` crate is linear time
let re = Regex::new(r"(a+)+b").unwrap();  // safe
re.is_match(&user_input);
```

**2. Upstream input-length cap before the match**
```python
# Python — reject long strings before matching
if len(user_input) > 256:
    raise ValidationError("too long")
EMAIL_RE.match(user_input)  # worst case bounded by 256 chars
```
A length cap turns exponential growth into a constant-time worst case (`2^256` with a hard 256-char cap is still "too much" in theory, but in practice a tight cap — 128 or 256 — keeps the match below practical DoS thresholds for most patterns). Flag as **low** severity when the cap is clearly present and clearly enforced before the match.

**3. Hard per-match timeout / cancellation**
```java
// Java — run Matcher on a worker with a timeout
Future<Boolean> f = executor.submit(() -> EMAIL.matcher(input).matches());
try {
    f.get(100, TimeUnit.MILLISECONDS);
} catch (TimeoutException e) {
    f.cancel(true);
    return false;
}
```
```csharp
// .NET — Regex constructor timeout
var re = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
```
```javascript
// Node.js — worker_threads with a timeout for untrusted patterns
// (No built-in per-regex timeout in V8 RegExp)
```

**4. Possessive quantifiers / atomic groups (Java, PCRE, Ruby)**
```java
// Java — possessive quantifier (no backtracking)
Pattern.compile("(a++)+b");          // "++" makes the inner match possessive
Pattern.compile("(?>a+)+b");          // atomic group form — equivalent
```
Possessive quantifiers and atomic groups tell the engine not to give up previously-matched characters. They eliminate the backtracking explosion in most classic ReDoS shapes.

**5. Validator libraries with known-linear internals**
```python
# Python — `email-validator` library (no regex-based quadratic validation)
from email_validator import validate_email
validate_email(user_input, check_deliverability=False)
```
```javascript
// Node.js — modern `validator` versions (validator.js >= 13.7 for isEmail)
const validator = require('validator');
validator.isEmail(input);  // historic CVEs fixed
```

**6. Bounded, anchored, non-nested patterns**
```
^[A-Za-z0-9_-]{1,64}$        # character class with explicit upper bound — safe
^\d{4}-\d{2}-\d{2}$          # fixed-length date — safe
^[a-z]+@[a-z]+\.[a-z]{2,8}$  # simple email shape — safe (no nested quantifier)
```

---

## Vulnerable vs. Secure Examples

### Node.js — custom email / URL regex on request body

```javascript
// VULNERABLE: nested quantifier over user input, no length cap
const EMAIL_RE = /^([a-zA-Z0-9._%+-]+)+@([a-zA-Z0-9.-]+)+\.([a-zA-Z]{2,})$/;
app.post('/signup', (req, res) => {
  const email = req.body.email;                   // attacker-controlled
  if (!EMAIL_RE.test(email)) return res.status(400).send('bad email');
  // Payload: "a".repeat(30) + "!" — each extra char doubles match time
  createUser(email);
});

// VULNERABLE: validator.isEmail on old validator.js (<13.7.0) — CVE-2021-3765
const validator = require('validator');
app.post('/signup', (req, res) => {
  if (!validator.isEmail(req.body.email)) return res.status(400).end();
});

// VULNERABLE: cookie parsing in old `cookie` package (<0.7.0) — CVE-2024-47764
// Regex over Cookie header (attacker-controlled) with super-linear behaviour.

// SECURE: length cap + simple linear pattern
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,8}$/;
app.post('/signup', (req, res) => {
  const email = req.body.email;
  if (typeof email !== 'string' || email.length > 254) return res.status(400).end();
  if (!EMAIL_RE.test(email)) return res.status(400).end();
  createUser(email);
});
```

### Python `re` — no timeout, blocks asyncio event loop

```python
# VULNERABLE: classic (a+)+ inside an async handler
import re
SUSPICIOUS = re.compile(r"^(\w+\s?)*$")   # super-linear on " " + "a" * 20 + "!"

@app.post("/comments")
async def post_comment(payload: CommentIn):
    text = payload.text                    # attacker-controlled, unbounded length
    if not SUSPICIOUS.match(text):          # runs on event loop — stalls ALL requests
        raise HTTPException(400)
    await db.save(text)

# VULNERABLE: user-supplied search regex compiled server-side
@app.get("/search")
def search(q: str):
    pattern = re.compile(q)                # attacker picks the pattern itself
    return [row for row in rows if pattern.search(row.text)]

# SECURE: length cap + run in threadpool (doesn't fix pattern, but bounds damage)
@app.post("/comments")
async def post_comment(payload: CommentIn):
    text = payload.text
    if len(text) > 4096:
        raise HTTPException(413)
    ok = await asyncio.wait_for(
        asyncio.to_thread(SUSPICIOUS.match, text),
        timeout=0.2,
    )
    if not ok:
        raise HTTPException(400)

# BETTER: replace the regex with a non-ambiguous one, or use google-re2
import re2 as re                           # drop-in for many uses; linear time
```

### Java `Pattern` — atomic groups / possessive quantifiers

```java
// VULNERABLE: nested quantifier evaluated on request parameter
private static final Pattern EMAIL =
    Pattern.compile("^([a-zA-Z0-9._-]+)+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");

@PostMapping("/signup")
public ResponseEntity<?> signup(@RequestBody SignupReq req) {
    if (!EMAIL.matcher(req.email()).matches()) return badRequest().build();
    // Payload: "a".repeat(30) + "!" — exponential on grouped '+'
    return ok().build();
}

// SECURE: possessive quantifier prevents backtracking
private static final Pattern EMAIL =
    Pattern.compile("^[a-zA-Z0-9._-]++@[a-zA-Z0-9.-]++\\.[a-zA-Z]{2,}$");

// SECURE: atomic group form
private static final Pattern EMAIL =
    Pattern.compile("^(?>[a-zA-Z0-9._-]+)@(?>[a-zA-Z0-9.-]+)\\.[a-zA-Z]{2,}$");

// SECURE: per-call timeout wrapper
boolean matchWithTimeout(Pattern p, String s, long ms) throws Exception {
    Future<Boolean> f = executor.submit(() -> p.matcher(s).matches());
    try { return f.get(ms, TimeUnit.MILLISECONDS); }
    catch (TimeoutException e) { f.cancel(true); return false; }
}
```

### Go `regexp` — RE2 is safe by default

```go
// NOT VULNERABLE: Go's regexp package is RE2-based (linear time, no backtracking)
var emailRe = regexp.MustCompile(`^([a-zA-Z0-9._%+-]+)+@([a-zA-Z0-9.-]+)+\.([a-zA-Z]{2,})$`)

func signup(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    if !emailRe.MatchString(email) {            // safe: RE2 runs in O(n*m)
        http.Error(w, "bad email", 400)
        return
    }
}

// CAUTION: third-party libraries that bring their own PCRE engine
//   - github.com/h2non/gentleman (uses PCRE bindings in some cases)
//   - go-pcre / rubex — these DO backtrack. Flag these.
```

### Ruby `Regexp` — slow regex on untrusted headers

```ruby
# VULNERABLE: grouped + with alternation, called per request on a header
EMAIL = /^([A-Za-z0-9._%+-]+)+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/

post '/signup' do
  email = params[:email]            # attacker-controlled
  halt 400 unless EMAIL.match?(email)
  User.create(email: email)
end

# SECURE: atomic group (Onigmo supports (?>...))
EMAIL = /^(?>[A-Za-z0-9._%+-]+)@(?>[A-Za-z0-9.-]+)\.[A-Za-z]{2,}$/

# SECURE: Ruby 3.2+ Regexp.timeout (global)
Regexp.timeout = 1.0
# Or per-pattern:
EMAIL = Regexp.new(pattern, timeout: 0.1)
```

### .NET `Regex` — MatchTimeout

```csharp
// VULNERABLE: default constructor has no timeout
private static readonly Regex Email = new Regex(
    @"^([A-Za-z0-9._%+-]+)+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$");

// SECURE: explicit timeout on the Regex instance
private static readonly Regex Email = new Regex(
    @"^([A-Za-z0-9._%+-]+)+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
    RegexOptions.CultureInvariant,
    TimeSpan.FromMilliseconds(100));

// SECURE: .NET 7+ non-backtracking engine
private static readonly Regex Email = new Regex(
    pattern,
    RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);
```

### Notable real-world CVEs

- **moment.js** `CVE-2017-18214` — `moment()` parsing regex took exponential time on long hint-matching strings; fixed in 2.19.3.
- **validator.js `isEmail()`** `CVE-2021-3765` — specific crafted inputs caused catastrophic backtracking in the email regex; fixed in 13.7.0.
- **cookie (Node)** `CVE-2024-47764` — cookie header parsing regex was super-linear; crafted Cookie header → server stall; fixed in 0.7.0.
- **marked** `CVE-2022-21680` — markdown regex in table/heading handling allowed exponential blow-up.
- **minimatch** `CVE-2022-3517` — glob-to-regex translation produced exponential patterns on crafted globs.
- **ua-parser-js** `CVE-2022-25927` — trim / regex on User-Agent header was super-linear.
- **semver (Node)** `CVE-2022-25883` — range parsing regex backtracked on crafted ranges.

Treat matches against these exact library + version ranges as confirmed vulnerabilities.

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context. The primary language(s), web framework(s), regex engine(s), and any listed CVE-affected dependencies from `architecture.md` all feed phase decisions.

### Phase 1: Recon — Find Suspicious Regex Literals

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a regex with a potentially super-linear pattern is compiled or invoked, and flag whether it may be matched against user-controlled input. Write results to `sast/redos-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, the regex engine in use (RE2 vs backtracking), request entry points, middleware, and any validator libraries in the dependency list.
>
> ---
>
> **Category 1 — Suspicious regex patterns (literal or constructed)**
>
> A pattern is a ReDoS candidate if it has any of the following shapes. Check regex literals (`/.../` in JS, `r"..."` in Python/Go, `"..."` passed to `Pattern.compile` / `re.compile` / `new Regex`), and regex constructed from string constants or templates:
>
> - **Nested quantifiers**: `(X+)+`, `(X*)*`, `(X+)*`, `(X*)+` for any non-empty `X` — e.g., `(a+)+`, `(\w+)+`, `(\d+)*`, `([0-9]+)*`, `(.+)+`, `([^,]+,?)*`.
> - **Overlapping alternation under repetition**: `(a|a)*`, `(a|aa)+`, `(foo|fo)+`, `(.|\n)*`, `(\s|\t)*` — branches that share a prefix.
> - **Consecutive greedy quantifiers**: `.*.*`, `.+.+`, `.*(x).*`, `(.*a){N,}`, `(.*,)+$` — two unbounded quantifiers competing over the same characters.
> - **Long disjunctions of overlapping literals** (e.g., a blocklist of 20+ keywords joined with `|` inside a `+` or `*` group).
> - **Greedy quantifier immediately before a lookahead / backreference** (only relevant in backtracking engines): `(.*)\1`, `(.+)(.+)\1\2`.
> - **Regex constructed at runtime from user input** — `re.compile(user_value)`, `new RegExp(userInput)` — always flag regardless of shape (the attacker picks the pattern).
>
> Also flag every regex literal that is **long and complex** (over ~60 chars or containing both alternation and quantifiers) even if you aren't certain — the verify phase will analyse it.
>
> **Category 2 — Regex invocation sites on user-controlled input**
>
> A suspicious pattern only matters if the match runs on attacker-controlled bytes. Check these common sink locations:
>
> - **Validators**: custom email / URL / UUID / hostname / phone / date / credit-card / ISO code regex applied to request body, query, or form fields.
> - **HTTP header parsing**: `User-Agent`, `Accept-Language`, `Content-Type`, `Cookie`, `Authorization`, `Referer`, `X-Forwarded-*`. Regex over headers is classic ReDoS territory — attackers fully control header values.
> - **Cookie parsing**: custom cookie splitters, `cookie-parser`-style regex, session-cookie parsers.
> - **Body / query parsers**: custom multipart parsers, JSON-path-like regexes, URL-encoded splitters.
> - **URL parsers / SSRF validators / CORS origin matchers**: regex that decides whether a URL is an "internal" host, whether an origin is allowed, or whether a hostname is on an allowlist. These run on attacker input and often use nested quantifiers to cover edge cases.
> - **File-type sniffing**: regex over the first few KB of an upload's bytes, MIME sniffing, magic-number parsing.
> - **Content sanitizers / HTML strippers**: regex-based HTML tag/attribute removers applied to user-submitted content.
> - **Log sanitizers** that run on incoming log lines or forwarded messages.
> - **Search / filter endpoints** where the user supplies a regex directly (`re.compile(q)`).
>
> **Category 3 — Third-party library calls with known ReDoS CVEs**
>
> Cross-reference the project's dependency list from `architecture.md`. Flag a direct finding for:
>
> - `moment` < 2.19.3 (CVE-2017-18214)
> - `validator` < 13.7.0 (CVE-2021-3765, `isEmail`)
> - `cookie` < 0.7.0 (CVE-2024-47764)
> - `marked` < 4.0.10 (CVE-2022-21680)
> - `minimatch` < 3.0.5 (CVE-2022-3517)
> - `ua-parser-js` < 0.7.33 (CVE-2022-25927)
> - `semver` (npm) < 7.5.2 / < 6.3.1 (CVE-2022-25883)
> - `ansi-regex` < 3.0.1 / < 4.1.1 / < 5.0.1 (CVE-2021-3807)
> - `trim` < 0.0.3 (CVE-2020-7753)
> - `trim-newlines` < 3.0.1 / < 4.0.1 (CVE-2021-33623)
> - Any other library flagged in the architecture's dependency notes
>
> ---
>
> **What to skip** (do not flag):
> - Patterns in Go's standard `regexp` package, Rust's `regex` crate (non-fancy mode), or any other confirmed RE2/linear engine — these cannot backtrack.
> - Patterns that run against a string you can prove is server-generated or a fixed constant.
> - Patterns that are anchored both ends and contain only a single bounded character class: `^[A-Za-z0-9_-]{1,64}$`, `^\d{4}-\d{2}-\d{2}$`.
>
> ---
>
> **Output format** — write to `sast/redos-recon.md`:
>
> ```markdown
> # ReDoS Recon: [Project Name]
>
> ## Summary
> Found [N] potential ReDoS candidates: [X] custom regex, [Y] header/cookie parsers, [Z] known-CVE library versions, [W] runtime-constructed regex.
>
> ## Candidates Found
>
> ### 1. [Descriptive name — e.g., "Nested-quantifier email regex in signup validator"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Regex engine**: [JS V8 / Python re / Java Pattern / .NET Regex / Ruby Onigmo / Go regexp (RE2) / Rust regex / other]
> - **Pattern** (verbatim): `^([a-zA-Z0-9._%+-]+)+@...$`
> - **Suspicious shape(s)**: [nested quantifier / overlapping alternation / long disjunction / runtime-constructed / known-CVE library]
> - **Apparent input source**: [e.g., `req.body.email`, `req.headers['user-agent']`, "unclear — passed in from caller"]
> - **Code snippet**:
>   ```
>   [the relevant code around the compile and match call]
>   ```
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/redos-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Candidates Found" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/redos-results.md`, write `sast/redos-results.json` with `{"findings": []}`, **delete** `sast/redos-recon.md`, and stop:

```markdown
# ReDoS Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one potential candidate.

### Phase 2: Verify — Analysis (Batched)

After Phase 1 completes, read `sast/redos-recon.md` and split the candidates into **batches of up to 3 candidates each** (numbered sections under `## Candidates Found`: `### 1.`, `### 2.`, etc.). Launch **one subagent per batch in parallel**. Each subagent analyses only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/redos-recon.md` and count the numbered candidate sections.
2. Divide them into batches of up to 3. For example, 8 candidates → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/redos-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework and regex engine from `sast/architecture.md`, and select the matching examples from the "Vulnerable vs. Secure Examples" section above. Include those examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned ReDoS candidate, determine whether the pattern has genuinely ambiguous repetition, whether attacker-controlled input reaches it, and whether mitigations (length cap, timeout, linear engine, atomic groups) neutralise the risk. Write results to `sast/redos-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use the architecture to identify entry points, middleware that may truncate inputs, and the regex engine in use.
>
> **ReDoS reference — what to look for**:
>
> For each candidate, answer three questions in order: **(1) Is the pattern actually ambiguous?**, **(2) Can attacker-controlled input reach the match, and at what max length?**, **(3) Is there an effective mitigation?**
>
> **1. Pattern ambiguity — can the engine backtrack?**
>
> A pattern is **ambiguous** (and therefore potentially exponential) if there exist two distinct ways for the engine to match the same prefix of some input. Specific red flags:
>
> - **Nested quantifier over overlapping character classes**: `(X+)+`, `(X*)*`, `(X+)*` where `X` matches at least one character that the outer repetition also covers. Example: `(a+)+` — the input `aaaa` can be partitioned as `(aaaa)`, `(a)(aaa)`, `(aa)(aa)`, `(a)(a)(aa)`, etc.
> - **Alternation with a shared-prefix branch under repetition**: `(a|a)*`, `(a|ab)+`, `(foo|fo+)*`. Both branches consume `a`, so on failure the engine retries each.
> - **Two greedy quantifiers competing**: `.*.*x` — for the input `aaaaa!` (no trailing `x`), the engine tries every split of the string between the two `.*`.
> - **Quantified group followed by a literal that is ALSO inside the group's character class**: `^(\w+)!$` on `aaaa` — each `\w` backtrack from the failing `!` triggers another attempt.
>
> A pattern is **safe** (linear) even in a backtracking engine if:
> - It has no repetition inside another repetition.
> - All alternation branches are disjoint in their first character.
> - Every quantifier has a tight finite upper bound: `{1,64}`, `{0,16}`.
> - It is fully anchored on both sides AND contains only bounded character classes.
>
> **2. Input reach and size**
>
> Trace the matched string back to its origin:
>
> - **Direct user input**: HTTP body, query, headers, cookies, form fields, URL path parameters, uploaded file bytes, WebSocket frames, queue messages, log ingest.
> - **Indirect user input**: value read from a database column that was originally user-supplied, or passed through a helper function.
> - **Server-side / hardcoded**: env var, config file, constant — not exploitable.
>
> For user input, determine the **maximum length** attackers can supply. Frameworks often have defaults:
> - Express default JSON body limit: 100 KB.
> - Spring Boot default max request size: 1 MB (multipart) / 2 MB (regular).
> - A custom `express.json({ limit: '50mb' })` greatly increases exposure.
> - Headers are typically capped at 8 KB by the web server (nginx, Apache), but that is still plenty for catastrophic backtracking (a 30-char payload is usually enough).
>
> **Crucially**: even a header capped at 8 KB can trigger ReDoS if the pattern is ambiguous. **Only a cap in the low hundreds of characters, applied BEFORE the match, is a reliable mitigation.**
>
> **3. Mitigations — does any of these fully or partially defuse the candidate?**
>
> - **Linear regex engine**: Go `regexp`, Rust `regex` (non-fancy), `re2` Python bindings, .NET 7+ `RegexOptions.NonBacktracking`, JS with `linkedom`/`re2` wrappers — FULL mitigation.
> - **Explicit length cap**: `if (input.length > N) return ...` with N ≤ 256 before the match — usually FULL mitigation for the DoS impact. With N in the low thousands, treat as PARTIAL mitigation (still flag, but downgrade severity to low).
> - **Match timeout**: .NET `Regex(..., TimeSpan)`, Ruby 3.2+ `Regexp.timeout`, a worker-thread wrapper with `setTimeout`/`Future.get(timeout)` — FULL mitigation of the stall impact (attacker can still burn one CPU worker for `timeout` ms, but other requests are not blocked). Note: Node.js has NO built-in per-regex timeout.
> - **Atomic group / possessive quantifier**: `(?>...)` or `X++`, `X*+` — FULL mitigation for most classic ReDoS shapes (Java, PCRE, Ruby Onigmo). Not supported in JS or Python `re`.
> - **Pattern rewritten to unambiguous form**: if you can find a rewrite that removes the nested quantifier (e.g., `[A-Za-z0-9._%+-]+@...` with a single flat character class and no nesting), the pattern is already safe.
> - **Validator library at a patched version**: confirm the version in `package.json` / `requirements.txt` is at or above the CVE fix version.
>
> **Vulnerable vs. secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Crafting a proof-of-concept input**
>
> For each candidate you rate Vulnerable or Likely Vulnerable, produce a concrete input string an attacker could send:
>
> - **Classic `(a+)+b` shape**: send `"a".repeat(30) + "!"` — the missing `b` forces full backtracking over every partition. Increase the 30 to 35 or 40 to move from sub-second to multi-second.
> - **Email-style** `^(...+)+@...$`: send `"a".repeat(30) + "!"` with no `@`.
> - **URL-style** `^(https?://)?([a-z0-9-]+)+(\.[a-z]+)+$`: send `"a".repeat(30)` (no dot).
> - **Long disjunction** `(foo|foa|fob|...)+$`: send many copies of a near-match followed by an invalid tail.
>
> The goal of the PoC is not to crash the production server — it is to confirm the pattern is super-linear on the exact regex + engine combination. Prefer conservative lengths (30-40 chars) and measure with a stopwatch / the dev-tools profiler if you can.
>
> **Classification**:
> - **Vulnerable**: Pattern is demonstrably ambiguous, attacker-controlled input of sufficient length reaches it, no effective mitigation is present, and you can articulate a concrete PoC input. Severity usually **high**.
> - **Likely Vulnerable**: Pattern is ambiguous and attacker can reach it, but exposure is partially reduced (medium length cap, async worker without hard timeout, single validator used many places). Severity usually **medium**.
> - **Low-severity (length cap upstream)**: Pattern is ambiguous but a length cap in the low hundreds is applied before the match. Still flag — caps can drift, be bypassed by framework internals, or removed by future refactors — but severity is **low**.
> - **Not Vulnerable**: Linear engine, explicit per-match timeout, atomic-group / possessive rewrite, or the input source is not attacker-controllable.
> - **Needs Manual Review**: Pattern complexity or input provenance cannot be determined confidently without runtime benchmarking.
>
> **Output format** — write to `sast/redos-batch-[N].md`:
>
> ```markdown
> # ReDoS Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Regex engine**: [backtracking engine name]
> - **Pattern**: `...`
> - **Ambiguity**: [e.g., "nested + inside grouped + over overlapping char class `[a-zA-Z0-9._%+-]`"]
> - **Input source**: [e.g., `req.body.email`, max length = Express default 100 KB, no upstream cap]
> - **Mitigations present**: none / [describe]
> - **Impact**: [e.g., "single ~35-char request pins one event-loop thread for multiple seconds, blocking all concurrent requests on that Node.js process"]
> - **Remediation**: [e.g., "cap `email` to 254 chars before the match AND rewrite regex to flat `^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,8}$`" / "upgrade validator to >=13.7.0" / "use `re2` Python bindings"]
> - **Dynamic Test (PoC)**:
>   ```
>   curl -X POST https://app.example.com/signup \
>        -H 'content-type: application/json' \
>        -d '{"email":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}'
>   # Observe ≥1 s wall-clock latency vs. a normal baseline of a few ms
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Pattern**: `...`
> - **Ambiguity**: [details]
> - **Input source**: [best-effort trace with uncertain step identified]
> - **Concern**: [why it's still a risk despite uncertainty]
> - **Remediation**: [fix]
> - **Dynamic Test**: [PoC to attempt]
>
> ### [LOW] Length cap upstream — bounded exposure
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Pattern**: `...`
> - **Ambiguity**: [details]
> - **Mitigation**: [e.g., "`if (input.length > 128) return 400;` on line 42 runs before the match"]
> - **Residual risk**: [e.g., "cap is generous; future refactor that removes it reintroduces the issue; also not applied to `req.headers['x-trace']` where the same regex is reused"]
> - **Remediation**: [rewrite pattern to linear form; or tighten cap]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Reason**: [e.g., "Go regexp package — RE2 engine, no backtracking" / "pattern is fully anchored and contains no nested quantifiers" / "input is a fixed server constant"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [why ambiguity or input reach could not be determined]
> - **Suggestion**: [e.g., "Benchmark the pattern against `'a'.repeat(35)+'!'` locally; inspect the helper `normalizeInput()` to see if it caps length"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/redos-batch-*.md` file and merge them into a single `sast/redos-results.md` plus the canonical `sast/redos-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/redos-batch-1.md`, `sast/redos-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged markdown report to `sast/redos-results.md` using this format:

```markdown
# ReDoS Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Low (length cap upstream): [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then LOW, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical machine-readable view to `sast/redos-results.json`. Shape:

```json
{
  "findings": [
    {
      "id": "redos-1",
      "skill": "sast-redos",
      "severity": "high",
      "title": "Nested-quantifier email regex on /signup reachable from user input",
      "description": "The pattern ^([a-zA-Z0-9._%+-]+)+@... is evaluated against req.body.email with no upstream length cap. A ~35-char crafted input pins the event loop for multiple seconds.",
      "location": { "file": "src/routes/signup.js", "line": 17 },
      "remediation": "Cap email length to 254 chars before validation and rewrite the pattern to a flat non-nested form, or upgrade to validator >=13.7.0."
    }
  ]
}
```

Use `severity: "high"` for Vulnerable, `"medium"` for Likely Vulnerable, `"low"` for the length-cap-upstream class, and omit Not Vulnerable items from the JSON (or include them as `"info"` only if clarifying). If no findings at all, write `{"findings": []}`.

6. After writing both results files, **delete all intermediate batch files** (`sast/redos-batch-*.md`) and **delete** `sast/redos-recon.md`.

---

## Findings

Use this template section in `sast/redos-results.md` when describing individual findings. Every finding should include:

- **File and line range** (absolute file path is fine, but relative paths are preferred for portability)
- **Endpoint or function name** so triage can find the call quickly
- **Regex engine** (backtracking vs. linear) — this often determines severity by itself
- **The verbatim pattern** — do not paraphrase the regex; triage needs the exact literal
- **The ambiguity class** — nested quantifier, overlapping alternation, long disjunction, runtime-constructed, or known-CVE library
- **Input source and maximum reachable length** — including any upstream framework limit
- **Mitigations present or absent** — length cap, timeout, atomic group / possessive quantifier, linear engine
- **Concrete PoC** — the exact input string and the expected latency delta; this separates theoretical ambiguity from real exploitability
- **Remediation** — the specific code change or library upgrade that closes the issue

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context. The regex engine and framework limits recorded there drive most of the phase-2 reasoning.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file.
- **Phase 1 is purely structural**: flag any regex with a suspicious shape AND any regex that may run on user input, regardless of how the input arrives. Do not try to confirm ambiguity or trace taint in Phase 1.
- **Phase 2 does the real analysis**: prove ambiguity by partitioning the input, trace reach, evaluate mitigations, produce a PoC input string.
- **Go `regexp` is safe by construction**. Do not flag patterns compiled with `regexp.Compile`, `regexp.MustCompile`, `regexp.MatchString` in Go — RE2 is linear. The same applies to Rust's `regex` crate (non-fancy mode). Flag them only if the PoC would demonstrate a slowdown, which it would not.
- **Length cap upstream mitigates — but flag as low**. A 128-byte cap applied before the match turns any ambiguous pattern into a bounded worst case. Still flag the pattern at low severity: caps can drift, be removed, or be skipped on a reused call site.
- **Benign anchored short-input patterns** (`^[A-Za-z0-9_-]{1,64}$`, `^\d{4}-\d{2}-\d{2}$`) can be left unflagged at Phase 1 or classified Not Vulnerable at Phase 2.
- **Famous CVEs are shortcuts** — moment.js, validator.js `isEmail`, cookie-parser, marked, minimatch, ua-parser-js, semver, ansi-regex. If the dependency list shows a vulnerable version, you have a confirmed finding; no further PoC is required beyond citing the CVE and the observed usage site.
- **Header parsing, file-type sniffing, SSRF URL validators, and CORS origin matchers** are high-value targets: attackers fully control header values and origins, and the matched strings typically skip body-size limits.
- **Node.js has no built-in per-regex timeout**. Unless the match is off-loaded to a worker thread, a slow match stalls the entire process. Treat Node.js ReDoS findings with extra weight.
- **Python `re` on an asyncio handler blocks the event loop**: the whole process stops serving requests until the match returns. Either push to a threadpool with a timeout, or replace the engine with `re2`.
- **User-supplied regex patterns** (`re.compile(user_input)`, `new RegExp(body.q)`) are automatically Vulnerable — the attacker chooses both the pattern and the input. Severity critical in most cases.
- Clean up intermediate files: delete `sast/redos-recon.md` and all `sast/redos-batch-*.md` files after the final `sast/redos-results.md` and `sast/redos-results.json` are written (Phase 3 merge step 6 performs this).
