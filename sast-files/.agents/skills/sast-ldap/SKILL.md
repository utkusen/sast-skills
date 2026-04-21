---
name: sast-ldap
description: >-
  Detect LDAP injection vulnerabilities in a codebase using a three-phase
  approach: recon (find LDAP query construction sites — search filters, DN
  assembly, bind operations), batched verify (trace user input to those sites in
  parallel subagents, 3 sites each), and merge (consolidate batch results).
  Covers auth-bypass filter tampering, wildcard enumeration, unescaped DN
  components, dynamic attribute names, and StartTLS/ldaps context issues.
  Requires sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/ldap-results.md and canonical sast/ldap-results.json. Use when asked to
  find LDAP injection, directory query tampering, or LDAP auth bypass bugs.
version: 0.1.0
---

# LDAP Injection Detection

You are performing a focused security assessment to find LDAP injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find LDAP query construction sites), **batched verify** (taint analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is LDAP Injection

LDAP injection occurs when user-supplied input is concatenated into an LDAP search filter or a Distinguished Name (DN) without proper escaping, allowing an attacker to alter the structure of the directory query. Successful exploitation can lead to authentication bypass, unauthorized data disclosure, privilege escalation, and enumeration of directory contents.

The core pattern: *unvalidated, unescaped user input reaches an LDAP search filter, DN, or bind call.*

LDAP uses two syntaxes that each require different escaping rules:

- **Search filters** use RFC 4515 syntax — for example `(&(uid=alice)(objectClass=person))`. The meta-characters that must be escaped inside filter values are `(`, `)`, `*`, `\`, and the NUL byte (`\00`). If any of these reach the filter unescaped, the filter tree can be rewritten by the attacker.
- **Distinguished Names** use RFC 4514 syntax — for example `uid=alice,ou=people,dc=example,dc=com`. The meta-characters that must be escaped inside DN attribute values are `,`, `=`, `+`, `<`, `>`, `#`, `;`, `\`, and `"`, plus leading/trailing spaces and a leading `#`.

Because the escape rules are context-specific, string concatenation is almost always unsafe. Safe code uses a language-specific *safe filter builder* or an explicit *escape function* that targets the correct context (filter vs DN).

### What LDAP Injection IS

- Concatenating user input directly into an LDAP search filter string: `f"(uid={username})"` or `"(uid=" + username + ")"`
- Concatenating user input into a DN used for bind, search base, modify, or delete: `f"uid={username},ou=people,dc=example,dc=com"`
- Passing a user-controlled string as the filter argument of `search()`, `search_s()`, `ldap_search()`, `searchEntries()`, or any equivalent client method without escaping
- Using user input as the bind DN of `simple_bind()` / `bind_s()` / `bind()` without escaping — attacker may inject alternate DNs
- Using user-controlled attribute names in the filter or in the list of attributes to return — e.g. `f"({attr}={value})"` where `attr` is user input
- Authentication-bypass filter tampering, such as submitting `admin)(&(password=*)` as a username so the built filter becomes `(&(uid=admin)(&(password=*))(password=<real>))` — the appended clauses change the intended Boolean tree
- Wildcard enumeration, such as submitting `*` or `a*` into a filter value to return many more records than intended
- Second-order LDAP injection — user input is stored (in the DB or directory itself) and later read into a filter or DN without re-escaping

### What LDAP Injection is NOT

Do not flag these as LDAP injection:

- **SQL injection**: Injection into a SQL query — that is SQLi, a separate class, even if the downstream store is later queried over LDAP.
- **NoSQL injection**: Injection into MongoDB/Redis/Elasticsearch operators — similar concept but a distinct vulnerability class. LDAP filter syntax is not the same as Mongo query-operator syntax; do not conflate `$ne`/`$gt` style injection with LDAP filter injection.
- **Missing authentication**: An endpoint that talks to LDAP but never authenticates the caller is a missing-auth finding, not LDAP injection. LDAP injection specifically requires attacker-controlled data flowing *into* a filter or DN.
- **Credential brute force**: Guessing passwords against an LDAP bind is not LDAP injection — the filter/DN are not being tampered with.
- **Safe parameterized bind**: A bind that uses a fixed service-account DN plus a user-supplied password sent as an opaque credential argument is not LDAP injection, even if the password contains `(` or `*`. LDAP bind credential comparison does not interpret filter meta-characters.
- **Plain `ldaps://` misconfiguration**: Missing StartTLS or using `ldap://` without TLS is a transport-security issue (credential interception), not LDAP injection. Note it in context but do not classify as injection.

### Patterns That Prevent LDAP Injection

When you see these patterns, the code is likely **not vulnerable**:

**1. Safe filter builders (preferred)**

Use a library that builds the filter as a structured object rather than a string:

```
# Python — ldap3 safe filter with placeholders
from ldap3.utils.conv import escape_filter_chars
safe_user = escape_filter_chars(username)
conn.search(search_base='ou=people,dc=example,dc=com',
            search_filter=f'(uid={safe_user})',
            attributes=['cn', 'mail'])

# Python — python-ldap
import ldap.filter
safe_filter = ldap.filter.filter_format('(uid=%s)', [username])

# Node.js — ldapjs parses and escapes via the Filter objects
const { EqualityFilter } = require('ldapjs');
const filter = new EqualityFilter({ attribute: 'uid', value: username });

# Java — UnboundID SDK Filter factory (handles escaping)
Filter f = Filter.createEqualityFilter("uid", username);

# Java — Spring LDAP LdapQueryBuilder
LdapQuery q = query().where("uid").is(username);
```

**2. Explicit escape helpers for both filter and DN contexts**

```
# Python — escape_filter_chars for filter values, escape_rdn for DN components
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
filter_val = escape_filter_chars(username)       # RFC 4515
dn_component = escape_rdn(username)              # RFC 4514

# Java — UnboundID
String safeFilter = Filter.encodeValue(username);  // RFC 4515
String safeDn = DN.escapeAttributeValue(username); // RFC 4514

# PHP — ext-ldap
$safeFilter = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
$safeDn     = ldap_escape($username, '', LDAP_ESCAPE_DN);
```

**3. Allowlist validation for attribute names and return-attribute lists**

Attribute names and search bases cannot be safely escaped as values — they must be validated against a static allowlist before being placed in a filter or used as a search argument:

```
ALLOWED_ATTRS = {'uid', 'cn', 'mail', 'givenName', 'sn'}
if attr not in ALLOWED_ATTRS:
    raise ValueError("Invalid attribute")
safe_value = escape_filter_chars(value)
filter_ = f"({attr}={safe_value})"
```

**4. Search-then-bind instead of DN concatenation for authentication**

The safest authentication flow is:

1. Bind as a low-privilege service account using hardcoded credentials.
2. Search for the user by a *safely escaped* identifier to retrieve their actual DN.
3. Re-bind as that DN using the user-supplied password.

This avoids assembling the user's DN from input strings. Flag code that skips step 2 and instead concatenates a DN like `f"uid={username},ou=people,dc=example,dc=com"` for bind.

**5. Use `ldaps://` or StartTLS so that even safe queries are not observable in transit**

This does not prevent injection but is part of the secure baseline. Note its absence as context when reporting findings on authentication flows, but do not classify a plaintext bind as LDAP injection on its own.

---

## Vulnerable vs. Secure Examples

### Python — ldap3

```python
# VULNERABLE: f-string interpolation into a search filter
from ldap3 import Server, Connection
def find_user(username):
    conn = Connection(Server('ldap://ldap.example.com'), auto_bind=True)
    conn.search(
        search_base='ou=people,dc=example,dc=com',
        search_filter=f'(uid={username})',
        attributes=['cn', 'mail'],
    )
    return conn.entries

# VULNERABLE: DN built by concatenation then used for bind — auth bypass risk
def login(username, password):
    dn = f'uid={username},ou=people,dc=example,dc=com'
    conn = Connection(Server('ldap://ldap.example.com'), user=dn, password=password)
    return conn.bind()

# SECURE: escape filter chars and escape RDN for DN assembly
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

def find_user(username):
    conn = Connection(Server('ldaps://ldap.example.com'), auto_bind=True)
    conn.search(
        search_base='ou=people,dc=example,dc=com',
        search_filter=f'(uid={escape_filter_chars(username)})',
        attributes=['cn', 'mail'],
    )
    return conn.entries

def login(username, password):
    conn = Connection(Server('ldaps://ldap.example.com'), auto_bind=True)
    conn.search('ou=people,dc=example,dc=com',
                f'(uid={escape_filter_chars(username)})',
                attributes=['distinguishedName'])
    if not conn.entries:
        return False
    user_dn = conn.entries[0].entry_dn
    user_conn = Connection(Server('ldaps://ldap.example.com'),
                           user=user_dn, password=password)
    return user_conn.bind()
```

### Python — python-ldap

```python
# VULNERABLE
import ldap
def search(username):
    l = ldap.initialize('ldap://ldap.example.com')
    return l.search_s('ou=people,dc=example,dc=com',
                      ldap.SCOPE_SUBTREE,
                      '(uid=' + username + ')')

# SECURE: filter_format handles RFC 4515 escaping
import ldap, ldap.filter
def search(username):
    l = ldap.initialize('ldaps://ldap.example.com')
    safe = ldap.filter.filter_format('(uid=%s)', [username])
    return l.search_s('ou=people,dc=example,dc=com', ldap.SCOPE_SUBTREE, safe)
```

### Node.js — ldapjs

```javascript
// VULNERABLE: template literal into filter string
client.search('ou=people,dc=example,dc=com',
  { filter: `(uid=${req.query.username})`, scope: 'sub' },
  (err, res) => { /* ... */ });

// VULNERABLE: DN built from user input used for bind
const dn = `uid=${req.body.username},ou=people,dc=example,dc=com`;
client.bind(dn, req.body.password, (err) => { /* ... */ });

// SECURE: structured Filter object (ldapjs handles escaping)
const { EqualityFilter } = require('ldapjs');
client.search('ou=people,dc=example,dc=com',
  { filter: new EqualityFilter({ attribute: 'uid', value: req.query.username }),
    scope: 'sub' },
  (err, res) => { /* ... */ });

// SECURE: search-then-bind so we never assemble a DN from user input
client.search('ou=people,dc=example,dc=com',
  { filter: new EqualityFilter({ attribute: 'uid', value: username }), scope: 'sub' },
  (err, res) => {
    res.on('searchEntry', (entry) => {
      client.bind(entry.objectName, password, (err) => { /* ... */ });
    });
  });
```

### Java — JNDI (javax.naming.directory)

```java
// VULNERABLE: user input concatenated into a search filter
public NamingEnumeration<SearchResult> findUser(String username) throws NamingException {
    DirContext ctx = new InitialDirContext(env);
    String filter = "(uid=" + username + ")";
    return ctx.search("ou=people,dc=example,dc=com", filter, controls);
}

// SECURE: parameterized filter with filter arguments (JNDI escapes each arg)
public NamingEnumeration<SearchResult> findUser(String username) throws NamingException {
    DirContext ctx = new InitialDirContext(env);
    return ctx.search(
        "ou=people,dc=example,dc=com",
        "(uid={0})",
        new Object[]{ username },
        controls
    );
}
```

### Java — UnboundID LDAP SDK

```java
// VULNERABLE
String filter = "(uid=" + username + ")";
SearchResult result = conn.search("ou=people,dc=example,dc=com", SearchScope.SUB, filter);

// SECURE: Filter factory handles RFC 4515 escaping
Filter f = Filter.createEqualityFilter("uid", username);
SearchResult result = conn.search("ou=people,dc=example,dc=com", SearchScope.SUB, f);
```

### Java — Spring LDAP

```java
// VULNERABLE: hand-built filter
String filter = "(uid=" + username + ")";
ldapTemplate.search("ou=people,dc=example,dc=com", filter, new UserAttributesMapper());

// SECURE: LdapQueryBuilder escapes values
LdapQuery q = LdapQueryBuilder.query()
    .base("ou=people,dc=example,dc=com")
    .where("uid").is(username);
ldapTemplate.search(q, new UserAttributesMapper());
```

### PHP — ext-ldap

```php
// VULNERABLE
function findUser($ds, $username) {
    $filter = "(uid=" . $username . ")";
    return ldap_search($ds, "ou=people,dc=example,dc=com", $filter);
}

// SECURE: ldap_escape with LDAP_ESCAPE_FILTER
function findUser($ds, $username) {
    $safe = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
    $filter = "(uid=$safe)";
    return ldap_search($ds, "ou=people,dc=example,dc=com", $filter);
}
```

### Go — go-ldap (github.com/go-ldap/ldap/v3)

```go
// VULNERABLE: fmt.Sprintf into a filter
func findUser(l *ldap.Conn, username string) (*ldap.SearchResult, error) {
    req := ldap.NewSearchRequest(
        "ou=people,dc=example,dc=com",
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        fmt.Sprintf("(uid=%s)", username),
        []string{"cn", "mail"}, nil,
    )
    return l.Search(req)
}

// SECURE: ldap.EscapeFilter applies RFC 4515 escaping
func findUser(l *ldap.Conn, username string) (*ldap.SearchResult, error) {
    safe := ldap.EscapeFilter(username)
    req := ldap.NewSearchRequest(
        "ou=people,dc=example,dc=com",
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        fmt.Sprintf("(uid=%s)", safe),
        []string{"cn", "mail"}, nil,
    )
    return l.Search(req)
}
```

### Authentication-Bypass Filter Tampering (all stacks)

A common real-world pattern: an application builds a filter like `(&(uid=<USER>)(password=<PASS>))` and calls `search()` to see if any entry matches. If the user submits `admin)(&(password=*)` as the username and anything as the password, the filter becomes:

```
(&(uid=admin)(&(password=*))(password=anything))
```

The extra balanced clause `(&(password=*))` always matches, so the search returns the admin entry and the application treats the login as successful. The fix is either (a) escape the username so `)` and `(` cannot close/open clauses, or (b) use search-then-bind so the password is never embedded in a filter.

### Wildcard Enumeration (all stacks)

Unescaped `*` inside a filter value lets an attacker enumerate the directory. `uid=a*` matches every user whose uid starts with `a`. Any site that accepts a user-provided filter value without escaping `*` is vulnerable to enumeration even if no Boolean-structure tampering is possible.

### Dynamic Attribute Names (all stacks)

```python
# VULNERABLE: attribute name itself is user-controlled
attr = request.args['attr']
val = request.args['value']
filter_ = f"({attr}={escape_filter_chars(val)})"  # escaping value does not help

# SECURE: allowlist the attribute, then escape the value
ALLOWED = {'uid', 'cn', 'mail'}
if attr not in ALLOWED:
    abort(400)
filter_ = f"({attr}={escape_filter_chars(val)})"
```

Escape helpers do **not** cover attribute names; only an allowlist does.

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find LDAP Query Construction Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where an LDAP operation is performed — specifically `search()`, `search_s()`, `searchEntries()`, `find()`, `ldap_search()`, `ldap_search_s()`, `bind()`, `simple_bind()`, `simple_bind_s()`, `modify()`, `add()`, `delete()`, and any equivalent client method — and where the filter string, DN, search base, or attribute list is constructed dynamically (string concatenation, f-string, template literal, `%` formatting, `.format()`, `fmt.Sprintf`, etc.). Write results to `sast/ldap-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to identify which LDAP client library is in use (ldap3, python-ldap, ldapjs, JNDI, UnboundID, Spring LDAP, ext-ldap, go-ldap, etc.) and which endpoints or services talk to LDAP.
>
> **What to search for — LDAP sink calls**:
>
> 1. **Search / find calls** whose `filter` / `search_filter` / `searchFilter` argument is a dynamic string:
>    - Python: `conn.search(..., search_filter=f"(uid={u})")`, `l.search_s(base, scope, "(uid=" + u + ")")`, `conn.search_ext_s(...)`
>    - Node.js: `` client.search(base, { filter: `(uid=${u})` }) ``, `client.searchAsync(base, { filter: '(uid=' + u + ')' })`
>    - Java: `ctx.search(base, "(uid=" + u + ")", controls)`, `ldapTemplate.search(base, "(uid=" + u + ")", mapper)`, `conn.search(base, SCOPE, "(uid=" + u + ")")`
>    - PHP: `ldap_search($ds, $base, "(uid=" . $u . ")")`, `ldap_list`, `ldap_read`
>    - Go: `ldap.NewSearchRequest(..., fmt.Sprintf("(uid=%s)", u), ...)` passed to `l.Search(...)`
>
> 2. **DN assembly sites** whose output is used in `bind()`, `modify()`, `delete()`, `add()`, `rename()`, or as a `base` argument:
>    - `dn = f"uid={u},ou=people,dc=example,dc=com"` followed by `conn.bind(dn, password)`
>    - `dn = "uid=" + u + ",ou=people,dc=example,dc=com"` passed to `ctx.lookup(dn)` or `ldap_bind($ds, $dn, $pw)`
>    - Template literal DN in Node.js: `` `uid=${u},ou=people,...` ``
>
> 3. **Dynamic attribute names or return-attribute lists**:
>    - `f"({attr}={escape_filter_chars(v)})"` where `attr` is a variable — escaping the value does not cover the attribute name
>    - `attributes=[user_attr]` in `conn.search(...)` where `user_attr` comes from input
>
> 4. **Dynamic search base**:
>    - `f"ou={u},dc=example,dc=com"` used as the `search_base` / first argument — equivalent to a DN assembly site
>
> 5. **`.format()` / `%`-style / `String.format()` / `sprintf` used to build any of the above**.
>
> For each site, capture whether any escape / safe-builder helper is in evidence in the immediate surroundings (`escape_filter_chars`, `escape_rdn`, `filter_format`, `ldap_escape`, `Filter.createEqualityFilter`, `EqualityFilter`, `LdapQueryBuilder`, `ldap.EscapeFilter`). Do not yet decide whether they are applied correctly — that is Phase 2.
>
> Also note whether the connection uses `ldaps://` or StartTLS. This does not affect injection classification but is useful context.
>
> **What to skip** (safe construction patterns — do not flag):
>
> - Fully static filter strings with no interpolation: `conn.search(base, "(objectClass=person)", attrs)`
> - Parameterized filters via JNDI `search(base, "(uid={0})", new Object[]{u}, controls)`
> - UnboundID `Filter.createEqualityFilter(...)` / `Filter.createANDFilter(...)` and similar factory calls
> - Spring LDAP `LdapQueryBuilder.query().where(...).is(...)`
> - ldapjs `new EqualityFilter(...)` / `new AndFilter(...)` used as the `filter` option
> - `python-ldap`'s `ldap.filter.filter_format('(uid=%s)', [u])` — treat as safe if the placeholder form is actually used
>
> **Output format** — write to `sast/ldap-recon.md`:
>
> ```markdown
> # LDAP Recon: [Project Name]
>
> ## Summary
> Found [N] locations where LDAP filters, DNs, or related arguments are constructed dynamically.
>
> LDAP client libraries detected: [list].
> Transport security: [ldaps / StartTLS / plain ldap — per connection site].
>
> ## Dynamic Construction Sites
>
> ### 1. [Descriptive name — e.g., "f-string filter in findUser"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **LDAP operation**: [search / search_s / bind / modify / delete / add / rename]
> - **Construction context**: [search filter / DN / search base / attribute name / attribute list]
> - **Construction pattern**: [string concat / f-string / template literal / % format / .format() / fmt.Sprintf]
> - **Interpolated variable(s)**: `var_name` — [brief note on what it appears to represent]
> - **Escape helper visible nearby**: [none / escape_filter_chars / escape_rdn / ldap_escape / filter_format / other — describe]
> - **Transport**: [ldaps / StartTLS / plain]
> - **Code snippet**:
>   ```
>   [the construction + the LDAP call]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/ldap-recon.md`. If the recon found **zero dynamic LDAP construction sites** (the summary reports "Found 0" or the "Dynamic Construction Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following to `sast/ldap-results.md`:

```markdown
# LDAP Injection Analysis Results

No vulnerabilities found.
```

And write the following to `sast/ldap-results.json`:

```json
{ "findings": [] }
```

Then stop. Only proceed to Phase 2 if Phase 1 found at least one dynamic construction site.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/ldap-recon.md` and split the construction sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent traces user input only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/ldap-recon.md` and count the numbered site sections under "Dynamic Construction Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/ldap-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above (e.g., "Python — ldap3" for a Python ldap3 codebase, "Java — JNDI" for a JNDI-based app). Include these in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]`.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned LDAP construction site, determine whether a user-supplied value reaches the interpolated variable in a way that makes the site exploitable. Our goal is to find LDAP injection vulnerabilities. Write results to `sast/ldap-batch-[N].md`.
>
> **Your assigned construction sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, and how data flows to the LDAP layer.
>
> **LDAP injection reference — trace the interpolated variable(s) backwards to their origin**:
>
> 1. **Direct user input** — assigned directly from a request source with no transformation:
>    - HTTP query params: `request.GET.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `c.Query("x")`
>    - Path parameters: `request.path_params['id']`, `req.params.id`, `params[:id]`
>    - Request body / form fields: `request.POST.get(...)`, `req.body.x`, `params[:x]`, `$_POST['x']`
>    - HTTP headers (including `Authorization` Basic userpart): `request.headers.get(...)`, `req.headers['x']`
>    - Cookies: `request.COOKIES.get(...)`, `req.cookies.x`
>
> 2. **Indirect user input** — derived from user input through transformations, helper calls, or intermediate assignments. Trace the full chain.
>
> 3. **Second-order input** — the variable is read from the database or from the directory itself, but was originally written from user input without escaping. Find the original write site.
>
> 4. **Server-side / hardcoded value** — config, environment, constant, or server-side state with no user influence — not exploitable.
>
> **Context-aware mitigation check** — for each site, verify that the escaping/validation applied matches the *context* of the variable:
>
> - If the variable is placed inside a **search filter value**, the correct mitigation is an RFC 4515 escape (`escape_filter_chars`, `ldap.filter.filter_format`, `ldap_escape(..., LDAP_ESCAPE_FILTER)`, `Filter.encodeValue`, `ldap.EscapeFilter`) or a structured filter object (`EqualityFilter`, `Filter.createEqualityFilter`, `LdapQueryBuilder.where(...).is(...)`). DN escaping alone is NOT sufficient.
> - If the variable is placed inside a **DN / RDN**, the correct mitigation is an RFC 4514 escape (`escape_rdn`, `DN.escapeAttributeValue`, `ldap_escape(..., LDAP_ESCAPE_DN)`). Filter escaping alone is NOT sufficient.
> - If the variable is an **attribute name** (left side of `=` in a filter, or an entry in the `attributes` list), no escape helper is sufficient — only an allowlist protects this position. Flag as vulnerable if no allowlist is present.
> - If the variable is used as a **bind DN**, prefer search-then-bind over concatenation. A concatenated bind DN with only filter escaping is still vulnerable — filter escape rules do not cover DN meta-characters (`,` `=` `+` `<` `>` `#` `;` `\` `"`).
>
> **Specific patterns to look for**:
>
> - **Auth-bypass filter tampering**: a filter like `(&(uid=<USER>)(password=<PASS>))` where `<USER>` is unescaped user input. A payload of `admin)(&(password=*)` closes the uid clause and injects a tautological password clause.
> - **Wildcard enumeration**: any filter value that accepts an unescaped `*` allows the caller to enumerate entries.
> - **Dynamic attribute name**: `f"({user_attr}=...)"` — escape helpers do not cover attribute names.
> - **DN assembly used for bind**: `dn = f"uid={u},ou=..."` then `bind(dn, password)` — attacker can inject alternate DN components unless DN-escaped.
> - **StartTLS / ldaps context**: plain `ldap://` doesn't cause injection but worsens impact (credentials on the wire). Note it as supporting context, not as the primary classification.
>
> **Filter meta-characters that MUST be escaped (RFC 4515)**: `(` `)` `*` `\` and NUL. If the code only strips some of these (e.g., only `*`) or uses a non-LDAP escape like `addslashes` / HTML-encode / URL-encode, classify as Likely Vulnerable.
>
> **DN meta-characters that MUST be escaped (RFC 4514)**: `,` `=` `+` `<` `>` `#` `;` `\` `"`, plus leading/trailing spaces and a leading `#`. Filter escaping is not a substitute.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the filter/DN with no correct context-specific escape or allowlist.
> - **Likely Vulnerable**: User input probably reaches the variable (indirect flow), or only wrong-context or partial escaping is applied (e.g., filter-escape for a DN, strip-only-`*`, home-grown regex).
> - **Not Vulnerable**: Correct context-specific escape or structured filter builder is applied, OR the variable is server-side only, OR an allowlist gates an attribute-name position.
> - **Needs Manual Review**: Cannot determine origin or escaping correctness with confidence (opaque helpers, deep indirection, external libraries).
>
> **Output format** — write to `sast/ldap-batch-[N].md`:
>
> ```markdown
> # LDAP Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "HTTP query param `username` flows unescaped into an f-string search filter"]
> - **Context**: [filter value / DN / attribute name / search base]
> - **Taint trace**: [Step-by-step from entry point to the construction site]
> - **Impact**: [auth bypass / record enumeration / data disclosure / privilege escalation, with reasoning]
> - **Remediation**: [specific API call — e.g., "use escape_filter_chars" or "use Filter.createEqualityFilter" or "switch to search-then-bind"]
> - **Dynamic Test**:
>   ```
>   [example payload. For auth bypass: username=admin)(&(password=*) ; password=x
>    For wildcard enumeration: username=a*
>    For filter tampering: username=*)(uid=*)(cn=*
>    Show the endpoint, the parameter, and the expected response signal.]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "Indirect flow or wrong-context escape (filter-escape used for a DN)"]
> - **Context**: [filter / DN / attribute name]
> - **Taint trace**: [Best-effort trace; mark uncertain steps]
> - **Concern**: [Why it remains a risk — e.g., "escape_filter_chars does not escape `,` or `=` required for DN safety"]
> - **Remediation**: [correct-context escape or structured API]
> - **Dynamic Test**:
>   ```
>   [payload that stresses the specific weakness]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "LdapQueryBuilder handles escaping" or "value comes from a hardcoded constant"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why origin or escaping correctness could not be determined]
> - **Suggestion**: [What to trace or test manually — e.g., "Verify whether the custom sanitize() helper covers `(`, `)`, `*`, `\`, NUL"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/ldap-batch-*.md` file and merge them into a single `sast/ldap-results.md` plus a canonical `sast/ldap-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/ldap-batch-1.md`, `sast/ldap-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and every detail field.
3. Count totals across all batches for the executive summary (construction sites analyzed = total sites batched).
4. Write the merged human-readable report to `sast/ldap-results.md` using this format:

```markdown
# LDAP Injection Analysis Results: [Project Name]

## Executive Summary
- Construction sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Also write the canonical machine-readable view to `sast/ldap-results.json` following the project's canonical schema:

```json
{
  "findings": [
    {
      "id": "ldap-1",
      "skill": "sast-ldap",
      "severity": "critical|high|medium|low|info",
      "title": "one-line description of the issue",
      "description": "full explanation including exploitability (auth bypass, enumeration, disclosure)",
      "location": { "file": "relative/path.ext", "line": 123, "column": 0 },
      "remediation": "context-specific escape, structured filter builder, allowlist for attribute names, or search-then-bind"
    }
  ]
}
```

Include one JSON finding per Vulnerable and Likely Vulnerable item from the merged results. If there are no such findings, still emit `{ "findings": [] }`.

Severity guidance:
- **critical**: auth bypass via filter tampering or DN injection on an authentication endpoint.
- **high**: unauthenticated data disclosure / enumeration of all directory entries, or privilege escalation.
- **medium**: authenticated LDAP injection with limited impact (e.g. enumerates only the caller's scope), or wrong-context escaping likely exploitable in practice.
- **low**: Likely Vulnerable with indirect flow and only minor data exposure.
- **info**: Needs Manual Review items where you want to record a pointer.

6. After writing `sast/ldap-results.md` and `sast/ldap-results.json`, **delete all intermediate batch files** (`sast/ldap-batch-*.md`) and the recon file (`sast/ldap-recon.md`).

---

## Findings

Use this template when describing individual findings in both the batch files and the merged report. It mirrors the output formats above and is reproduced here as a single reference.

```markdown
### [CLASSIFICATION] Short descriptive title
- **File**: `relative/path/to/file.ext` (lines X-Y)
- **Endpoint / function**: [route path or function name]
- **LDAP operation**: [search / search_s / bind / modify / delete / add]
- **Context**: [filter value / DN / attribute name / search base]
- **Issue**: One-sentence description of the vulnerability.
- **Taint trace**:
  1. Entry point — e.g., `POST /login` reads `req.body.username`
  2. Intermediate — passed to `authenticate(username, password)` at `auth.py:42`
  3. Sink — interpolated into `f"(uid={username})"` at `ldap_client.py:17`
- **Filter/DN meta-character exposure**:
  - Filter: `(` `)` `*` `\` NUL (RFC 4515)
  - DN: `,` `=` `+` `<` `>` `#` `;` `\` `"` (RFC 4514)
  - Which of these are unescaped at the sink: [list]
- **Impact**: [Auth bypass / wildcard enumeration / privilege escalation / data disclosure — with a concrete scenario]
- **Transport**: [ldaps / StartTLS / plain ldap — note as supporting context]
- **Remediation**: Replace with [specific API, e.g. `escape_filter_chars(username)`, `Filter.createEqualityFilter("uid", username)`, `LdapQueryBuilder.query().where("uid").is(username)`, or switch to search-then-bind].
- **Dynamic Test**:
  ```
  # Auth-bypass payload example
  curl -X POST https://app.example.com/login \
       -d 'username=admin)(%26(password=*)&password=anything'
  # Expected signal: login succeeds or returns admin-only data without a valid password
  ```
```

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 construction sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file.
- **Phase 1 is purely structural**: flag any dynamic variable embedded into an LDAP filter, DN, search base, or attribute position, regardless of origin. Do not trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint + context analysis**: for each assigned site, trace the interpolated variable back to its origin AND verify the mitigation matches the context (filter-escape for filter, DN-escape for DN, allowlist for attribute name).
- Filter meta-characters are `(` `)` `*` `\` NUL (RFC 4515). DN meta-characters are `,` `=` `+` `<` `>` `#` `;` `\` `"` (RFC 4514). These sets are NOT interchangeable — a filter escape is not a DN escape and vice versa.
- The canonical auth-bypass payload to keep in mind: `username=admin)(&(password=*)` against a filter `(&(uid=<USER>)(password=<PASS>))`.
- Wildcard enumeration via unescaped `*` is a real LDAP-injection finding even without Boolean-tree tampering — do not dismiss it as "just enumeration".
- Dynamic attribute names cannot be fixed with escape helpers — only an allowlist protects that position. Flag any dynamic attribute name without an allowlist.
- DN concatenation used for `bind()` is especially dangerous — prefer search-then-bind. A concatenated bind DN with only filter-escape is still vulnerable.
- StartTLS / `ldaps://` status is context, not a classification — note it but don't let its absence promote a non-injection finding to "Vulnerable" here; that belongs to a transport-security skill.
- Second-order LDAP injection is easy to miss — user input stored earlier (in the DB or the directory itself) may later be read and placed into a filter/DN without re-escaping. Trace DB-read values back to their original write site.
- Custom escape functions (regex strippers, `addslashes`, HTML/URL encoders, or partial replacers) are **not** equivalent to RFC 4515 / RFC 4514 escaping — classify as Likely Vulnerable even if such a helper is present.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete `sast/ldap-recon.md` and all `sast/ldap-batch-*.md` files after the final `sast/ldap-results.md` and `sast/ldap-results.json` are written.
