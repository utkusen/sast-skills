---
name: sast-nosql
description: >-
  Detect NoSQL injection vulnerabilities in a codebase using a three-phase
  approach: recon (find query construction sites on MongoDB, Firestore,
  DynamoDB, CouchDB, etc.), batched verify (trace user input and operator
  shape validation in parallel subagents, 3 sites each), and merge
  (consolidate batch results). Covers operator injection ($gt, $ne, $where,
  $regex, $expr), Mongoose schema bypass, Firestore path injection, and
  DynamoDB expression concatenation. Requires sast/architecture.md (run
  sast-analysis first). Outputs findings to sast/nosql-results.md and
  sast/nosql-results.json. Use when asked to find NoSQL injection, MongoDB
  operator injection, or document-store query bugs.
version: 0.1.0
---

# NoSQL Injection Detection

You are performing a focused security assessment to find NoSQL injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find query construction sites), **batched verify** (taint + shape analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is NoSQL Injection

NoSQL injection occurs when user-supplied input — typically an object rather than a string — reaches a document-store query without being validated for type or shape. Unlike SQL injection, the attack vector is not always a string payload. In many NoSQL engines, particularly MongoDB, the query filter is itself a structured document, and an attacker who can plant operator keys (`$gt`, `$ne`, `$where`, `$regex`, `$expr`) inside that document can fundamentally alter the query semantics — bypassing authentication, enumerating records, or even triggering server-side JavaScript execution.

The core pattern: *unvalidated user input, whose type or shape is not constrained to what the query expects, reaches a NoSQL query execution call.*

The canonical example is Express with `body-parser` or Express 4.16+ built-in parsers: `req.body.username` is whatever the client sent. If the client sends `{"username": {"$ne": null}, "password": {"$ne": null}}` with a JSON content type, then `req.body.username` is the object `{$ne: null}`, not a string. Passing it straight into `User.findOne({ username: req.body.username, password: req.body.password })` produces a MongoDB filter that matches any user whose username and password are not null — classic auth bypass.

### What NoSQL Injection IS

- **Operator injection**: user input that should be a scalar is an object containing MongoDB operators — `{$ne: null}`, `{$gt: ""}`, `{$regex: ".*"}`, `{$in: [...]}`, `{$exists: true}`
- **`$where` with user input**: MongoDB's `$where` clause accepts a JavaScript function or string executed server-side by the MongoDB engine; concatenating user input into `$where` is equivalent to RCE on the database
- **`$expr` with user input**: allows aggregation operators inside a query filter; uncontrolled user keys can pivot the query shape
- **Mongoose schema bypass**: passing an object where a `String` field is defined, when `strictQuery` is disabled, lets operator keys flow through
- **Firestore path injection**: building a document reference path from user input — `db.collection('users').doc(req.params.id)` where `id` contains `../` or collection segments
- **DynamoDB expression concatenation**: building `FilterExpression`, `KeyConditionExpression`, or `ConditionExpression` strings from user input instead of using `ExpressionAttributeValues`
- **CouchDB / Mango query injection**: passing user-controlled objects into `db.find({ selector: userInput })` without shape validation
- **Aggregation pipeline injection**: user input controls stages of `db.collection.aggregate([...])` — e.g., `$match`, `$lookup`, `$out`

### What NoSQL Injection is NOT

Do not flag these as NoSQL injection:

- **SQL injection**: string concatenation into a relational SQL query — that is SQLi, a separate class. NoSQL injection is distinguished by the fact that the *shape* of input matters, not just its string contents.
- **LDAP injection**: filter operators like `(&(uid=*)(userPassword=*))` — different grammar, different class.
- **XSS**: a `<script>` tag stored in a Mongo document and later rendered to HTML without escaping — that is stored XSS, not NoSQL injection.
- **IDOR**: changing `?userId=1` to `?userId=2` to access another user's document when the code already validates the ID as a string. If the query is parameterized correctly and only the reference is guessable, that is IDOR.
- **Mass assignment**: spreading `req.body` into `new User(req.body)` so an attacker sets `isAdmin: true` — different vulnerability (mass assignment / over-posting).
- **Safe driver calls with scalars**: `User.findOne({ _id: new ObjectId(req.params.id) })` where the ID is validated as a string and cast via `ObjectId`. The cast throws on malformed input and forces scalar shape.
- **Prototype pollution**: setting `__proto__` keys to corrupt Object.prototype — related attack surface but classified separately.

### Patterns That Prevent NoSQL Injection

When you see these patterns, the code is likely **not vulnerable**:

**1. Strict type validation before the query**
```javascript
// Explicit string check — rejects objects
if (typeof req.body.username !== 'string' || typeof req.body.password !== 'string') {
  return res.status(400).send('bad input');
}
await User.findOne({ username: req.body.username, password: req.body.password });
```

```python
# Python — explicit isinstance check
if not isinstance(username, str) or not isinstance(password, str):
    abort(400)
users_col.find_one({'username': username, 'password': password})
```

**2. Schema validation with Mongoose (strict by default)**
```javascript
// Schema declares username as String, strictQuery is on (Mongoose 7+ default)
const UserSchema = new Schema({ username: String, password: String });
const User = model('User', UserSchema);
// Operator objects in the filter are coerced/rejected for defined String paths
// under strictQuery in most configurations.
await User.findOne({ username: req.body.username });
```
Note: Mongoose `strictQuery` prevents unknown paths, but it does **not** automatically coerce `{$ne: null}` to a string — you still need casting or a string check. The protection comes from Schema `cast` behavior on typed paths, which throws when a non-string shape reaches a `String` path in most versions.

**3. Joi / Zod / Ajv schema validation at the request boundary**
```javascript
const schema = z.object({ username: z.string(), password: z.string() });
const { username, password } = schema.parse(req.body);  // throws on non-string
await User.findOne({ username, password });
```

**4. Parameterization via ODM query builders, not raw objects**
```javascript
// Mongoose — chaining with typed setters
await User.find().where('username').equals(req.body.username);
```

**5. Allowlist for fields and operators when dynamic queries are unavoidable**
```javascript
const ALLOWED_SORT = new Set(['createdAt', 'price']);
const sort = ALLOWED_SORT.has(req.query.sort) ? req.query.sort : 'createdAt';
```

**6. Forbid `$where` with user input, period**
- `$where` runs JavaScript on the MongoDB server. There is no safe way to use it with user input. If you see `$where` and any dynamic value, it is at minimum Likely Vulnerable.

**7. Firestore — validate document IDs against a known shape before `.doc(id)`**
```javascript
if (!/^[a-zA-Z0-9_-]{20}$/.test(req.params.id)) return res.sendStatus(400);
db.collection('users').doc(req.params.id);
```

**8. DynamoDB — use `ExpressionAttributeValues`, never concatenate**
```javascript
client.scan({
  TableName: 'Users',
  FilterExpression: '#u = :u',
  ExpressionAttributeNames: { '#u': 'username' },
  ExpressionAttributeValues: { ':u': username },
});
```

---

## Vulnerable vs. Secure Examples

### Node.js — Mongoose (login bypass via `$ne`)

```javascript
// VULNERABLE: Express JSON body parser preserves object shape.
// An attacker POSTs {"username": {"$ne": null}, "password": {"$ne": null}}
// and req.body.username is the object {$ne: null}, not a string.
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });
  if (user) return res.json({ ok: true, token: sign(user) });
  res.status(401).end();
});

// SECURE: strict type check at the boundary
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).send('bad input');
  }
  const user = await User.findOne({ username, password });
  if (user) return res.json({ ok: true, token: sign(user) });
  res.status(401).end();
});
```

### Node.js — MongoDB native driver (`$regex` enumeration)

```javascript
// VULNERABLE: client sends {"search": {"$regex": "^a"}} to enumerate usernames
app.post('/users/search', async (req, res) => {
  const results = await db.collection('users').find({ username: req.body.search }).toArray();
  res.json(results);
});

// SECURE: enforce shape and escape any characters that would be treated as regex metachars
const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
app.post('/users/search', async (req, res) => {
  const search = req.body.search;
  if (typeof search !== 'string' || search.length > 64) return res.sendStatus(400);
  const results = await db.collection('users')
    .find({ username: { $regex: '^' + escapeRe(search), $options: 'i' } })
    .limit(50).toArray();
  res.json(results);
});
```

### Node.js — `$where` (server-side JS execution, effectively RCE on the DB)

```javascript
// VULNERABLE: user input concatenated into a JavaScript expression that runs
// inside the MongoDB server. Injection becomes RCE against the DB process.
app.get('/search', async (req, res) => {
  const threshold = req.query.minAge;
  const users = await db.collection('users').find({
    $where: `this.age > ${threshold}`,
  }).toArray();
  res.json(users);
});
// Payload: ?minAge=0;return%20true  =>  `this.age > 0;return true` matches all docs.
// Payload: ?minAge=0;while(1){}      =>  denial of service.

// SECURE: do not use $where with user input. Use a typed comparison.
app.get('/search', async (req, res) => {
  const minAge = Number.parseInt(req.query.minAge, 10);
  if (!Number.isFinite(minAge)) return res.sendStatus(400);
  const users = await db.collection('users').find({ age: { $gt: minAge } }).toArray();
  res.json(users);
});
```

### Node.js — `$expr` with user-controlled operator

```javascript
// VULNERABLE: the client picks which aggregation operator runs
app.post('/compare', async (req, res) => {
  const { op, a, b } = req.body;  // op e.g. "$gt", a/b field references
  const rows = await db.collection('items').find({
    $expr: { [op]: ['$' + a, '$' + b] },
  }).toArray();
  res.json(rows);
});

// SECURE: allowlist operator and fields
const OP_ALLOW = new Set(['$gt', '$gte', '$lt', '$lte', '$eq']);
const FIELD_ALLOW = new Set(['price', 'stock', 'discount']);
app.post('/compare', async (req, res) => {
  const { op, a, b } = req.body;
  if (!OP_ALLOW.has(op) || !FIELD_ALLOW.has(a) || !FIELD_ALLOW.has(b)) {
    return res.sendStatus(400);
  }
  const rows = await db.collection('items').find({
    $expr: { [op]: ['$' + a, '$' + b] },
  }).toArray();
  res.json(rows);
});
```

### Mongoose — strict schema blocks the attack

```javascript
// With a Mongoose schema declaring username: String, Mongoose's cast layer
// will throw a CastError when it sees {$ne: null} for that path in most
// configurations, turning the attempted injection into a 500/400 instead of
// a silent auth bypass. Do not rely on this alone — combine with explicit
// type checks — but recognize it as a mitigating factor.
const UserSchema = new Schema({ username: String, password: String });
const User = model('User', UserSchema);
try {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });
} catch (e) {
  if (e.name === 'CastError') return res.status(400).send('bad input');
  throw e;
}
```

### Firestore — dynamic field paths and document IDs

```javascript
// VULNERABLE: attacker controls the document path. Firestore accepts any
// non-empty string as a doc ID and the app exposes whatever it reads.
app.get('/doc', async (req, res) => {
  const docRef = db.collection('public').doc(req.query.id);
  const snap = await docRef.get();
  res.json(snap.data());
});

// VULNERABLE: user-controlled field path in a where() clause
app.get('/search', async (req, res) => {
  const field = req.query.field;  // e.g. "__name__" or a private field
  const value = req.query.value;
  const snap = await db.collection('users').where(field, '==', value).get();
  res.json(snap.docs.map(d => d.data()));
});

// SECURE: validate ID shape and allowlist queryable fields
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const FIELD_ALLOW = new Set(['name', 'city']);
app.get('/search', async (req, res) => {
  const { id, field, value } = req.query;
  if (id !== undefined && !ID_RE.test(id)) return res.sendStatus(400);
  if (!FIELD_ALLOW.has(field)) return res.sendStatus(400);
  if (typeof value !== 'string') return res.sendStatus(400);
  const snap = await db.collection('users').where(field, '==', value).get();
  res.json(snap.docs.map(d => d.data()));
});
```

### DynamoDB — FilterExpression / ConditionExpression concatenation

```javascript
// VULNERABLE: user input concatenated into a FilterExpression string.
// Attacker sends `active' OR username = 'admin` and the expression parses as
// a compound filter instead of an equality on `status`.
const out = await ddb.scan({
  TableName: 'Users',
  FilterExpression: `status = '${req.query.status}'`,
}).promise();

// VULNERABLE: ConditionExpression built from user input — can bypass
// optimistic-lock style guards.
await ddb.updateItem({
  TableName: 'Items',
  Key: { id: { S: req.body.id } },
  UpdateExpression: 'SET #n = :n',
  ConditionExpression: `version = ${req.body.expectedVersion}`,
  ExpressionAttributeNames: { '#n': 'name' },
  ExpressionAttributeValues: { ':n': { S: req.body.name } },
}).promise();

// SECURE: use placeholders via ExpressionAttributeValues and ExpressionAttributeNames.
const out = await ddb.scan({
  TableName: 'Users',
  FilterExpression: '#s = :s',
  ExpressionAttributeNames: { '#s': 'status' },
  ExpressionAttributeValues: { ':s': { S: req.query.status } },
}).promise();
```

### Python — pymongo (operator injection)

```python
# VULNERABLE: Flask's request.get_json() preserves dict shape. Attacker sends
# {"username": {"$ne": null}, "password": {"$ne": null}} to bypass auth.
@app.post('/login')
def login():
    data = request.get_json()
    user = users.find_one({
        'username': data['username'],
        'password': data['password'],
    })
    if user:
        return jsonify(ok=True)
    abort(401)

# SECURE: explicit type enforcement at the boundary
@app.post('/login')
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not isinstance(username, str) or not isinstance(password, str):
        abort(400)
    user = users.find_one({'username': username, 'password': password})
    if user:
        return jsonify(ok=True)
    abort(401)
```

### Python — `$where` with pymongo

```python
# VULNERABLE: server-side JS execution on Mongo
def search(min_age):
    return list(db.users.find({'$where': f'this.age > {min_age}'}))

# SECURE: typed comparison
def search(min_age):
    return list(db.users.find({'age': {'$gt': int(min_age)}}))
```

### CouchDB / Mango

```javascript
// VULNERABLE: client-supplied selector is passed straight through; attacker
// can add fields (including _id patterns) or exfiltrate via $regex.
const rows = await db.find({ selector: req.body.selector });

// SECURE: build the selector from validated scalar values
const selector = { type: 'user' };
if (typeof req.body.name === 'string') selector.name = req.body.name;
const rows = await db.find({ selector });
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Query Construction Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a NoSQL query is constructed with any variable in the filter, update, or pipeline — regardless of where the variable comes from. Write results to `sast/nosql-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to identify the NoSQL engine(s) in use (MongoDB, Mongoose, Firestore, DynamoDB, CouchDB, Realm, Cosmos DB), the driver versions, and how request bodies are parsed.
>
> **What to search for — query construction call sites**:
>
> 1. **MongoDB native driver / Mongoose / Cosmos DB Mongo API**:
>    - `.find(`, `.findOne(`, `.findOneAndUpdate(`, `.findOneAndDelete(`, `.findOneAndReplace(`
>    - `.aggregate(`, `.distinct(`, `.count(`, `.countDocuments(`, `.estimatedDocumentCount(`
>    - `.update(`, `.updateOne(`, `.updateMany(`, `.replaceOne(`
>    - `.deleteOne(`, `.deleteMany(`, `.remove(`
>    - `.bulkWrite(`
>    - Any filter object literal that contains `$where`, `$expr`, `$regex`, `$function`, `$accumulator`
>    - `db.eval(`, `.runCommand(` with user data
>    - Mongoose: `.where(`, `.equals(`, `.gte(`, `.in(`, raw `Model.collection.find(...)`
>
> 2. **Firestore**:
>    - `.collection(varOrTemplate)`, `.doc(varOrTemplate)`
>    - `.where(fieldVar, op, value)` where `fieldVar` is not a hardcoded string
>    - `.orderBy(varField)`
>    - `getDoc(doc(db, varPath))`
>
> 3. **DynamoDB (AWS SDK v2 and v3)**:
>    - `scan`, `query`, `updateItem`, `deleteItem`, `getItem`, `putItem`, `batchWriteItem`, `transactWriteItems`
>    - Any `FilterExpression`, `KeyConditionExpression`, `ConditionExpression`, `UpdateExpression`, `ProjectionExpression` that is built with string concatenation / template literals rather than static strings with `ExpressionAttributeValues`
>
> 4. **CouchDB / PouchDB / Cloudant**:
>    - `db.find({ selector: ... })`
>    - Mango queries built from user input
>    - `_all_docs` with user-controlled keys
>
> 5. **Generic / ODM-specific**:
>    - TypeORM Mongo: `.findBy`, `.findOneBy`, `createQueryBuilder().where(...)`
>    - Prisma MongoDB provider: `prisma.model.findMany({ where: userInput })`
>    - Realm: `realm.objects(Class).filtered(string)` with dynamic string
>
> **What to flag — any of the following is a construction site worth Phase 2 analysis**:
>
> - The filter/update/pipeline argument is an object that contains a variable (not a literal scalar string/number)
> - The expression string (DynamoDB) is built with concatenation, `+`, template literals, or string `.format`
> - A field name, collection name, or document ID is interpolated from a variable
> - `$where`, `$expr`, `$regex`, `$function`, or `$accumulator` appears anywhere
> - An entire `where:` / `selector:` / `filter:` object comes from a variable (e.g., `req.body`)
>
> **What to skip** (safe by construction):
>
> - Filters composed only of literal scalars: `db.collection('users').findOne({ status: 'active' })`
> - `_id` lookups where the ID is explicitly validated or cast via `new ObjectId(...)` in a try/catch
> - DynamoDB calls using `ExpressionAttributeValues` / `ExpressionAttributeNames` with static expression strings
> - Firestore `.doc('config/global')` with fully hardcoded paths
>
> **Output format** — write to `sast/nosql-recon.md`:
>
> ```markdown
> # NoSQL Recon: [Project Name]
>
> ## Summary
> Found [N] query construction sites that use variables in the filter / expression / path.
>
> ## Construction Sites
>
> ### 1. [Descriptive name — e.g., "Login query passes req.body straight to findOne"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Engine**: [MongoDB / Mongoose / Firestore / DynamoDB / CouchDB / ...]
> - **Operation**: [findOne / find / aggregate / updateMany / scan / ...]
> - **Construction pattern**: [object literal with var / whole filter from variable / $where with string concat / field path from variable / DynamoDB expression concat]
> - **Risky operators present**: [$where / $expr / $regex / none]
> - **Interpolated variable(s)**: `var_name` — [brief note on apparent origin]
> - **Code snippet**:
>   ```
>   [the query construction call]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/nosql-recon.md`. If the recon found **zero construction sites** (summary reports "Found 0" or the section is empty or absent), **skip Phase 2 entirely**. Instead, write the following to `sast/nosql-results.md`:

```markdown
# NoSQL Analysis Results

No vulnerabilities found.
```

Also write the canonical JSON at `sast/nosql-results.json`:

```json
{ "findings": [] }
```

Then stop.

Only proceed to Phase 2 if Phase 1 found at least one construction site.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/nosql-recon.md` and split the construction sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent traces user input and checks for shape validation only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/nosql-recon.md` and count the numbered site sections under "Construction Sites".
2. Divide into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections.
4. Launch all batch subagents **in parallel**, passing each only its assigned sites.
5. Each subagent writes to `sast/nosql-batch-N.md`.
6. Identify the project's NoSQL engine(s) from `sast/architecture.md` and select only the matching examples from the "Vulnerable vs. Secure Examples" section above. Include those in each subagent's instructions where marked `[ENGINE EXAMPLES]`.

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: For each assigned construction site, determine whether user-supplied input can reach the query filter / expression / path, AND whether any shape validation (type check, schema, ODM cast, allowlist) effectively prevents operator injection. Write results to `sast/nosql-batch-[N].md`.
>
> **Your assigned construction sites**:
>
> [Paste full text of assigned sections here, preserving numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, body parsers (Express `express.json()`, Fastify, Koa, Flask `request.get_json()`, etc.), middleware, and ODM configuration.
>
> **NoSQL taint analysis — trace the variable(s) AND check the shape**:
>
> Unlike SQL injection, NoSQL injection is a *shape* problem as much as a taint problem. Even if you can prove user input reaches the query, the finding is only exploitable if that input can be an **object containing operator keys**. Perform both checks.
>
> **Step 1 — trace the variable backwards to its origin**:
>
> 1. **Direct user input**: `req.body.*`, `req.query.*`, `req.params.*`, `req.headers.*`, `req.cookies.*`, `request.get_json()`, `request.args`, `request.form`, `request.values`, path params, GraphQL arguments.
> 2. **Indirect**: assigned from a helper, pulled from session state that was populated from user input, passed through middleware that didn't sanitize.
> 3. **Second-order**: read from the DB but originally stored from user input.
> 4. **Server-side only**: constants, env vars, server-generated IDs — not exploitable.
>
> **Step 2 — check whether input shape is constrained to scalar**:
>
> - `typeof x === 'string'` (JS) / `isinstance(x, str)` (Py) before use: **blocks operator injection**
> - Zod `.string()`, Joi `Joi.string()`, Ajv `{ type: 'string' }`, class-validator `@IsString()`, Pydantic `str` field: **blocks it**
> - Mongoose Schema with a typed path (`String`, `Number`, `ObjectId`) + default `strictQuery` + cast not disabled: **mostly blocks it**; flag as Likely Vulnerable if no explicit type check and architecture notes any history of disabling strict/cast
> - Cast via `new ObjectId(x)` inside try/catch: blocks it for `_id`
> - Custom validator that only checks length or regex-on-string: does NOT block it if the validator runs `.length` or `.match` — those can still receive an object and produce truthy/false results; flag as Likely Vulnerable
> - No validation at all: **vulnerable**
>
> **Step 3 — recognize high-risk operator usage even with partial mitigation**:
>
> - `$where` + any dynamic value: Likely Vulnerable at minimum, Vulnerable if user-controlled
> - `$expr` with user-controlled operator keys or field references: Vulnerable
> - `$regex` built from unescaped user input: Vulnerable (ReDoS / enumeration / match-all)
> - Entire filter object from `req.body` (`Model.find(req.body)`): Vulnerable — any key is attacker-chosen
> - Firestore `.doc(userInput)` without ID shape check: Likely Vulnerable
> - DynamoDB expression string built via concat/template literal: Vulnerable
>
> **Mitigations that DO NOT count**:
>
> - Client-side validation only
> - `.toString()` on an object — `({$ne:null}).toString()` is `"[object Object]"` but many code paths bypass coercion; does not reliably prevent operator injection when the value is used as-is in a filter
> - Blacklists of specific operator names — easily bypassed
> - `JSON.parse(JSON.stringify(x))` — preserves operator keys
>
> **Vulnerable vs. Secure examples for this project's engine(s)**:
>
> [ENGINE EXAMPLES]
>
> **Classification**:
>
> - **Vulnerable**: user input demonstrably reaches the filter with no shape validation, OR `$where`/`$expr` is concatenated with user input, OR DynamoDB expression is string-built from user input, OR entire filter object comes from `req.body` without pruning.
> - **Likely Vulnerable**: user input probably reaches it (indirect flow or partial validation only), OR Mongoose schema is the only guard and no explicit type check, OR Firestore ID used without shape check.
> - **Not Vulnerable**: input is server-side only, OR strict type check / Zod / Joi / Pydantic enforces scalar shape before the query, OR `ObjectId` cast gates the value, OR static expression with `ExpressionAttributeValues`.
> - **Needs Manual Review**: origin or shape constraint cannot be determined from the code alone.
>
> **Output format** — write to `sast/nosql-batch-[N].md`:
>
> ```markdown
> # NoSQL Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Engine / operation**: [MongoDB findOne / Firestore doc() / DynamoDB scan / ...]
> - **Issue**: [e.g., "req.body.username flows into findOne filter without type check; operator injection enables auth bypass"]
> - **Taint trace**: [step-by-step entry -> query]
> - **Shape check**: [none / weak / strong — be specific about what was or wasn't found]
> - **Impact**: [auth bypass / data enumeration / DoS via $where / RCE on DB server / data leak across tenant]
> - **Remediation**: [add typeof check, Zod schema, cast, switch to placeholders, drop $where]
> - **Dynamic Test**:
>   ```
>   [curl payload — show the injection JSON and expected response signal.
>    Example:
>      curl -X POST https://app.example.com/login \
>        -H 'content-type: application/json' \
>        -d '{"username": {"$ne": null}, "password": {"$ne": null}}'
>      Expect: 200 OK with a session token instead of 401.]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [indirect flow or partial-only mitigation]
> - **Taint trace**: [best-effort trace with uncertainties marked]
> - **Concern**: [why it remains a risk — e.g., Mongoose cast can be bypassed when strictQuery is off]
> - **Remediation**: [add explicit type check at the boundary]
> - **Dynamic Test**:
>   ```
>   [payload to attempt]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [Zod string schema / typeof guard / ObjectId cast / server-side constant / static DynamoDB expression]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [what could not be determined]
> - **Suggestion**: [what to trace or test manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/nosql-batch-*.md` file and merge them into a single `sast/nosql-results.md` and the canonical `sast/nosql-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read every `sast/nosql-batch-1.md`, `sast/nosql-batch-2.md`, ... file.
2. Collect all findings into one list, preserving classification and all detail fields.
3. Count totals across all batches.
4. Write the merged report to `sast/nosql-results.md`.
5. Also emit the machine-readable `sast/nosql-results.json` with a `findings` array. Severity guidance:
   - `$where` with user input, or `Model.find(req.body)` wholesale: **critical**
   - Operator injection leading to auth bypass: **critical**
   - Operator injection leading to data enumeration or cross-tenant read: **high**
   - DynamoDB expression concat enabling filter bypass: **high**
   - Firestore path injection: **high**
   - `$regex` DoS / enumeration without auth bypass: **medium**
   - Likely Vulnerable (partial mitigation): **medium**
   - Needs Manual Review: **info** or **low**
6. After writing both files, **delete all intermediate batch files** (`sast/nosql-batch-*.md`) and `sast/nosql-recon.md`.

**Markdown report format** (`sast/nosql-results.md`):

```markdown
# NoSQL Analysis Results: [Project Name]

## Executive Summary
- Construction sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings grouped by classification: VULNERABLE first, then LIKELY
VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE. Preserve every
field from the batch results verbatim.]
```

**JSON format** (`sast/nosql-results.json`):

```json
{
  "findings": [
    {
      "id": "nosql-1",
      "skill": "sast-nosql",
      "severity": "critical",
      "title": "Login endpoint vulnerable to MongoDB operator injection",
      "description": "req.body.username and req.body.password flow unchecked into User.findOne, allowing {$ne: null} payloads to bypass authentication.",
      "location": { "file": "src/routes/auth.js", "line": 42, "column": 5 },
      "remediation": "Enforce typeof === 'string' on username and password before the query, or validate req.body with a Zod/Joi string schema."
    }
  ]
}
```

If no findings exist, still write `{ "findings": [] }` so the aggregator can verify the scan ran.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to every subagent as context. Note in particular which NoSQL engine is in use, the body parser configuration (`express.json()` etc.), and any global validation middleware.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete.
- Batch size is **3 construction sites per subagent**. 1-3 sites → one subagent. 10 sites → 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — never sequentially.
- Each batch subagent receives only its assigned sites' text, not the full recon file. Keep context small and focused.
- **Phase 1 is purely structural**: flag any dynamic variable in a query filter / expression / path. Do not trace user input in Phase 1.
- **Phase 2 is taint + shape analysis**: trace the variable AND verify whether the shape is constrained to a scalar.
- The fundamental NoSQL-injection insight: in Express (and Koa, Fastify, Hapi, Flask `get_json()`, etc.), `req.body.x` is whatever the JSON parser produced — often an object. A `typeof` check is cheap and mandatory. Missing that check on any `req.body.*` that reaches a filter is a finding.
- `$where` with any dynamic value is at minimum Likely Vulnerable. With user input it is Vulnerable and functionally RCE on the MongoDB server.
- Mongoose `strictQuery` + schema typing helps but is not a complete defense on its own. In older Mongoose versions `strictQuery` defaulted to `false`; in Mongoose 7+ the default flipped. Check `mongoose.set('strictQuery', ...)` calls and the Mongoose version in `package.json`.
- Firestore document IDs are flexible strings — validate shape with a tight regex before calling `.doc(id)`.
- DynamoDB FilterExpression / ConditionExpression / KeyConditionExpression / UpdateExpression must be built from static strings with `ExpressionAttributeValues` and `ExpressionAttributeNames`. Any concatenation is a finding.
- Do NOT classify a standard IDOR as NoSQL injection. If the query is shape-safe (`{ _id: new ObjectId(req.params.id) }`) but lacks an ownership check, that is IDOR — route it to `sast-idor` instead.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files after the final results files are written: delete `sast/nosql-recon.md` and all `sast/nosql-batch-*.md`.
