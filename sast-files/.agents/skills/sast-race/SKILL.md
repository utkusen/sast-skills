---
name: sast-race
description: >-
  Detect race condition vulnerabilities in a codebase using a three-phase
  approach: recon (find read-modify-write and TOCTOU sites), batched verify
  (check atomicity in parallel subagents, 3 sites each), and merge
  (consolidate batch results). Covers balance/coupon double-spend, file
  TOCTOU, auth time-of-check/time-of-use, duplicate webhook processing,
  missing optimistic concurrency, and Node.js async/await races.
  Requires sast/architecture.md (run sast-analysis first). Outputs findings
  to sast/race-results.md. Use when asked to find race conditions, TOCTOU,
  or concurrency bugs with security impact.
version: 0.1.0
---

# Race Condition Vulnerability Detection

You are performing a focused security assessment to find race condition vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find read-modify-write and TOCTOU sites), **batched verify** (check whether each site is atomic under concurrency in parallel batches of 3), and **merge** (consolidate batch results).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is a Race Condition

A race condition is a security vulnerability where two (or more) operations on shared state interleave non-atomically, producing a security-relevant outcome that would be impossible if the operations were serialized. The attacker does not exploit a single request in isolation — they exploit the *gap* between two reads, or between a check and the action that depends on it.

The core pattern is always the same: *the application reads a value, makes a decision based on that value, and then acts — but another request modifies the same value inside that window, invalidating the decision.*

Typical security outcomes include:

- **Duplicate spend**: a balance check passes for two concurrent withdrawals, but only one decrement is recorded, so the user withdraws twice.
- **Coupon double-redeem**: a single-use coupon is validated by two concurrent redemptions before either marks it used.
- **File TOCTOU bypass**: the application checks a path with `stat`, it looks benign, then opens it — but between the two syscalls an attacker swaps it for a symlink to `/etc/shadow`.
- **Auth time-of-check vs time-of-use**: a session is validated at request start and an action runs seconds later using a privilege that has since been revoked, but never re-checked.
- **Inventory oversell**: two buyers each see "1 in stock", both succeed, and stock becomes -1.
- **Duplicate webhook processing**: a provider retries a webhook; two handlers run concurrently and both fire the downstream effect (payout, email, mint).

### What Race Conditions ARE

- Two concurrent `POST /transfer` requests that both pass the `balance >= amount` check against the same starting balance, and both decrement it — resulting in a total decrement larger than the balance allowed.
- A coupon redemption endpoint that does `SELECT used FROM coupons WHERE code = ?`, branches on the result in Python/Node/Ruby, then `UPDATE coupons SET used = true` — racing the select with itself.
- A webhook handler that does `SELECT * FROM processed_events WHERE event_id = ?` and, if missing, inserts and fires a side effect — without a unique constraint on `event_id` or a transactional `INSERT ... ON CONFLICT DO NOTHING`.
- A file upload validator that calls `os.stat(path)` to check size/permissions, then `open(path)` — allowing a symlink swap between the two calls.
- A Node.js in-memory counter incremented across `await` boundaries without a mutex, where two concurrent requests each read `counter`, both increment, and write back the same value.
- A password reset token consumer that checks `token.used === false` in one query and sets `token.used = true` in a later, separate query.
- A session rotation flow that reads the old session, creates a new one, and deletes the old — without wrapping the three operations in a transaction, leaving a window where both are valid or neither is.
- An `await`-separated check-then-act where `if (await isAllowed(user))` passes, then `await performAction()` executes, but the user's permission was revoked between the two awaits.

### What Race Conditions are NOT

Do not flag these as race conditions:

- **Missing authentication / authorization**: If the check is missing entirely, that's an auth bug, not a race. Races require a *correct-looking* check that is defeated by interleaving.
- **Plain business logic flaws**: Sending a negative `amount` that bypasses validation is a business-logic bug, not a race — it works with a single request.
- **Injection**: SQLi, SSRF, XSS, RCE and friends are separate skills, even if the sink sits next to a race-prone flow.
- **Generic non-determinism / flakiness**: A test that sometimes fails because of I/O ordering, without a security consequence, is not a race condition vulnerability.
- **Pure data corruption without a security impact**: A duplicate log line, a harmless counter drift, or a lost update to a non-security field is a bug but not in scope for this skill.
- **Front-end double-click**: If the backend properly deduplicates, the client-side double-click spinner issue is UX, not security.

A race is in scope only when *both* conditions hold: (1) two or more operations interleave non-atomically on shared state, and (2) the interleaving yields a security-relevant outcome — money moved that shouldn't move, a token reused, a privilege kept after revocation, a file read that should have been denied.

### Patterns That Prevent Race Conditions

These are the building blocks to look for during verification. If the code uses one of these correctly around the check-and-act window, the race is typically mitigated.

- **Database transactions with `SELECT ... FOR UPDATE`**: Acquire a row lock at read time so concurrent transactions block until commit. Required for any "read balance, decide, write balance" flow on the same row.
- **Serializable isolation level**: `SET TRANSACTION ISOLATION LEVEL SERIALIZABLE` makes the database detect and abort conflicting transactions. Correct when combined with retry logic.
- **Atomic conditional update**: Skip the read-modify-write entirely — use `UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt` and check affected-row count. If 0 rows were updated, the transfer failed. This is the strongest pattern for balances and counters.
- **Atomic counters / `UPDATE ... RETURNING`**: `UPDATE inventory SET stock = stock - 1 WHERE id = ? AND stock > 0 RETURNING stock` — single-statement check-and-decrement.
- **Optimistic concurrency via version column or ETag**: `UPDATE ... WHERE id = ? AND version = :v` with version bump. If `UPDATE` affects 0 rows, another writer won and the client must retry. HTTP analog: `If-Match: <etag>` with 412 Precondition Failed.
- **Database unique constraints + `INSERT ... ON CONFLICT DO NOTHING`**: Lets the database enforce "at most one" for idempotency keys, webhook IDs, coupon-redemption pairs, etc.
- **Redis `WATCH` / `MULTI` / `EXEC`**: Optimistic transaction — `WATCH key`, read, build a `MULTI` block, and `EXEC`. If the key changed since `WATCH`, `EXEC` returns nil and the client retries. Correct pattern for Redis-backed balances and rate counters.
- **Redis `SET key value NX PX ttl` for locks**: Single-atomic lock acquisition with expiry to avoid deadlock. Must be paired with a release-only-if-owned Lua script.
- **Idempotency keys**: Client supplies an `Idempotency-Key` header; server stores it with the response. Subsequent requests with the same key return the stored response instead of re-executing. Critical for payments (Stripe model).
- **`O_EXCL | O_CREAT` on file create**: Atomic "create if not exists" — fails if the file already exists, closing the create/open TOCTOU window.
- **`fstat(fd)` on the opened file descriptor**: Instead of `stat(path)` then `open(path)`, open first and call `fstat` on the returned fd. Guarantees the check and the use refer to the same inode, immune to path-based swaps.
- **`openat(dirfd, ..., O_NOFOLLOW)`**: Open relative to a directory fd and refuse symlinks at the final component — closes path-based swap races during file access.
- **Mutex / semaphore around the critical section**: In-process primitive for in-memory shared state (Python `threading.Lock`, Node.js `async-mutex`, Go `sync.Mutex`). Only effective when the shared state lives in a single process.
- **Monotonic state machine with guarded transitions**: Encode transitions as SQL `UPDATE ... WHERE status = 'pending'` so moving to a terminal state can happen at most once.
- **Queue-based single-writer serialization**: Funnel all writes for a given key through a single worker (e.g. partitioned Kafka consumer, per-user job queue) so there is no cross-process concurrency to race on.

The absence of all of these in a read-modify-write or check-then-use flow against security-relevant state is the signal we are looking for.

---

## Vulnerable vs. Secure Examples

Each example shows the vulnerable pattern first, then the secure fix. The exact syntax is for illustration — the *shape* of the pattern is what verification should match on.

### 1. Balance transfer: SELECT-then-UPDATE vs atomic UPDATE

**Vulnerable** — read balance, branch, update:

```python
def transfer(user_id, amount):
    acc = db.fetchone("SELECT balance FROM accounts WHERE id = %s", (user_id,))
    if acc["balance"] < amount:
        raise InsufficientFunds()
    db.execute("UPDATE accounts SET balance = balance - %s WHERE id = %s",
               (amount, user_id))
```

Two concurrent calls both read balance = 100, both see 100 >= 80, both run `UPDATE balance = balance - 80`, ending at -60.

**Secure** — atomic conditional update with affected-row check:

```python
def transfer(user_id, amount):
    rows = db.execute(
        "UPDATE accounts SET balance = balance - %s "
        "WHERE id = %s AND balance >= %s",
        (amount, user_id, amount),
    )
    if rows.rowcount == 0:
        raise InsufficientFunds()
```

Equally acceptable: `SELECT ... FOR UPDATE` inside a transaction, followed by the read-modify-write.

### 2. Coupon redemption: check used then mark used

**Vulnerable**:

```js
const coupon = await db.query("SELECT used FROM coupons WHERE code = $1", [code]);
if (coupon.used) throw new Error("already redeemed");
await applyDiscount(userId, coupon.value);
await db.query("UPDATE coupons SET used = true WHERE code = $1", [code]);
```

Two concurrent redemptions both see `used = false`, both apply the discount, both mark used.

**Secure** — redeem atomically and fail loudly if no rows changed:

```js
const res = await db.query(
  "UPDATE coupons SET used = true WHERE code = $1 AND used = false RETURNING value",
  [code],
);
if (res.rowCount === 0) throw new Error("already redeemed or invalid");
await applyDiscount(userId, res.rows[0].value);
```

Or use a `coupon_redemptions(coupon_id, user_id)` table with a unique constraint and `INSERT ... ON CONFLICT DO NOTHING`, then apply the discount only if a row was inserted.

### 3. File TOCTOU: `stat` then `open`

**Vulnerable** — classic path-based TOCTOU:

```python
st = os.stat(path)
if st.st_uid != os.getuid():
    raise PermissionError()
with open(path) as f:   # attacker swaps `path` for a symlink to /etc/shadow
    data = f.read()
```

**Secure** — open first, `fstat` on the fd:

```python
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    st = os.fstat(fd)
    if st.st_uid != os.getuid():
        raise PermissionError()
    data = os.read(fd, size)
finally:
    os.close(fd)
```

For create-if-not-exists use `O_EXCL | O_CREAT`. The check and the use must refer to the same file descriptor, not the same path string.

### 4. Session rotation: check old, create new, delete old

**Vulnerable** — three separate, non-transactional operations:

```js
const old = await sessions.findOne({ token: oldToken });
if (!old || old.expired) throw new Unauthorized();
const fresh = await sessions.insertOne({ userId: old.userId, token: newToken });
await sessions.deleteOne({ token: oldToken });
```

Between `insertOne` and `deleteOne` both sessions are valid. If the process crashes, both stay valid indefinitely. Under concurrent rotation, two new sessions can be minted from one old one.

**Secure** — rotate in one transaction, invalidate old atomically:

```js
await db.transaction(async (tx) => {
  const rotated = await tx.query(
    "UPDATE sessions SET token = $1, rotated_at = now() " +
    "WHERE token = $2 AND expired = false RETURNING user_id",
    [newToken, oldToken],
  );
  if (rotated.rowCount === 0) throw new Unauthorized();
});
```

One `UPDATE`, one row, new token replaces old atomically. No window where both are valid.

### 5. Async webhook dedup: lookup then insert

**Vulnerable** — duplicate Stripe webhook triggers double payout:

```js
app.post("/webhooks/stripe", async (req, res) => {
  const eventId = req.body.id;
  const seen = await db.query("SELECT 1 FROM processed_events WHERE id = $1", [eventId]);
  if (seen.rowCount > 0) return res.sendStatus(200);
  await processEvent(req.body);        // <-- side effect: mints credit, pays out, etc.
  await db.query("INSERT INTO processed_events(id) VALUES ($1)", [eventId]);
  res.sendStatus(200);
});
```

Stripe retries deliveries on 5xx and occasionally fires in parallel. Two workers both see "not processed", both run `processEvent`, both insert — or one fails on the insert after the side effect already shipped.

**Secure** — claim the event atomically *before* the side effect:

```js
app.post("/webhooks/stripe", async (req, res) => {
  const eventId = req.body.id;
  const claim = await db.query(
    "INSERT INTO processed_events(id) VALUES ($1) ON CONFLICT DO NOTHING",
    [eventId],
  );
  if (claim.rowCount === 0) return res.sendStatus(200);   // duplicate
  await processEvent(req.body);
  res.sendStatus(200);
});
```

Plus: verify the Stripe signature, and also honour any client-supplied `Idempotency-Key` header on upstream calls so the side effect is itself idempotent.

### 6. Node.js in-memory cache race

**Vulnerable** — shared Map mutated across `await` boundaries:

```js
const cache = new Map();

async function getOrCompute(key) {
  if (cache.has(key)) return cache.get(key);
  const value = await expensiveFetch(key);   // <-- many concurrent callers land here
  cache.set(key, value);
  return value;
}
```

Ten concurrent callers for the same cold key all miss, all run `expensiveFetch`, all write. If `expensiveFetch` has side effects (charges a provider, consumes a quota, generates a signed URL that burns a nonce), this is a real security bug — not just a performance issue.

**Secure** — cache the promise, not the value:

```js
const inflight = new Map();
const cache = new Map();

function getOrCompute(key) {
  if (cache.has(key)) return cache.get(key);
  if (inflight.has(key)) return inflight.get(key);
  const p = expensiveFetch(key).then((v) => {
    cache.set(key, v);
    inflight.delete(key);
    return v;
  });
  inflight.set(key, p);
  return p;
}
```

Concurrent callers now share the same in-flight promise; `expensiveFetch` runs once. For multi-process deployments the same concept moves to a distributed lock (Redis `SET NX PX`) or a single-writer queue.

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Read-Modify-Write and TOCTOU Sites

Launch a subagent with the following instructions:

> **Goal**: Enumerate every code site in the project where two operations on shared state could interleave non-atomically with a security-relevant outcome. Write results to `sast/race-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, where state lives (DB, Redis, in-memory, filesystem), and which flows touch money, coupons, quotas, sessions, tokens, webhooks, or file access.
>
> **Do not verify exploitability in this phase — just enumerate candidate sites.**
>
> **Search for the following patterns**:
>
> 1. **SELECT then arithmetic then UPDATE on the same row**
>    - A `SELECT`/`findOne`/`get` that reads a numeric or boolean field.
>    - Followed (possibly across `await`/function boundaries) by a branch on that field.
>    - Followed by an `UPDATE`/`save`/`set` that writes a value derived from the read.
>    - Especially: balances, credits, stock, quota counters, `used` flags, `status` enums, retry counts.
>
> 2. **File operations split across `stat`/`access`/`readlink` and `open`/`read`**
>    - `os.stat`, `os.access`, `lstat`, `fs.statSync`, `Path.exists`, followed by `open`, `read_file`, `fs.readFile` on the same path string.
>    - Upload pipelines that validate extension/size/mime by path, then read/move the file.
>    - Temp-file creation without `O_EXCL` / `mkstemp` / `fs.mkdtemp`.
>
> 3. **External check then state change**
>    - A call out to a provider (payments, KYC, 2FA, license server, feature flag) whose result is cached in a local variable, then consumed by a subsequent write.
>    - Webhook handlers that look up `processed_events` and then insert, without a unique index.
>    - Permission checks (`await can(user, action)`) followed by `await perform(action)` with no re-check.
>
> 4. **`await` between two logically coupled operations**
>    - In JavaScript/TypeScript/Python async code, any pair of `await`s where the first reads and the second writes the same conceptual record counts as a candidate — because Node.js/asyncio event loops can interleave other requests during the first `await`.
>    - Pay special attention to Express/Fastify/Koa handlers and FastAPI/async-Django views that do `const x = await db.find(...); ... await db.update(...)`.
>
> 5. **Missing optimistic concurrency**
>    - Update endpoints on resources that return an ETag or a `version`/`updated_at` column but do not require it on write (no `If-Match`, no `WHERE version = :v`).
>    - REST PUT/PATCH handlers that last-writer-wins into a security-relevant field (role, email, 2FA phone, recovery email).
>
> 6. **Duplicate submit on side-effecting endpoints**
>    - POST handlers that perform a side effect (charge, mint, send email, file upload) with no idempotency-key column, no request-dedup table, and no unique constraint that would fire on replay.
>    - Especially: payout, transfer, checkout, password-reset-consume, invite-accept, mint/issue.
>
> 7. **Stripe / payment-provider integration sites**
>    - Any call to `stripe.paymentIntents.create`, `charges.create`, `transfers.create`, `refunds.create`, `checkout.sessions.create`, or equivalents for other providers (Adyen, Braintree, Paddle, Lemon Squeezy).
>    - Flag sites that do not pass an `idempotency_key` / `idempotencyKey` option.
>
> 8. **Node.js / async-Python shared state**
>    - Module-scope `Map`/`Set`/`Object`/`dict` mutated inside request handlers without a lock or a promise-coalescing pattern.
>    - Counters, in-memory rate limiters, in-memory caches of privileged data, single-use nonce stores.
>
> 9. **File locks and mutexes that look wrong**
>    - `flock`/`fcntl`/`fs.open('wx')` used on a path that the attacker can influence.
>    - `threading.Lock` or `async-mutex` declared but released before the follow-up DB write, or not held across the full critical section.
>
> 10. **Monotonic state transitions without guards**
>     - `order.status = 'paid'` / `invoice.state = 'settled'` written without `WHERE status != 'paid'`.
>     - Booleans (`is_verified`, `is_admin`, `used`) flipped without a guard clause checking the current value in the same statement.
>
> **Output format** — write to `sast/race-recon.md`:
>
> ```markdown
> # Race Condition Recon: [Project Name]
>
> ## Shared State Surface
> - Databases in use and isolation levels (if discoverable)
> - Redis / cache usage (locks, WATCH/MULTI, counters)
> - Filesystem write paths (uploads, tmp, cache dirs)
> - In-process shared state (module-scope mutables)
> - Payment / webhook providers in use
>
> ## Candidate Sites
>
> ### 1. [Short title, e.g. "Balance decrement in POST /transfer"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Pattern**: [One of the 10 patterns above]
> - **Shared state**: [Which table/row/key/file/variable]
> - **Read operation**: [The check or fetch]
> - **Write operation**: [The update that depends on the read]
> - **Concurrency context**: [HTTP handler, webhook, cron, background job, CLI]
> - **Potential security impact**: [Double-spend, coupon re-redeem, priv retention, file swap, etc.]
>
> ### 2. ...
>
> [Use sequential numbering ### 1., ### 2., ... for every candidate — required for batching in Phase 2.]
> ```

### Phase 2: Verify — Atomicity Check (Batched)

After Phase 1 completes, read `sast/race-recon.md` and split candidate sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/race-recon.md` and count the numbered candidate sections (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 8 candidates → 3 batches (1–3, 4–6, 7–8).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/race-batch-N.md` where N is the 1-based batch number.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate site, determine whether the read-modify-write (or check-then-use) window is atomic under concurrency or whether an attacker can interleave requests to produce a security-relevant outcome. Write results to `sast/race-batch-[N].md`.
>
> **Your assigned sites** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the DB engine, ORM, transaction defaults, and concurrency model.
>
> **What race conditions are NOT** — do not flag these here:
> - Missing auth / authz (separate skill)
> - Plain business logic flaws exploitable with a single request (business-logic skill)
> - Injection, SSRF, XSS, RCE (separate skills)
> - Pure correctness bugs with no security consequence
>
> **For each site, perform the following checks**:
>
> **1. Is the critical section wrapped in a transaction with appropriate isolation / locking?**
>    - Is the read followed by `FOR UPDATE` (Postgres/MySQL) or `WITH (UPDLOCK, ROWLOCK)` (SQL Server)?
>    - Is the transaction `SERIALIZABLE`, and is there retry logic on `40001` / serialization-failure errors?
>    - Is the ORM transaction explicit (`with db.transaction():`, `sequelize.transaction`, `prisma.$transaction`), or implicit per-statement?
>
> **2. Can the read-modify-write be collapsed to an atomic conditional update?**
>    - Does the code use `UPDATE ... WHERE <guard>` and check affected rows?
>    - Or does it use `INSERT ... ON CONFLICT DO NOTHING` / unique constraint to enforce at-most-once?
>    - Or Redis `WATCH`/`MULTI`/`EXEC`, or `SET NX PX`?
>    - If not, how many concurrent requests can pass the check before any of them writes?
>
> **3. Is there optimistic concurrency (version / ETag)?**
>    - Does the table have a `version` / `updated_at` column enforced on update?
>    - Does the HTTP layer require `If-Match` for mutating requests?
>    - If missing: last-writer-wins → flag as LIKELY EXPLOITABLE when the target field is security-relevant (role, email, 2FA, recovery, password hash, permission flags).
>
> **4. For duplicate-submit / webhook dedup**:
>    - Is there an `idempotency_key` column with a unique constraint?
>    - For Stripe / payment provider calls: is `idempotency_key` / `idempotencyKey` passed on outgoing requests? Missing it is exploitable in retry-storm and double-submit scenarios.
>    - For incoming webhooks: is the event claimed (unique insert) *before* the side effect, or only recorded after?
>
> **5. For file TOCTOU**:
>    - Is the check done on a path string and the use done on a separately-resolved path? → Exploitable via symlink swap if the attacker can influence the directory or the file between the two calls.
>    - Or is the check done on an open file descriptor (`fstat`, `openat`, `O_NOFOLLOW`, `O_EXCL|O_CREAT`)? → Not exploitable.
>
> **6. For Node.js / async-Python**:
>    - Between any two `await`s on the same shared state, can another request's microtask run? (Answer is almost always yes — Node.js and asyncio interleave on every `await`.)
>    - Is the critical section serialized via `async-mutex`, a promise chain keyed by the resource id, or a Redis lock? If none and the state is security-relevant → Exploitable.
>    - For multi-process deployments (cluster, PM2, gunicorn, uvicorn with workers, Kubernetes replicas): in-process locks do not help — only distributed mechanisms (DB, Redis) count.
>
> **7. For monotonic transitions**:
>    - Does the `UPDATE` include `WHERE status = <expected_old_status>` (or the boolean equivalent)?
>    - If not, can a concurrent request transition out of the "paid"/"used"/"verified" state and back?
>
> **Classification**:
> - **Exploitable**: Clear read-modify-write / TOCTOU with no atomicity mechanism, on security-relevant state, reachable by an authenticated-or-less attacker. Two concurrent requests visibly interleave to produce the bad outcome.
> - **Likely Exploitable**: The atomicity mechanism exists but has a gap — wrong isolation level without retry, lock released too early, idempotency key optional, unique constraint on the wrong column, missing optimistic concurrency on a sensitive field.
> - **Not Exploitable**: Proper atomicity is enforced (`FOR UPDATE`, atomic conditional update, unique constraint, `O_EXCL`, `fstat(fd)`, mutex covering the full critical section for a single-process deployment, etc.).
> - **Needs Manual Review**: Cannot determine with confidence (dynamic SQL, exotic ORM hook, external queue semantics, complex transaction nesting).
>
> **Output format** — write to `sast/race-batch-[N].md`:
>
> ```markdown
> # Race Condition Batch [N] Results
>
> ## Findings
>
> ### [EXPLOITABLE] Site title
> - **Pattern**: [e.g. "SELECT-then-UPDATE on balances without locking"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / trigger**: `METHOD /path` or job name
> - **Shared state**: [table.column / redis key / file path / in-memory variable]
> - **Read operation**: [code reference]
> - **Write operation**: [code reference]
> - **Race window**: [What happens between read and write — DB round trip, `await`, syscall, etc.]
> - **Security impact**: [Double-spend, coupon re-redeem, privilege retention, file swap, duplicate payout]
> - **Why atomic mechanisms are absent**: [No transaction / no lock / no unique constraint / no idempotency key / `stat` then `open`]
> - **Proof**: [Show the exact code path, including the missing guard]
> - **Remediation**: [Specific fix — atomic UPDATE with WHERE guard, FOR UPDATE, unique constraint + ON CONFLICT, idempotency key, fstat on fd, etc.]
> - **Dynamic Test**:
>   ```
>   [Concrete PoC. Typically two concurrent curl / httpie / Turbo Intruder requests firing the same POST
>    with identical bodies, showing that both succeed and both produce the side effect.
>    Include exact HTTP method, endpoint, headers, and bodies. Describe what response or DB state confirms the race.]
>   ```
>
> ### [LIKELY EXPLOITABLE] Site title
> - **Pattern**: [e.g. "Missing Idempotency-Key on outgoing Stripe call"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / trigger**: `METHOD /path`
> - **Shared state**: [...]
> - **Existing protection**: [What atomicity mechanism is present]
> - **Gap**: [Why it's incomplete — wrong isolation, released lock, optional header, partial unique constraint]
> - **Concern**: [Scenario under which the gap becomes exploitable]
> - **Proof**: [code path]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [Concurrent-request PoC or retry-storm PoC.]
>   ```
>
> ### [NOT EXPLOITABLE] Site title
> - **Pattern**: [...]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Protection**: [What makes it atomic — FOR UPDATE, atomic UPDATE WHERE, unique constraint, fstat(fd), mutex, etc.]
>
> ### [NEEDS MANUAL REVIEW] Site title
> - **Pattern**: [...]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [Why static analysis couldn't conclude]
> - **Suggestion**: [What to examine manually or test dynamically]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/race-batch-*.md` file and merge them into a single `sast/race-results.md` and its canonical JSON counterpart `sast/race-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/race-batch-1.md`, `sast/race-batch-2.md`, ... files.
2. Collect all findings into one list, preserving classification and all detail fields.
3. Count totals across batches for the executive summary.
4. Write the merged human-readable report to `sast/race-results.md` using this format:

```markdown
# Race Condition Analysis Results: [Project Name]

## Executive Summary
- Candidate sites analyzed: [total across all batches]
- Exploitable: [N]
- Likely Exploitable: [N]
- Not Exploitable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 EXPLOITABLE first, then LIKELY EXPLOITABLE, then NEEDS MANUAL REVIEW, then NOT EXPLOITABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical machine-readable view to `sast/race-results.json`. Every EXPLOITABLE and LIKELY EXPLOITABLE finding becomes one entry; NOT EXPLOITABLE and NEEDS MANUAL REVIEW entries are optional and may be included with severity `info`.

```json
{
  "findings": [
    {
      "id": "race-1",
      "skill": "sast-race",
      "severity": "high",
      "title": "Balance transfer SELECT-then-UPDATE without row lock",
      "description": "POST /transfer reads balance, branches, then issues a separate UPDATE. Two concurrent requests both pass the check and both decrement, resulting in negative balance / double-spend.",
      "location": { "file": "app/handlers/transfer.py", "line": 42, "column": 5 },
      "remediation": "Replace the read-modify-write with a single atomic UPDATE: `UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt` and reject the transfer if rowcount == 0. Alternatively wrap the read in SELECT ... FOR UPDATE inside an explicit transaction."
    }
  ]
}
```

If no findings exist, still write `{"findings": []}` so the aggregator can verify the scan ran.

6. After writing both `sast/race-results.md` and `sast/race-results.json`, **delete all intermediate files** (`sast/race-recon.md`, `sast/race-batch-*.md`).

---

## Findings

Use this template when rendering individual findings inside `sast/race-results.md`. Each EXPLOITABLE or LIKELY EXPLOITABLE entry must include every field below — the triage and reporting skills depend on them.

```markdown
### [EXPLOITABLE | LIKELY EXPLOITABLE] Short title of the race

- **Category**: Race Condition — [TOCTOU | read-modify-write without lock | duplicate submit | missing optimistic concurrency | async/await interleave | webhook dedup | session rotation]
- **File**: `relative/path/to/file.ext` (lines X-Y)
- **Endpoint / trigger**: `METHOD /path` or job / webhook name
- **Shared state**: table.column / redis key / file path / in-memory variable
- **Read operation**: Reference to the line(s) doing the check or fetch
- **Write operation**: Reference to the line(s) doing the update
- **Race window**: What happens between the two (another DB round trip, an `await`, a syscall, a network call)
- **Security impact**: Concrete attacker gain (double-spend USD, coupon re-redeem, privilege retention, file swap read of `/etc/shadow`, duplicate payout of $X, etc.)
- **Why atomic mechanisms are absent**: No transaction / wrong isolation / no FOR UPDATE / no unique constraint / no idempotency key / path-based stat-then-open / missing version column
- **Proof**: Code excerpt demonstrating the missing guard
- **Remediation**: One or more of —
  - Atomic `UPDATE ... WHERE <guard>` + affected-row check
  - `SELECT ... FOR UPDATE` inside an explicit transaction
  - Redis `WATCH`/`MULTI`/`EXEC` or `SET NX PX` lock
  - Unique constraint on `(idempotency_key)` / `(webhook_event_id)` / `(coupon_id, user_id)` plus `INSERT ... ON CONFLICT DO NOTHING`
  - Optimistic concurrency: add `version` column and `WHERE version = :v`, or HTTP `If-Match` with ETag
  - Pass `idempotency_key` to Stripe / payment provider calls
  - Replace `stat(path)` + `open(path)` with `open` then `fstat(fd)`, or `O_EXCL | O_CREAT` for create-only
  - Add per-key mutex or promise-coalescing for in-process state, or move state to DB/Redis for multi-process deployments
- **Dynamic Test**: Runnable proof — typically N concurrent identical requests. Example:
  ```bash
  # Fire 20 concurrent transfers of $80 from an account with $100 balance.
  # Expected (secure): exactly one succeeds, 19 return InsufficientFunds.
  # Observed (vulnerable): multiple succeed, final balance is negative.
  for i in $(seq 1 20); do
    curl -s -X POST https://target.example/api/transfer \
      -H 'Authorization: Bearer '"$TOKEN" \
      -H 'Content-Type: application/json' \
      -d '{"to":"attacker","amount":80}' &
  done
  wait
  ```
```

---

## Important Reminders

- Read `sast/architecture.md` and pass its contents to all subagents as context.
- Phase 2 must run **after** Phase 1 completes — it depends on the recon output.
- Phase 3 must run **after** all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1–3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- Focus strictly on **races with security impact**. A drifting analytics counter is not in scope; a drifting balance, coupon-used flag, session rotation state, file-permission check, or webhook-dedup state is.
- Concurrent duplicate POST (two clients firing the same request) is the default attack model — do not require a "sophisticated attacker" to flag it. Tools like Turbo Intruder, `xargs -P`, `curl &` loops, and `httpx`/`aiohttp` make it trivial.
- **Missing optimistic concurrency** (no `version` column / no ETag) on a resource with a security-relevant field (role, email, recovery phone, 2FA settings, password hash, plan tier) is a LIKELY EXPLOITABLE finding even without a demonstrated timing attack, because any two well-timed writes can silently overwrite each other.
- **Missing Stripe / payment-provider `idempotency_key`** is a LIKELY EXPLOITABLE finding on retry-prone paths (payment intents, charges, refunds, transfers, checkout sessions). Stripe explicitly recommends it for all mutating calls.
- **Node.js / asyncio `await` boundaries**: any pair of `await`s that (1) read then write the same security-relevant state and (2) are not protected by a DB/Redis atomic primitive should be flagged. In-process mutexes only suffice for single-process deployments; most Node.js and Python web apps run multiple workers.
- When in doubt, classify as **Needs Manual Review** rather than **Not Exploitable**. False negatives in a race-condition review are expensive — they tend to turn into six-figure incidents.
- Clean up intermediate files: delete `sast/race-recon.md` and all `sast/race-batch-*.md` files after the final `sast/race-results.md` and `sast/race-results.json` are written.
