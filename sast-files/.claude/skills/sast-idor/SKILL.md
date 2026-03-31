---
name: sast-idor
description: >-
  Detect Insecure Direct Object Reference (IDOR) vulnerabilities in a codebase
  using a three-phase approach: recon (find candidates), batched verify (check
  authorization in parallel subagents, 3 candidates each), and merge (consolidate
  batch results). Checks endpoints for missing ownership or authorization checks
  on user-supplied identifiers. Requires sast/architecture.md (run sast-analysis
  first). Outputs findings to sast/idor-results.md. Use when asked to find IDOR
  or authorization bypass bugs.
---

# IDOR (Insecure Direct Object Reference) Detection

You are performing a focused security assessment to find IDOR vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find candidate endpoints), **batched verify** (check authorization in parallel batches of 3), and **merge** (consolidate results).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is IDOR

IDOR occurs when an application uses a user-supplied identifier (ID, slug, filename, etc.) to directly access an object **without verifying the requesting user is authorized to access that specific object**. The application authenticates the user but fails to check ownership or permissions on the requested resource.

The core pattern: *authenticated user A can access or modify resources belonging to user B by changing an identifier in the request.*

### What IDOR IS

- Changing `/api/orders/1001` to `/api/orders/1002` and seeing another user's order
- Sending `DELETE /api/documents/555` to delete a document you don't own
- Modifying `{"account_id": 789}` in a request body to transfer money from someone else's account
- Changing a file download parameter `?file_id=42` to access another user's private file
- Updating another user's profile via `PUT /api/users/other-user-id`

### What IDOR is NOT

Do not flag these as IDOR:

- **Missing authentication**: Endpoint requires no login at all → that's "Unauthenticated Access", a different class
- **Broken function-level access control**: Regular user accessing `/admin/dashboard` → that's vertical privilege escalation, not IDOR
- **Public resources**: Accessing `/api/posts/123` where posts are intentionally public is not IDOR
- **Parameter tampering on non-object fields**: Changing `role=admin` or `price=0` in a request → that's mass assignment or business logic, not IDOR
- **SQL injection via ID fields**: `?id=1 OR 1=1` → that's SQLi, not IDOR

### Authorization Patterns That Prevent IDOR

When you see these patterns, the endpoint is likely **not vulnerable**:

**1. Query scoped to current user (most common fix)**
```
# The query itself ensures only the user's own records are returned
Order.objects.filter(id=order_id, user=request.user)       # Django
current_user.orders.find(params[:id])                       # Rails
Order.findOne({ _id: orderId, userId: req.user.id })        # Mongoose
SELECT * FROM orders WHERE id = ? AND user_id = ?           # Raw SQL
```

**2. Explicit ownership check after fetch**
```
order = Order.find(order_id)
if order.user_id != current_user.id:
    raise Forbidden
```

**3. Policy / ability / authorization middleware**
```
authorize('view', order)                    # Laravel Policy
can?(:read, @order)                         # CanCanCan (Rails)
@PreAuthorize("@auth.ownsOrder(#orderId)")  # Spring Security
```

**4. Tenant/organization scoping**
```
# Multi-tenant apps that scope all queries to the tenant
tenant = get_current_tenant(request)
Order.objects.filter(id=order_id, tenant=tenant)
```

---

## Vulnerable vs. Secure Examples

### Python — Django

```python
# VULNERABLE: fetches any order by ID, no ownership check
def get_order(request, order_id):
    order = Order.objects.get(id=order_id)
    return JsonResponse(model_to_dict(order))

# SECURE: query scoped to requesting user
def get_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    return JsonResponse(model_to_dict(order))
```

### Python — Flask / SQLAlchemy

```python
# VULNERABLE
@app.route('/api/documents/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    return jsonify(doc.serialize())

# SECURE
@app.route('/api/documents/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
    return jsonify(doc.serialize())
```

### Node.js — Express / Mongoose

```javascript
// VULNERABLE
router.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

// SECURE
router.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});
```

### Node.js — Express / Prisma

```javascript
// VULNERABLE
router.get('/api/invoices/:id', auth, async (req, res) => {
  const invoice = await prisma.invoice.findUnique({ where: { id: req.params.id } });
  res.json(invoice);
});

// SECURE
router.get('/api/invoices/:id', auth, async (req, res) => {
  const invoice = await prisma.invoice.findFirst({
    where: { id: req.params.id, userId: req.user.id }
  });
  if (!invoice) return res.status(404).json({ error: 'Not found' });
  res.json(invoice);
});
```

### Ruby on Rails

```ruby
# VULNERABLE
def show
  @order = Order.find(params[:id])
end

# SECURE
def show
  @order = current_user.orders.find(params[:id])
end
```

### Java — Spring Boot

```java
// VULNERABLE
@GetMapping("/api/accounts/{id}")
public Account getAccount(@PathVariable Long id) {
    return accountRepo.findById(id).orElseThrow();
}

// SECURE
@GetMapping("/api/accounts/{id}")
public Account getAccount(@PathVariable Long id, Authentication auth) {
    Account acct = accountRepo.findById(id).orElseThrow();
    if (!acct.getOwnerId().equals(auth.getName()))
        throw new AccessDeniedException("Forbidden");
    return acct;
}
```

### Go

```go
// VULNERABLE
func GetOrder(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    order, _ := db.GetOrder(id)
    json.NewEncoder(w).Encode(order)
}

// SECURE
func GetOrder(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    userID := r.Context().Value("userID").(string)
    order, _ := db.GetOrderByUser(id, userID)
    json.NewEncoder(w).Encode(order)
}
```

### PHP — Laravel

```php
// VULNERABLE
public function show($id) {
    return Invoice::findOrFail($id);
}

// SECURE (scoped query)
public function show($id) {
    return auth()->user()->invoices()->findOrFail($id);
}

// SECURE (policy)
public function show($id) {
    $invoice = Invoice::findOrFail($id);
    $this->authorize('view', $invoice);
    return $invoice;
}
```

### C# — ASP.NET Core

```csharp
// VULNERABLE
[HttpGet("api/profiles/{id}")]
public async Task<IActionResult> GetProfile(int id) {
    var profile = await _db.Profiles.FindAsync(id);
    return Ok(profile);
}

// SECURE
[HttpGet("api/profiles/{id}")]
public async Task<IActionResult> GetProfile(int id) {
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var profile = await _db.Profiles.FirstOrDefaultAsync(p => p.Id == id && p.UserId == userId);
    if (profile == null) return NotFound();
    return Ok(profile);
}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Candidate Endpoints

Launch a subagent with the following instructions:

> **Goal**: Find every endpoint, controller action, or handler that retrieves, modifies, or deletes a specific object using a user-supplied identifier. Write results to `sast/idor-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, frameworks, route definitions, and data access patterns.
>
> **What to search for**:
>
> 1. **Route definitions** that contain ID parameters:
>    - Path parameters: `:id`, `{id}`, `<int:id>`, `[id]`
>    - Search patterns: route/path/endpoint definitions with parameter placeholders
>
> 2. **Controller/handler methods** that accept ID arguments and use them to fetch or mutate objects:
>    - ORM lookups: `find(id)`, `findById()`, `get(id=)`, `objects.get()`, `findOne()`, `findUnique()`, `findFirst()`, `query.get()`, `where(id:)`
>    - Raw queries: `SELECT ... WHERE id = ?`, etc.
>    - Also look for delete, update operations with user-supplied IDs
>
> 3. **Request body or query parameter IDs** used in operations:
>    - `req.body.userId`, `req.query.id`, `request.data['account_id']`, etc.
>
> 4. **GraphQL resolvers and mutations** that accept ID arguments
>
> 5. **File/resource access by user-supplied path or filename**
>
> **What to ignore**:
> - Endpoints that are intentionally public (no auth required by design)
> - Admin-only endpoints behind role-based checks (these are a different class)
> - Endpoints where the only ID used is the authenticated user's own ID (e.g., `GET /api/me/profile`)
> - Static asset serving
>
> **Output format** — write to `sast/idor-recon.md`:
>
> ```markdown
> # IDOR Recon: [Project Name]
>
> ## Summary
> Found [N] candidate endpoints that use user-supplied identifiers to access objects.
>
> ## Candidates
>
> ### 1. [Descriptive name]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path/:param`
> - **Identifier source**: [path param / query param / body field]
> - **Operation**: [read / update / delete]
> - **Object accessed**: [model/table name]
> - **Code snippet**:
>   ```
>   [relevant code]
>   ```
>
> [Repeat for each candidate]
> ```

### Phase 2: Verify — Check Authorization (Batched)

After Phase 1 completes, read `sast/idor-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/idor-recon.md` and count the numbered candidate sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 candidates → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/idor-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Node.js/Express with Prisma, include only the "Node.js — Express / Prisma" and "Node.js — Express / Mongoose" examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: Verify the following IDOR (Insecure Direct Object Reference) candidates and determine whether adequate authorization checks exist. Our goal is to find IDOR vulnerabilities. Write results to `sast/idor-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the auth mechanism, middleware stack, and ORM patterns.
>
> **IDOR Reference — What to look for**:
>
> IDOR occurs when an authenticated user can access or modify resources belonging to another user by changing an identifier in the request. Focus on **horizontal privilege escalation** (user-to-user).
>
> **What IDOR is NOT** — do not flag these as IDOR:
> - **Missing authentication**: Endpoint requires no login at all → that's "Unauthenticated Access", not IDOR
> - **Broken function-level access control**: Regular user accessing `/admin/dashboard` → that's vertical privilege escalation, not IDOR
> - **Public resources**: Accessing `/api/posts/123` where posts are intentionally public is not IDOR
> - **Parameter tampering on non-object fields**: Changing `role=admin` or `price=0` → that's mass assignment or business logic, not IDOR
> - **SQL injection via ID fields**: `?id=1 OR 1=1` → that's SQLi, not IDOR
>
> **Authorization patterns that PREVENT IDOR** — if you see these, the endpoint is likely safe:
> 1. **Query scoped to current user**: The query filters by the authenticated user's ID (e.g., `WHERE id = ? AND user_id = ?`, `current_user.orders.find(id)`, `Order.findOne({ _id: id, userId: req.user.id })`, `Order.objects.filter(id=order_id, user=request.user)`)
> 2. **Explicit ownership check after fetch**: Code fetches the object then compares `resource.user_id == current_user.id` before returning
> 3. **Policy / ability / authorization middleware**: Framework authorization like `authorize('view', order)`, `can?(:read, @order)`, `@PreAuthorize("@auth.ownsOrder(#orderId)")`
> 4. **Tenant/organization scoping**: All queries scoped to the current tenant/org
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each candidate endpoint, check**:
>
> 1. **Is the database query scoped to the authenticated user?**
>    - Does the query include a `user_id` / `owner_id` / `tenant_id` filter matching the current user?
>    - Is the query done through an association (e.g., `current_user.orders.find(id)`)?
>
> 2. **Is there an explicit ownership/permission check after fetching?**
>    - Does the code compare `resource.user_id == current_user.id` (or equivalent)?
>    - Is there a policy/ability/authorization check?
>
> 3. **Is there authorization middleware applied to this route?**
>    - Is there middleware that verifies object ownership before the handler runs?
>    - Trace the middleware chain — don't assume a middleware name implies it checks ownership
>
> 4. **For mutations (update/delete), are the same checks present?**
>    - Sometimes read endpoints are protected but write endpoints are not
>
> 5. **Edge cases to check**:
>    - Does the auth check exist but only run conditionally (e.g., skipped for certain content types)?
>    - Is the check present in one branch of an if/else but missing in another?
>    - Can the check be bypassed by sending the ID in an alternative field?
>    - Are bulk/batch endpoints checked per-item or just at the batch level?
>
> **Classification**:
> - **Vulnerable**: No authorization check found for the specific object. User A can access User B's resources.
> - **Likely Vulnerable**: Auth check exists but appears incomplete, bypassable, or conditional.
> - **Not Vulnerable**: Proper authorization check is in place.
> - **Needs Manual Review**: Cannot determine with confidence (e.g., complex middleware chain, authorization happens in a service layer that's hard to trace).
>
> **Output format** — write to `sast/idor-batch-[N].md`:
>
> ```markdown
> # IDOR Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path/:param`
> - **Issue**: [Clear description of what's missing]
> - **Impact**: [What an attacker can do — read other users' X, delete other users' Y, etc.]
> - **Proof**: [Show the code path — from route to DB query — highlighting the missing check]
> - **Remediation**: [Specific fix for this endpoint]
> - **Dynamic Test**:
>   ```
>   [curl command or step-by-step instructions to confirm this finding on the live app.
>    Include the exact endpoint, HTTP method, headers, and what to look for in the response.
>    Use placeholder tokens like <USER_B_TOKEN> and <USER_A_RESOURCE_ID>.]
>   ```
>
> ### [LIKELY VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path/:param`
> - **Issue**: [What's incomplete about the check]
> - **Concern**: [Why this might still be exploitable]
> - **Proof**: [Show the code path with the weak/partial check]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [curl command or step-by-step instructions to confirm this finding on the live app.
>    Include the exact endpoint, HTTP method, headers, and what to look for in the response.
>    Use placeholder tokens like <USER_B_TOKEN> and <USER_A_RESOURCE_ID>.]
>   ```
>
> ### [NOT VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path/:param`
> - **Protection**: [How it's protected — scoped query / ownership check / policy]
>
> ### [NEEDS MANUAL REVIEW] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path/:param`
> - **Uncertainty**: [Why automated analysis couldn't determine the status]
> - **Suggestion**: [What to look at manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/idor-batch-*.md` file and merge them into a single `sast/idor-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/idor-batch-1.md`, `sast/idor-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/idor-results.md` using this format:

```markdown
# IDOR Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/idor-results.md`, **delete all intermediate batch files** (`sast/idor-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- Focus on **horizontal privilege escalation** (user-to-user). Vertical escalation (user-to-admin) is a different skill.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Trace the full code path: route → middleware → controller → service → data access. Authorization can happen at any layer.
- Pay attention to framework conventions. In Rails, `current_user.orders.find(id)` is safe. In Express, just having `auth` middleware doesn't mean ownership is checked.
- Clean up intermediate files: delete `sast/idor-recon.md` and all `sast/idor-batch-*.md` files after the final `sast/idor-results.md` is written.
