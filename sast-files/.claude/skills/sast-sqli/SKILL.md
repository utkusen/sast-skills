---
name: sast-sqli
description: >-
  Detect SQL injection vulnerabilities in a codebase using a three-phase approach:
  recon (find unsafe SQL construction sites), batched verify (trace user input to
  those sites in parallel subagents, 3 sites each), and merge (consolidate batch
  results). Covers string concat, f-strings, unsafe ORM methods, and dynamic
  identifiers. Requires sast/architecture.md (run sast-analysis first). Outputs
  findings to sast/sqli-results.md. Use when asked to find SQLi or database
  injection bugs.
version: 0.1.0
---

# SQL Injection (SQLi) Detection

You are performing a focused security assessment to find SQL injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find vulnerable SQL construction sites), **batched verify** (taint analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is SQL Injection

SQL injection occurs when user-supplied input is incorporated into SQL queries through string concatenation or interpolation rather than parameterized binding. This allows attackers to alter query logic, bypass authentication, extract sensitive data, modify or delete records, and in some configurations execute OS commands.

The core pattern: *unvalidated, unparameterized user input reaches a SQL query execution call.*

### What SQLi IS

- Concatenating user input directly into a SQL string: `"SELECT * FROM users WHERE name = '" + username + "'"`
- Using string formatting to build queries: `f"SELECT * FROM orders WHERE id = {order_id}"`
- Dynamic `ORDER BY` / `GROUP BY` / table/column names from user input with no allowlist validation
- ORM raw query methods with unsanitized input: `User.objects.raw(f"SELECT * WHERE id={id}")`, `$queryRawUnsafe(input)`
- Second-order injection: input is stored in the DB and later used in a raw query without re-sanitization

### What SQLi is NOT

Do not flag these as SQLi:

- **IDOR**: Changing `?id=1` to `?id=2` to access another user's data — that's Insecure Direct Object Reference, a separate class
- **Mass assignment**: Setting extra ORM model fields from user input — different vulnerability
- **XSS via database**: Storing a `<script>` tag in the DB that's later rendered unescaped — that's XSS, not SQLi
- **NoSQL injection**: Injecting into MongoDB operators — similar concept but a distinct vulnerability class
- **Safe ORM queries**: Parameterized ORM lookups like `User.objects.filter(id=user_id)` or `User.find(params[:id])` — do not flag these

### Patterns That Prevent SQLi

When you see these patterns, the code is likely **not vulnerable**:

**1. Parameterized queries / prepared statements (most common fix)**
```
# Python — cursor.execute with tuple binding
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Node.js — mysql2 / pg placeholder binding
db.query("SELECT * FROM users WHERE id = ?", [userId])
pool.query("SELECT * FROM users WHERE id = $1", [userId])

# Java — PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);

# Go — database/sql placeholder
db.QueryRow("SELECT * FROM users WHERE id = $1", userID)

# PHP — PDO with named params
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);

# C# — SqlCommand with parameters
cmd.CommandText = "SELECT * FROM users WHERE id = @id";
cmd.Parameters.AddWithValue("@id", userId);
```

**2. ORM query builder (safe by default)**
```
# Django ORM
User.objects.filter(id=user_id)

# ActiveRecord (Rails)
User.find(params[:id])
User.where(name: params[:name])

# Prisma (tagged template literal form of $queryRaw)
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`

# Laravel Eloquent (non-raw)
User::find($id)
```

**3. Allowlist validation for dynamic identifiers**
```
# Dynamic ORDER BY — validate column name against a hardcoded set before interpolating
ALLOWED_COLUMNS = {'name', 'created_at', 'price'}
if sort_col not in ALLOWED_COLUMNS:
    raise ValueError("Invalid column")
query = f"SELECT * FROM products ORDER BY {sort_col}"  # safe only after allowlist check
```

---

## Vulnerable vs. Secure Examples

### Python — Django (raw SQL)

```python
# VULNERABLE: f-string interpolation in raw()
def search_users(request):
    username = request.GET.get('username')
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")
    return JsonResponse(list(users.values()), safe=False)

# SECURE: parameterized raw()
def search_users(request):
    username = request.GET.get('username')
    users = User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])
    return JsonResponse(list(users.values()), safe=False)
```

### Python — Flask / SQLAlchemy

```python
# VULNERABLE: f-string into text()
@app.route('/search')
def search():
    name = request.args.get('name')
    result = db.session.execute(text(f"SELECT * FROM products WHERE name = '{name}'"))
    return jsonify(result.fetchall())

# SECURE: named bound parameter
@app.route('/search')
def search():
    name = request.args.get('name')
    result = db.session.execute(
        text("SELECT * FROM products WHERE name = :name"), {"name": name}
    )
    return jsonify(result.fetchall())
```

### Python — sqlite3 / psycopg2

```python
# VULNERABLE
def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()

# SECURE
def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
```

### Node.js — mysql2

```javascript
// VULNERABLE: template literal in query string
app.get('/user', async (req, res) => {
  const { id } = req.query;
  const [rows] = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(rows);
});

// SECURE: placeholder binding
app.get('/user', async (req, res) => {
  const { id } = req.query;
  const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
  res.json(rows);
});
```

### Node.js — pg (PostgreSQL)

```javascript
// VULNERABLE
app.get('/orders', async (req, res) => {
  const status = req.query.status;
  const result = await pool.query(`SELECT * FROM orders WHERE status = '${status}'`);
  res.json(result.rows);
});

// SECURE
app.get('/orders', async (req, res) => {
  const status = req.query.status;
  const result = await pool.query('SELECT * FROM orders WHERE status = $1', [status]);
  res.json(result.rows);
});
```

### Ruby on Rails

```ruby
# VULNERABLE: string interpolation in where()
def search
  @users = User.where("name = '#{params[:name]}'")
end

# VULNERABLE: find_by_sql with interpolation
def find_user
  @user = User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")
end

# SECURE: parameterized where()
def search
  @users = User.where("name = ?", params[:name])
  # or using hash form: User.where(name: params[:name])
end
```

### Java — Spring JDBC

```java
// VULNERABLE: string concatenation
public User findUser(String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(sql, userRowMapper);
}

// SECURE: parameterized query
public User findUser(String username) {
    return jdbcTemplate.queryForObject(
        "SELECT * FROM users WHERE username = ?", userRowMapper, username
    );
}
```

### Go — database/sql

```go
// VULNERABLE: fmt.Sprintf to build query
func GetUserByName(name string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    row := db.QueryRow(query)
    // ...
}

// SECURE: parameterized query
func GetUserByName(name string) (*User, error) {
    row := db.QueryRow("SELECT * FROM users WHERE name = $1", name)
    // ...
}
```

### PHP — PDO

```php
// VULNERABLE: string concatenation
function getUser($id) {
    $stmt = $pdo->query("SELECT * FROM users WHERE id = " . $id);
    return $stmt->fetch();
}

// SECURE: prepared statement
function getUser($id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $id]);
    return $stmt->fetch();
}
```

### C# — ADO.NET

```csharp
// VULNERABLE: string concatenation
public User GetUser(string username) {
    using var cmd = new SqlCommand(
        "SELECT * FROM Users WHERE Username = '" + username + "'", conn);
    return ReadUser(cmd.ExecuteReader());
}

// SECURE: parameterized command
public User GetUser(string username) {
    using var cmd = new SqlCommand(
        "SELECT * FROM Users WHERE Username = @username", conn);
    cmd.Parameters.AddWithValue("@username", username);
    return ReadUser(cmd.ExecuteReader());
}
```

### Dynamic ORDER BY / Column Names (all stacks)

```python
# VULNERABLE: unsanitized user input as column name (parameterization can't help here)
sort_col = request.args.get('sort', 'name')
cursor.execute(f"SELECT * FROM products ORDER BY {sort_col}")

# SECURE: allowlist validation before interpolation
ALLOWED_SORT_COLS = {'name', 'price', 'created_at'}
sort_col = request.args.get('sort', 'name')
if sort_col not in ALLOWED_SORT_COLS:
    return abort(400)
cursor.execute(f"SELECT * FROM products ORDER BY {sort_col}")
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Vulnerable SQL Construction Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a SQL query is constructed in a vulnerable way — using string concatenation, interpolation, or formatting with any variable (regardless of where that variable comes from). Write results to `sast/sqli-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, database layer, ORM patterns, and query execution methods.
>
> **What to search for — vulnerable query construction patterns**:
>
> Look for SQL query execution calls where the query string argument is built dynamically rather than being a static string with placeholder parameters. Flag ANY dynamic variable embedded into the query — you are not yet tracing whether the variable is user-controlled; that is Phase 2's job.
>
> 1. **String concatenation into a SQL execution call**:
>    - `cursor.execute("SELECT ... WHERE id = " + var)`
>    - `$pdo->query("SELECT * FROM users WHERE id = " . $var)`
>    - `jdbcTemplate.query("SELECT * WHERE username = '" + var + "'")`
>
> 2. **F-strings / template literals used as a query argument**:
>    - `cursor.execute(f"SELECT * WHERE name = '{var}'")`
>    - `` db.query(`SELECT * WHERE id = ${var}`) ``
>    - `db.QueryRow(fmt.Sprintf("SELECT * WHERE id = '%s'", var))`
>
> 3. **String formatting functions used to build the query**:
>    - `cursor.execute("SELECT * WHERE id = %s" % var)` (note: `%` formatting, NOT parameterized binding)
>    - `cursor.execute("SELECT * WHERE id = {}".format(var))`
>    - `String.format("SELECT * WHERE id = '%s'", var)` (Java)
>    - `sprintf("SELECT * WHERE id = %s", $var)` (PHP)
>
> 4. **ORM raw/unsafe methods called with a dynamically built string** (not a static template with bound params):
>    - Django: `Model.objects.raw(f"...")`, `RawSQL(f"...")`, `extra(where=[f"..."])`
>    - ActiveRecord: `where("col = '#{var}'")`  (Ruby interpolation inside string arg)
>    - Sequelize: `` sequelize.query(`...${var}...`) ``, `literal(var)`
>    - TypeORM: `` createQueryBuilder().where(`col = '${var}'`) ``, `.query("..." + var)`
>    - Prisma: `$queryRawUnsafe(...)`, `$executeRawUnsafe(...)`
>    - Entity Framework: `FromSqlRaw("..." + var)`, `ExecuteSqlRaw("..." + var)`
>
> 5. **Dynamic identifiers** — any variable used as a column name, table name, `ORDER BY` / `GROUP BY` value in a query string (parameterization cannot protect identifiers; only allowlist validation can):
>    - `f"SELECT * FROM {table_var}"`
>    - `` `SELECT * FROM ${tableVar}` ``
>    - `f"SELECT * ORDER BY {sort_col}"`
>
> **What to skip** (these are safe construction patterns — do not flag):
> - Static query strings with no dynamic parts: `cursor.execute("SELECT * FROM users WHERE id = %s", (val,))`
> - ORM safe query builder methods: `.filter()`, `.where(col: val)`, `.findOne()`, `.findUnique()`, `prisma.$queryRaw` with tagged template literals
> - Properly parameterized raw queries where the string itself is static and values are passed as a separate argument list: `execute("SELECT * WHERE id = %s", (val,))`, `query("SELECT * WHERE id = ?", [val])`
>
> **Output format** — write to `sast/sqli-recon.md`:
>
> ```markdown
> # SQLi Recon: [Project Name]
>
> ## Summary
> Found [N] locations where SQL queries are constructed in a vulnerable way.
>
> ## Vulnerable Construction Sites
>
> ### 1. [Descriptive name — e.g., "String concat in get_user query"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Query execution method**: [cursor.execute / db.query / raw / etc.]
> - **Construction pattern**: [string concat / f-string / template literal / % format / .format() / fmt.Sprintf / ORM raw]
> - **Interpolated variable(s)**: `var_name` — [brief note on what it appears to represent, e.g., "looks like a sort column" or "unknown origin"]
> - **Code snippet**:
>   ```
>   [the vulnerable query construction + execution call]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/sqli-recon.md`. If the recon found **zero vulnerable construction sites** (the summary reports "Found 0" or the "Vulnerable Construction Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/sqli-results.md` and stop:

```markdown
# SQLi Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one vulnerable construction site.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/sqli-recon.md` and split the construction sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent traces user input only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/sqli-recon.md` and count the numbered site sections under "Vulnerable Construction Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/sqli-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Node.js with `pg`, include the "Node.js — pg (PostgreSQL)" and related Node examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned vulnerable SQL construction site, determine whether a user-supplied value reaches the interpolated variable. Our goal is to find SQL injection vulnerabilities. Write results to `sast/sqli-batch-[N].md`.
>
> **Your assigned construction sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, and how data flows through the application.
>
> **SQLi reference — trace the interpolated variable(s) backwards to their origin**:
>
> 1. **Direct user input** — the variable is assigned directly from a request source with no transformation:
>    - HTTP query params: `request.GET.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `c.Query("x")`
>    - Path parameters: `request.path_params['id']`, `req.params.id`, `params[:id]`
>    - Request body / form fields: `request.POST.get(...)`, `req.body.x`, `params[:x]`, `$_POST['x']`
>    - HTTP headers: `request.headers.get(...)`, `req.headers['x']`
>    - Cookies: `request.COOKIES.get(...)`, `req.cookies.x`
>
> 2. **Indirect user input** — the variable is derived from user input through transformations, function calls, or intermediate assignments. Trace the full chain:
>    - Variable assigned from a function return value → check that function's parameter origin
>    - Variable passed as a function argument → check the call site(s)
>    - Variable read from a class attribute or shared state set elsewhere → find the setter
>    - Variable conditionally assigned — check all branches
>
> 3. **Second-order input** — the variable is read from the database, but the stored value originally came from user input:
>    - Find where this value was written to the DB — was it stored from a user-supplied field?
>    - Was it sanitized or parameterized at write time?
>
> 4. **Server-side / hardcoded value** — the variable comes from config, an environment variable, a hardcoded constant, or server-side logic with no user influence — this site is NOT exploitable.
>
> **Mitigations** (check even if user input might reach the variable):
> - Allowlist validation before use (especially for dynamic identifiers — column/table names, `ORDER BY`)
> - Type casts that genuinely constrain the value in context (e.g., `int(val)` in purely numeric SQL fragments)
> - Custom escaping (`mysql_real_escape_string`, `addslashes`, homegrown sanitizers) is **not** equivalent to parameterization — still classify as Likely Vulnerable if taint is present
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the interpolated variable with no effective mitigation.
> - **Likely Vulnerable**: User input probably reaches the variable (indirect flow) or only weak mitigation (custom escaping) is present.
> - **Not Vulnerable**: The variable is server-side only, OR effective parameterization / allowlist validation is in place.
> - **Needs Manual Review**: Cannot determine the variable's origin with confidence (opaque helpers, complex flows, external libraries).
>
> **Output format** — write to `sast/sqli-batch-[N].md`:
>
> ```markdown
> # SQLi Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "HTTP query param `username` flows directly into f-string SELECT query"]
> - **Taint trace**: [Step-by-step from entry point to the construction site]
> - **Impact**: [What an attacker can do — extract records, bypass auth, delete data, etc.]
> - **Remediation**: [Parameterized query, ORM equivalent, or allowlist for identifiers]
> - **Dynamic Test**:
>   ```
>   [sqlmap command or manual curl payload. Show parameter, payload, expected response signal.
>    Example: sqlmap -u "https://app.example.com/search?q=test" -p q --dbs]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "Indirect flow or custom escaping only"]
> - **Taint trace**: [Best-effort trace; mark uncertain steps]
> - **Concern**: [Why it remains a risk]
> - **Remediation**: [Replace with parameterized query]
> - **Dynamic Test**:
>   ```
>   [payload to attempt bypass]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Server-side constant" or "Allowlist gates sort column"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why origin could not be determined]
> - **Suggestion**: [What to trace manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/sqli-batch-*.md` file and merge them into a single `sast/sqli-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/sqli-batch-1.md`, `sast/sqli-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (construction sites analyzed = total sites from recon that were batched, i.e., sum of sites across batches).
4. Write the merged report to `sast/sqli-results.md` using this format:

```markdown
# SQLi Analysis Results: [Project Name]

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

5. After writing `sast/sqli-results.md`, **delete all intermediate batch files** (`sast/sqli-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 construction sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any dynamic variable embedded in a SQL query string, regardless of origin. Do not trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint analysis**: for each assigned site, trace the interpolated variable back to its origin. If it comes from a user-controlled source, the site is a real vulnerability.
- Focus on **raw SQL and ORM raw/unsafe methods**. Standard ORM query builder calls (`.filter()`, `.where(col: val)`, `.find()`) are safe by default — do not flag them.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Taint can flow indirectly: a request parameter may be extracted in a middleware, stored in a shared object, passed through several helper functions, and finally reach the query construction. Trace the full chain.
- Custom escaping (including `mysql_real_escape_string`, `addslashes`, or homegrown sanitizers) is **not** equivalent to parameterization — flag as Likely Vulnerable even if escaping is present.
- For dynamic identifiers (column/table names), parameterization cannot help — the only safe fix is allowlist validation. Flag any dynamic identifier without an allowlist, regardless of whether it appears user-controlled.
- Second-order injection is easy to miss: a value stored in the DB from user input may later be read and used unsafely in a raw query elsewhere in the codebase. In Phase 2, treat DB-read values as potentially tainted and trace back to where they were written.
- Clean up intermediate files: delete `sast/sqli-recon.md` and all `sast/sqli-batch-*.md` files after the final `sast/sqli-results.md` is written.
