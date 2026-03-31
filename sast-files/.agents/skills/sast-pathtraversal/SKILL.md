---
name: sast-pathtraversal
description: >-
  Detect path traversal vulnerabilities in a codebase using a three-phase
  approach: recon (find file-loading sinks with dynamic paths), batched verify
  (trace user input and mitigations in parallel subagents, 3 sinks each), and
  merge (consolidate batch results). Requires sast/architecture.md (run
  sast-analysis first). Outputs findings to sast/pathtraversal-results.md. Use
  when asked to find path traversal, directory traversal, or file disclosure
  bugs.
---

# Path Traversal Detection

You are performing a focused security assessment to find path traversal vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find file-loading sinks with dynamic paths), **batched verify** (trace user input and check mitigations in parallel batches of 3), and **merge** (consolidate batch results into one report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Path Traversal

Path traversal (also called directory traversal) occurs when user-supplied input is incorporated into a file path that is then used to read, write, or serve files from the filesystem — without properly constraining the resulting path to an intended base directory. An attacker can supply sequences like `../` or encoded variants (`%2e%2e%2f`, `..%2f`, `%2e%2e/`) to escape the intended directory and access arbitrary files such as `/etc/passwd`, application source code, credentials, or private keys.

The core pattern: *unvalidated user input reaches a filesystem operation and the resolved path is not verified to remain within the intended base directory.*

### What Path Traversal IS

- Serving a user-requested filename directly from a base directory without canonicalizing and checking the resulting path:
  `open(os.path.join(BASE_DIR, user_filename))`
- Constructing a file path from a URL parameter and passing it to a file-read function:
  `fs.readFile(path.join(__dirname, req.query.file), ...)`
- Template rendering or include directives driven by user input:
  `include($_GET['page'] . '.php')`
- Archive extraction (`ZipFile`, `tarfile`, `zipslip`) where entry names are used as output paths without stripping `../` components
- Using `send_file()` / `send_from_directory()` / `res.sendFile()` with an unsanitized user-controlled path
- Reading a file whose path is derived from a user-controlled database value that was stored without sanitization

### What Path Traversal is NOT

Do not flag these as path traversal:

- **SSRF**: Fetching a remote URL from user input — that is Server-Side Request Forgery, a separate class
- **RCE via file write**: Writing attacker-controlled content to an arbitrary path — related but a different impact class (flag as RCE or File Upload)
- **Static file serving**: Serving files from a path that is entirely hardcoded with no user influence
- **Safe path joins followed by realpath + prefix check**: The code computes `realpath()` and verifies it starts with the intended base directory
- **basename() before join**: Using only the filename component strips traversal sequences (though note this prevents directory selection, not just traversal)

### Patterns That Prevent Path Traversal

When you see these mitigations applied **before** the file operation, the code is likely **not vulnerable**:

**1. `realpath` / `resolve` followed by a base-directory prefix check (most robust fix)**
```python
# Python
import os
BASE = '/var/www/files'
safe_path = os.path.realpath(os.path.join(BASE, user_input))
if not safe_path.startswith(BASE + os.sep):
    raise PermissionError("Path escape detected")
with open(safe_path) as f:
    ...
```

```javascript
// Node.js
const BASE = path.resolve('/var/www/files');
const resolved = path.resolve(BASE, req.query.file);
if (!resolved.startsWith(BASE + path.sep)) {
    return res.status(403).send('Forbidden');
}
fs.readFile(resolved, ...);
```

```java
// Java
Path base = Paths.get("/var/www/files").toRealPath();
Path resolved = base.resolve(userInput).normalize();
if (!resolved.startsWith(base)) {
    throw new SecurityException("Path escape");
}
Files.readAllBytes(resolved);
```

**2. `basename()` / `path.basename()` to strip directory components**
```python
# Python — strips all directory parts, only the filename remains
filename = os.path.basename(user_input)
with open(os.path.join(BASE, filename)) as f:
    ...
```

```php
// PHP
$filename = basename($_GET['file']);
readfile('/var/www/uploads/' . $filename);
```

**3. Allowlist of permitted filenames or extensions**
```python
ALLOWED = {'report.pdf', 'manual.txt', 'logo.png'}
if user_input not in ALLOWED:
    abort(400)
with open(os.path.join(BASE, user_input)) as f:
    ...
```

**4. Framework-provided safe file serving**
```python
# Flask — send_from_directory validates the path stays within the directory
return send_from_directory('/var/www/files', filename)

# Django — FileResponse with a path that was never user-controlled
```

---

## Vulnerable vs. Secure Examples

### Python — Flask

```python
# VULNERABLE: user-controlled filename joined without realpath check
@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('/var/www/files', filename)
    return send_file(filepath)

# SECURE: resolve and verify the path stays within the base directory
@app.route('/download')
def download():
    filename = request.args.get('file')
    base = os.path.realpath('/var/www/files')
    filepath = os.path.realpath(os.path.join(base, filename))
    if not filepath.startswith(base + os.sep):
        abort(403)
    return send_file(filepath)
```

### Python — FastAPI

```python
# VULNERABLE: path parameter used directly in file read
@app.get('/file/{name}')
async def get_file(name: str):
    return FileResponse(f'/app/static/{name}')

# SECURE: basename strips traversal sequences
@app.get('/file/{name}')
async def get_file(name: str):
    safe_name = os.path.basename(name)
    return FileResponse(os.path.join('/app/static', safe_name))
```

### Node.js — Express

```javascript
// VULNERABLE: req.query.file used directly in readFile
app.get('/file', (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.query.file);
  fs.readFile(filePath, (err, data) => res.send(data));
});

// SECURE: resolve and check prefix
app.get('/file', (req, res) => {
  const base = path.resolve(__dirname, 'uploads');
  const filePath = path.resolve(base, req.query.file);
  if (!filePath.startsWith(base + path.sep)) {
    return res.status(403).send('Forbidden');
  }
  fs.readFile(filePath, (err, data) => res.send(data));
});
```

### PHP

```php
// VULNERABLE: direct inclusion of user input
<?php
$page = $_GET['page'];
include($page . '.php');

// VULNERABLE: readfile with unsanitized path
$file = $_GET['file'];
readfile('/var/www/uploads/' . $file);

// SECURE: basename strips directory components
$file = basename($_GET['file']);
readfile('/var/www/uploads/' . $file);

// SECURE: realpath + prefix check
$base = realpath('/var/www/uploads');
$path = realpath($base . '/' . $_GET['file']);
if ($path === false || strpos($path, $base . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(403);
    exit;
}
readfile($path);
```

### Ruby on Rails

```ruby
# VULNERABLE: params[:file] used directly in file read
def show
  file_path = Rails.root.join('public', 'reports', params[:file])
  send_file file_path
end

# SECURE: basename only
def show
  safe_name = File.basename(params[:file])
  send_file Rails.root.join('public', 'reports', safe_name)
end
```

### Java — Spring

```java
// VULNERABLE: path variable used directly to read file
@GetMapping("/file/{name}")
public ResponseEntity<Resource> getFile(@PathVariable String name) throws IOException {
    Path filePath = Paths.get("/var/www/files").resolve(name);
    Resource resource = new UrlResource(filePath.toUri());
    return ResponseEntity.ok(resource);
}

// SECURE: normalize and check prefix
@GetMapping("/file/{name}")
public ResponseEntity<Resource> getFile(@PathVariable String name) throws IOException {
    Path base = Paths.get("/var/www/files").toRealPath();
    Path resolved = base.resolve(name).normalize();
    if (!resolved.startsWith(base)) {
        return ResponseEntity.status(403).build();
    }
    Resource resource = new UrlResource(resolved.toUri());
    return ResponseEntity.ok(resource);
}
```

### Go

```go
// VULNERABLE: query param joined directly to base directory
func fileHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    http.ServeFile(w, r, filepath.Join("/var/www/files", name))
}

// SECURE: filepath.Clean + prefix check
func fileHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    base := "/var/www/files"
    clean := filepath.Join(base, filepath.Clean("/"+name))
    if !strings.HasPrefix(clean, base+string(os.PathSeparator)) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, clean)
}
```

### Archive Extraction (ZipSlip)

```python
# VULNERABLE: ZipSlip — zip entry names can contain ../
import zipfile
with zipfile.ZipFile(user_zip) as zf:
    zf.extractall('/var/www/uploads')

# SECURE: validate each entry path stays within the target directory
import zipfile, os
base = os.path.realpath('/var/www/uploads')
with zipfile.ZipFile(user_zip) as zf:
    for member in zf.namelist():
        target = os.path.realpath(os.path.join(base, member))
        if not target.startswith(base + os.sep):
            raise ValueError(f"ZipSlip detected: {member}")
    zf.extractall(base)
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find File-Loading Sinks With Dynamic Paths

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a file is opened, read, served, or extracted using a dynamically constructed path — meaning the path (or a component of it) is stored in a variable rather than being a fully hardcoded string. Write results to `sast/pathtraversal-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, web framework, file-serving patterns, and any file upload or download features.
>
> **What to search for — file-loading sinks with dynamic path components**:
>
> Flag any call to a file-reading/serving function where the path argument contains a variable (regardless of where the variable comes from). You are **not** tracing user input in this phase — that is Phase 2's job. Just find all dynamic file access patterns.
>
> 1. **Direct file open / read calls with a variable path**:
>    - Python: `open(var)`, `open(os.path.join(..., var))`, `pathlib.Path(var).read_text()`, `pathlib.Path(var).read_bytes()`
>    - Node.js: `fs.readFile(var, ...)`, `fs.readFileSync(var)`, `fs.createReadStream(var)`
>    - PHP: `file_get_contents(var)`, `fopen(var, ...)`, `readfile(var)`, `include(var)`, `require(var)`, `include_once(var)`, `require_once(var)`
>    - Ruby: `File.read(var)`, `File.open(var)`, `IO.read(var)`, `IO.binread(var)`
>    - Java: `new FileInputStream(var)`, `new File(var)`, `Files.readAllBytes(Paths.get(var))`, `Files.newInputStream(path)`
>    - Go: `os.Open(var)`, `os.ReadFile(var)`, `ioutil.ReadFile(var)`, `os.OpenFile(var, ...)`
>    - C#: `File.ReadAllText(var)`, `File.ReadAllBytes(var)`, `new FileStream(var, ...)`, `System.IO.File.Open(var, ...)`
>
> 2. **Framework file-serving calls with a variable path**:
>    - Flask: `send_file(var)`, `send_from_directory(base, var)`
>    - FastAPI / Starlette: `FileResponse(var)`
>    - Django: `FileResponse(open(var, 'rb'))`, `StreamingHttpResponse` over an opened file
>    - Express: `res.sendFile(var)`, `res.download(var)`, `express.static` with dynamic root
>    - Spring: `new UrlResource(path.toUri())`, `ResourceLoader.getResource(var)`, `ClassPathResource(var)`
>    - Rails: `send_file var`, `render file: var`
>    - Go: `http.ServeFile(w, r, var)`, `http.ServeContent(w, r, var, ...)`
>
> 3. **Path construction functions where at least one component is a variable**:
>    - `os.path.join(BASE, var)`, `os.path.join(var1, var2)`
>    - `path.join(__dirname, var)`, `path.resolve(base, var)`
>    - `Paths.get(base).resolve(var)`
>    - `filepath.Join(base, var)`
>    - String concatenation used as a path: `BASE + var`, `f"{BASE}/{var}"`, `` `${base}/${var}` ``
>
> 4. **Archive extraction with user-supplied archives** (ZipSlip pattern):
>    - Python: `zipfile.ZipFile.extractall(...)`, `tarfile.TarFile.extractall(...)`
>    - Java: `ZipEntry.getName()` used as an output path
>    - Node.js: `unzipper`, `adm-zip`, `node-tar` extraction calls
>    - Go: `archive/zip` or `archive/tar` extraction without entry-name validation
>
> **What to skip** (these have no dynamic path component — do not flag):
> - File paths that are fully hardcoded string literals with no variable parts
> - Paths derived entirely from server-side config / environment variables with no user-supplied component (e.g., `open(settings.LOG_FILE)` where `LOG_FILE` is a config value)
> - Framework built-in static file middleware where the root directory is hardcoded (e.g., `express.static('public')` with a fixed root)
>
> **Output format** — write to `sast/pathtraversal-recon.md`:
>
> ```markdown
> # Path Traversal Recon: [Project Name]
>
> ## Summary
> Found [N] locations where files are accessed using dynamically constructed paths.
>
> ## File-Loading Sinks
>
> ### 1. [Descriptive name — e.g., "Dynamic readFile in download endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Sink**: [open / fs.readFile / send_file / include / FileInputStream / etc.]
> - **Path construction**: [os.path.join / path.join / string concat / f-string / etc.]
> - **Dynamic variable(s)**: `var_name` — [brief note on what it appears to represent, e.g., "looks like a filename from request" or "unknown origin"]
> - **Code snippet**:
>   ```
>   [the path construction + file operation call]
>   ```
>
> [Repeat for each sink]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/pathtraversal-recon.md`. If the recon found **zero file-loading sinks** (the summary reports "Found 0" or the "File-Loading Sinks" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/pathtraversal-results.md`, then delete `sast/pathtraversal-recon.md`, and stop:

```markdown
# Path Traversal Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one file-loading sink.

### Phase 2: Verify — Trace Taint and Check Mitigations (Batched)

After Phase 1 completes, read `sast/pathtraversal-recon.md` and split the file-loading sinks into **batches of up to 3 sinks each**. Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned sinks and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/pathtraversal-recon.md` and count the numbered sink sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sinks → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those sink sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sinks.
5. Each subagent writes to `sast/pathtraversal-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above (and "Patterns That Prevent Path Traversal" / "What Path Traversal is NOT" as reference). For example, if the project uses Node.js/Express, include the "Node.js — Express" block. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned file-loading sink, determine whether a user-supplied value reaches the dynamic path variable AND whether any mitigation prevents the path from escaping the intended base directory. Our goal is to find path traversal vulnerabilities. Write results to `sast/pathtraversal-batch-[N].md`.
>
> **Your assigned sinks** (from the recon phase):
>
> [Paste the full text of the assigned sink sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, and how data flows through the application.
>
> **Path traversal reference** — what to look for:
>
> User-supplied input incorporated into a filesystem path without constraining the resolved path to an intended base directory (including ZipSlip-style archive extraction). Do **not** flag SSRF, pure RCE/file-write classes, fully hardcoded paths, or safe `realpath`/`resolve` + base prefix checks as path traversal (see the skill's "What Path Traversal is NOT" and "Patterns That Prevent Path Traversal" sections in the main skill document if needed).
>
> **For each sink, perform two checks**:
>
> **Check A — Is the path variable user-controlled?**
>
> Trace the dynamic variable(s) backwards to their origin:
>
> 1. **Direct user input** — the variable is assigned directly from a request source:
>    - HTTP query params: `request.GET.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `c.Query("x")`
>    - Path parameters: `request.path_params['name']`, `req.params.name`, `params[:name]`, `c.Param("name")`
>    - Request body / form fields: `request.POST.get(...)`, `req.body.x`, `params[:x]`, `$_POST['x']`
>    - HTTP headers: `request.headers.get(...)`, `req.headers['x']`
>    - Cookies: `request.COOKIES.get(...)`, `req.cookies.x`
>    - Multipart filename: `file.filename`, `req.file.originalname`, `$_FILES['file']['name']`
>
> 2. **Indirect user input** — the variable is derived from user input through transformations, intermediate assignments, or function calls. Trace the full chain:
>    - Variable assigned from a helper function → check the function's source
>    - Variable passed as an argument → check all call sites
>    - Variable read from a database value that was originally stored from user input
>
> 3. **Server-side / hardcoded value** — the variable comes from config, an environment variable, a hardcoded constant, or server-side logic with no user influence — this sink is NOT exploitable via path traversal.
>
> **Check B — Is path escape prevented by an effective mitigation?**
>
> Even if user input reaches the path, the following mitigations prevent traversal. Check whether they are applied **before** the file operation and applied **correctly**:
>
> - **`realpath` / `os.path.realpath()` + base-directory prefix check**: resolves symlinks and `..` sequences, then verifies the result starts with the intended base. This is the strongest fix.
>   - `os.path.realpath(path).startswith(BASE + os.sep)` — effective ✓
>   - `os.path.realpath(path).startswith(BASE)` without trailing separator — potentially bypassable if BASE is a prefix of another directory name ✗
> - **`path.resolve()` + `startsWith(base + sep)`** (Node.js) — effective ✓
> - **`Paths.get(...).normalize()` + `startsWith(base)`** (Java) — effective only if `base` was also obtained via `toRealPath()` ✓
> - **`filepath.Clean()` + `strings.HasPrefix(clean, base+sep)`** (Go) — effective ✓
> - **`basename()` / `path.basename()` / `File.basename()`** — strips all directory components; effective at preventing traversal but prevents subdirectory access
> - **Allowlist of permitted filenames** — fully effective if the allowlist is strict and the input is compared against it before use
> - **Framework `send_from_directory`** (Flask) — Flask's `send_from_directory` internally calls `safe_join` which raises an error on traversal; effective ✓
>
> Mitigations that are **insufficient**:
> - Stripping `../` with a simple `replace('../', '')` — bypassable with `....//` or URL encoding
> - Checking that input does not start with `/` — does not prevent relative traversal
> - Using `os.path.join` alone without `realpath` — `os.path.join('/base', '../etc/passwd')` still produces `/etc/passwd`
> - URL-decoding the input once — attackers can double-encode: `%252e%252e%252f` → `%2e%2e%2f` → `../`
> - Type validation (e.g., checking the extension is `.pdf`) without a path escape check — an attacker can use `../../etc/passwd%00.pdf` (null-byte) on older systems or frame the path to have the right extension at the end
>
> **Vulnerable vs. secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the path variable AND no effective mitigation is in place before the file operation.
> - **Likely Vulnerable**: User input probably reaches the path variable (indirect flow), or a weak/incomplete mitigation is present (e.g., `replace('../', '')`, no trailing-separator in prefix check).
> - **Not Vulnerable**: The path variable is server-side only, OR an effective mitigation (`realpath` + prefix check, `basename`, strict allowlist, safe framework helper) is correctly applied.
> - **Needs Manual Review**: Cannot determine the variable's origin with confidence (passes through opaque helpers or complex conditional flows), or the mitigation logic is non-standard and hard to evaluate statically.
>
> **Output format** — write to `sast/pathtraversal-batch-[N].md`:
>
> ```markdown
> # Path Traversal Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "HTTP query param `file` flows directly into os.path.join without realpath check"]
> - **Taint trace**: [Step-by-step from entry point to the file operation]
> - **Missing mitigation**: [What check is absent]
> - **Impact**: Read arbitrary files accessible to the process user, including `/etc/passwd`, application config, source code, private keys.
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [curl command or payload to confirm; show traversal and encoded variants as appropriate]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "Variable likely sourced from user input via helper" or "Weak mitigation: strips ../ but bypassable with ....//"]
> - **Taint trace**: [Best-effort trace with the uncertain step identified]
> - **Concern**: [Why it remains a risk despite partial mitigation]
> - **Remediation**: [Apply realpath + prefix check or basename before joining]
> - **Dynamic Test**:
>   ```
>   [payloads to attempt bypass of the partial mitigation]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Path is derived entirely from server-side config" or "os.path.realpath() + prefix check correctly applied"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the variable's origin or mitigation could not be determined]
> - **Suggestion**: [What to trace manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/pathtraversal-batch-*.md` file and merge them into a single `sast/pathtraversal-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/pathtraversal-batch-1.md`, `sast/pathtraversal-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/pathtraversal-results.md` using this format:

```markdown
# Path Traversal Analysis Results: [Project Name]

## Executive Summary
- Sinks analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/pathtraversal-results.md`, **delete all intermediate batch files** (`sast/pathtraversal-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sinks per subagent**. If there are 1-3 sinks total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sinks' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any file-loading sink where the path has a dynamic component, regardless of origin. Do not attempt to trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is taint analysis + mitigation review**: for each sink found in Phase 1, (a) trace the path variable back to its origin and (b) check whether an effective mitigation prevents escape from the intended directory.
- `os.path.join` and `path.join` alone do **not** prevent traversal — `os.path.join('/base', '../etc/passwd')` resolves to `/etc/passwd`. Only `realpath` + prefix check prevents this.
- Encoded traversal variants (`%2e%2e%2f`, `%252e%252e%252f`, `..%2f`, `%2e%2e/`) bypass naive string-match filters; only filesystem-level resolution (`realpath`) handles them reliably.
- `send_from_directory` in Flask is safe by itself (it calls `safe_join` internally) — do not flag it unless user input is also used as the *base directory* argument.
- Archive extraction (ZipSlip) is a path traversal variant: zip/tar entry names can contain `../` sequences. Flag any extraction that uses entry names as output paths without per-entry validation.
- Second-order traversal is possible: a filename stored in the DB from user input may later be used in a file read elsewhere in the codebase. Treat DB-read path values as potentially tainted and trace back to where they were written.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete `sast/pathtraversal-recon.md` and all `sast/pathtraversal-batch-*.md` files after the final `sast/pathtraversal-results.md` is written.
