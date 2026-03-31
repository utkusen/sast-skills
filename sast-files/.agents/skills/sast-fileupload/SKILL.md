---
name: sast-fileupload
description: >-
  Detect insecure file upload vulnerabilities in a codebase using a three-phase
  approach: discovery (find all upload sites), batched verify (check extension
  bypass and related issues in parallel subagents, 3 sites each), and merge
  (consolidate batch results). Requires sast/architecture.md (run sast-analysis
  first). Outputs findings to sast/fileupload-results.md. Use when asked to find
  file upload, unrestricted upload, or extension bypass bugs.
---

# Insecure File Upload Detection

You are performing a focused security assessment to find insecure file upload vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **discovery** (find all places where uploaded files are received and stored), **batched verify** (check bypass vectors in parallel batches of up to 3 upload sites each), and **merge** (consolidate batch reports into one results file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is an Insecure File Upload

Insecure file upload occurs when an application accepts files from users without properly validating or restricting what can be uploaded, allowing an attacker to upload executable or malicious files. The most critical outcome is **Remote Code Execution (RCE)**: an attacker uploads a web shell (e.g., a `.php` file) and the server executes it when accessed via a direct URL.

The core pattern: *a user-supplied file reaches a storage location without adequate extension validation, and the stored file is accessible or executable.*

### What Insecure File Upload IS

- Accepting any file type with no extension or content check: `file.save(upload_path)` with no validation
- Content-Type-only validation: checking `Content-Type: image/png` without verifying the actual extension or file content — trivially bypassed by setting the header manually
- Extension blocklist with gaps: `.php` is blocked but `.php3`, `.php4`, `.php5`, `.phtml`, `.phar`, `.shtml` are not
- Case-insensitive bypass: blocking `.php` but allowing `.PHP`, `.Php`, `.pHp`
- Double extension bypass: `shell.php.jpg` — code extracts the last `.jpg` and considers it safe, but the server (Apache) serves it as PHP
- Path traversal in filenames: `../../webroot/shell.php` stored via an unsanitized filename
- Incomplete filename sanitization: only stripping `../` but not encoded variants `%2e%2e%2f`
- Serving uploaded files from a web-executable directory without disabling execution

### What Insecure File Upload is NOT

Do not flag these as file upload vulnerabilities:

- **Stored XSS via SVG**: uploading an SVG with embedded `<script>` that is reflected back — that's XSS, not an upload execution issue
- **SSRF via file content**: uploading an XML or SVG that triggers an outbound request — that's XXE/SSRF, not a file upload execution issue
- **DoS via large files**: missing file size limits — a separate availability issue
- **IDOR on download**: accessing another user's uploaded file without authorization — that's IDOR
- **Secure uploads**: files stored outside the web root, or served through a controlled download endpoint that sets `Content-Disposition: attachment`, or stored in an object storage bucket with no public execution capability

### Patterns That Prevent Insecure File Upload

When you see these patterns together, the code is likely **not vulnerable**:

**1. Allowlist of safe extensions (most important)**
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
ext = filename.rsplit('.', 1)[-1].lower()
if ext not in ALLOWED_EXTENSIONS:
    abort(400)
```

**2. Magic byte / file content validation (defense in depth)**
```python
import magic
mime = magic.from_buffer(file.read(2048), mime=True)
ALLOWED_MIMES = {'image/png', 'image/jpeg', 'image/gif'}
if mime not in ALLOWED_MIMES:
    abort(400)
```

**3. Filename sanitization using a trusted library**
```python
from werkzeug.utils import secure_filename
filename = secure_filename(file.filename)  # strips path separators and dangerous chars
```

**4. Storing uploads outside the web root**
```
/var/uploads/  ← not served by the web server
/var/www/html/ ← web root (do NOT store uploads here)
```

**5. Serving uploads through a controlled endpoint with Content-Disposition**
```python
@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename,
                               as_attachment=True)  # forces download, prevents execution
```

**6. Renaming the file to a server-generated UUID**
```python
import uuid
stored_name = str(uuid.uuid4()) + '.jpg'  # extension is server-controlled, not user-controlled
```

---

## Vulnerable vs. Secure Examples

### Python — Flask

```python
# VULNERABLE: no extension check, file stored in web-accessible directory
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(os.path.join('static/uploads', f.filename))
    return 'uploaded'

# VULNERABLE: content-type only check (trivially bypassed with curl -H)
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    if f.content_type not in ['image/png', 'image/jpeg']:
        abort(400)
    f.save(os.path.join('static/uploads', f.filename))
    return 'uploaded'

# VULNERABLE: blocklist — .phtml/.phar/.php5 not covered
BLOCKED = {'.php', '.sh', '.exe'}
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    ext = os.path.splitext(f.filename)[1].lower()
    if ext in BLOCKED:
        abort(400)
    f.save(os.path.join('static/uploads', f.filename))
    return 'uploaded'

# SECURE: allowlist + sanitized filename + outside web root
ALLOWED = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = '/var/uploads'  # outside web root

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    filename = secure_filename(f.filename)
    ext = filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED:
        abort(400)
    f.save(os.path.join(UPLOAD_FOLDER, filename))
    return 'uploaded'
```

### Python — Django

```python
# VULNERABLE: no validation on FileField
class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['upload']

# VULNERABLE: manual save with no extension check
def upload(request):
    f = request.FILES['file']
    with open(f'media/uploads/{f.name}', 'wb+') as dest:
        for chunk in f.chunks():
            dest.write(chunk)

# SECURE: custom validator on FileField
def validate_file_extension(value):
    ext = os.path.splitext(value.name)[1].lower()
    if ext not in ['.png', '.jpg', '.jpeg', '.gif']:
        raise ValidationError('Unsupported file extension.')

class DocumentForm(forms.ModelForm):
    upload = forms.FileField(validators=[validate_file_extension])
```

### Node.js — Multer (Express)

```javascript
// VULNERABLE: no file filter, stored in public directory
const upload = multer({ dest: 'public/uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
    res.send('uploaded');
});

// VULNERABLE: MIME type filter only (can be faked)
const upload = multer({
    dest: 'uploads/',
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) return cb(null, false);
        cb(null, true);
    }
});

// SECURE: allowlist of extensions + storage outside web root
const ALLOWED_EXT = ['.jpg', '.jpeg', '.png', '.gif'];
const storage = multer.diskStorage({
    destination: '/var/uploads',  // not served by Express
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${uuidv4()}${ext}`);
    }
});
const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, ALLOWED_EXT.includes(ext));
    }
});
```

### PHP

```php
// VULNERABLE: no extension check, stored in web root
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);

// VULNERABLE: checking only content type header
if ($_FILES['file']['type'] !== 'image/jpeg') {
    die('Invalid file type');
}
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);

// VULNERABLE: blocklist missing phtml/phar
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
$blocked = ['php', 'sh', 'py'];
if (in_array($ext, $blocked)) die('Blocked');
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);

// SECURE: allowlist + rename to UUID + outside web root
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) die('Invalid extension');
$stored = '/var/uploads/' . bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], $stored);
```

### Java — Spring Boot (MultipartFile)

```java
// VULNERABLE: no validation, stored in web-accessible path
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) throws IOException {
    Path path = Paths.get("src/main/resources/static/uploads/" + file.getOriginalFilename());
    Files.write(path, file.getBytes());
    return "uploaded";
}

// VULNERABLE: content type header only
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) throws IOException {
    if (!file.getContentType().startsWith("image/")) throw new BadRequestException();
    Files.write(Paths.get("uploads/" + file.getOriginalFilename()), file.getBytes());
    return "uploaded";
}

// SECURE: allowlist + UUID rename + path outside web root
private static final Set<String> ALLOWED = Set.of("jpg", "jpeg", "png", "gif");

@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) throws IOException {
    String original = StringUtils.cleanPath(file.getOriginalFilename());
    String ext = FilenameUtils.getExtension(original).toLowerCase();
    if (!ALLOWED.contains(ext)) throw new BadRequestException("Invalid extension");
    String stored = UUID.randomUUID() + "." + ext;
    Files.write(Paths.get("/var/uploads/" + stored), file.getBytes());
    return "uploaded";
}
```

### Go

```go
// VULNERABLE: no extension check, stored in static directory
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("file")
    defer file.Close()
    dst, _ := os.Create("static/uploads/" + header.Filename)
    defer dst.Close()
    io.Copy(dst, file)
}

// SECURE: allowlist extension + UUID rename + outside web root
var allowed = map[string]bool{"jpg": true, "jpeg": true, "png": true, "gif": true}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("file")
    defer file.Close()
    ext := strings.ToLower(filepath.Ext(header.Filename))
    if ext == "" || !allowed[ext[1:]] {
        http.Error(w, "invalid extension", http.StatusBadRequest)
        return
    }
    stored := "/var/uploads/" + uuid.New().String() + ext
    dst, _ := os.Create(stored)
    defer dst.Close()
    io.Copy(dst, file)
}
```

### Ruby on Rails

```ruby
# VULNERABLE: no content type or extension validation
def upload
  file = params[:file]
  File.open(Rails.root.join('public', 'uploads', file.original_filename), 'wb') do |f|
    f.write(file.read)
  end
end

# SECURE: ActiveStorage with content type allowlist (Rails 6+)
has_one_attached :avatar
validates :avatar, content_type: ['image/png', 'image/jpg', 'image/jpeg']
# Note: still validate extension too — content_type is user-supplied in some configurations

# SECURE: CarrierWave with extension and content type allowlist
class AvatarUploader < CarrierWave::Uploader::Base
  def extension_allowlist
    %w[jpg jpeg png gif]
  end

  def content_type_allowlist
    /image\//
  end
end
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: no extension check, stored in wwwroot
[HttpPost]
public async Task<IActionResult> Upload(IFormFile file) {
    var path = Path.Combine("wwwroot/uploads", file.FileName);
    using var stream = new FileStream(path, FileMode.Create);
    await file.CopyToAsync(stream);
    return Ok();
}

// SECURE: allowlist + GUID rename + outside web root
private static readonly HashSet<string> _allowed = new() { ".jpg", ".jpeg", ".png", ".gif" };

[HttpPost]
public async Task<IActionResult> Upload(IFormFile file) {
    var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
    if (!_allowed.Contains(ext)) return BadRequest("Invalid extension");
    var stored = Path.Combine("/var/uploads", $"{Guid.NewGuid()}{ext}");
    using var stream = new FileStream(stored, FileMode.Create);
    await file.CopyToAsync(stream);
    return Ok();
}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find All File Upload Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where files uploaded by users are received and stored. Write results to `sast/fileupload-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the framework, file storage patterns, and whether uploads go to local disk, cloud storage, or a CDN.
>
> **What to search for — file upload handling patterns**:
>
> Look for any code that receives a file from an HTTP request and writes or stores it. Do not yet evaluate whether validation is present — just find all the sites.
>
> 1. **Python / Django**:
>    - `request.FILES` access
>    - `InMemoryUploadedFile`, `TemporaryUploadedFile`
>    - `default_storage.save(...)`, `FileSystemStorage().save(...)`
>    - Model `FileField` / `ImageField` form submissions
>    - `shutil.copyfileobj(f, dest)` or manual `.write(f.read())` on uploaded data
>
> 2. **Python / Flask**:
>    - `request.files.get(...)` or `request.files[...]`
>    - `file.save(...)` calls on a `FileStorage` object
>    - `werkzeug` `FileStorage` handling
>
> 3. **Node.js**:
>    - `multer` middleware: `upload.single(...)`, `upload.array(...)`, `upload.fields(...)`
>    - `busboy`, `formidable`, `multiparty` form parsing
>    - `express-fileupload`: `req.files`
>    - `fs.writeFile` / `fs.createWriteStream` / `pipe()` called with a request stream
>
> 4. **PHP**:
>    - `$_FILES` access
>    - `move_uploaded_file(...)` calls
>    - `copy($_FILES[...]['tmp_name'], ...)`
>
> 5. **Java / Spring**:
>    - `MultipartFile` parameters in controller methods: `@RequestParam MultipartFile`
>    - `CommonsMultipartFile`, `StandardMultipartFile`
>    - `Part.write(...)` (Servlet API)
>    - `file.transferTo(...)`, `Files.write(path, file.getBytes())`
>
> 6. **Go**:
>    - `r.FormFile(...)` or `r.MultipartForm.File`
>    - `io.Copy(dst, file)` where `file` comes from a multipart form
>    - `os.Create(...)` called with a filename derived from `header.Filename`
>
> 7. **Ruby / Rails**:
>    - `params[:file]` with `.read`, `.original_filename`, `.tempfile`
>    - `File.open(..., 'wb')` called with uploaded data
>    - `has_one_attached` / `has_many_attached` (ActiveStorage)
>    - CarrierWave `mount_uploader`, Shrine `include Shrine::Attachment`
>
> 8. **C# / ASP.NET**:
>    - `IFormFile` parameters: `file.CopyToAsync(...)`, `file.OpenReadStream()`
>    - `HttpPostedFileBase.SaveAs(...)`
>    - `Request.Files[...]`
>
> **Output format** — write to `sast/fileupload-recon.md`:
>
> ```markdown
> # File Upload Recon: [Project Name]
>
> ## Summary
> Found [N] file upload sites.
>
> ## Upload Sites
>
> ### 1. [Descriptive name — e.g., "Avatar upload endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Framework / method**: [e.g., Flask request.files / multer / move_uploaded_file]
> - **Storage destination**: [path, variable, or storage abstraction — e.g., "static/uploads/" or "S3 via boto3" or "unknown"]
> - **Validation observed** (preliminary, Phase 2 will analyze in depth): [list any extension checks, content-type checks, or "none visible"]
> - **Code snippet**:
>   ```
>   [the upload receive and save code]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/fileupload-recon.md`. If the recon found **zero upload sites** (the summary reports "Found 0" or the "Upload Sites" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/fileupload-results.md` and stop:

```markdown
# File Upload Analysis Results

No file upload sites found.
```

Only proceed to Phase 2 if Phase 1 found at least one upload site.

### Phase 2: Check for Extension Bypass Vulnerabilities (Batched)

After Phase 1 completes, read `sast/fileupload-recon.md` and split the upload sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/fileupload-recon.md` and count the numbered site sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/fileupload-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Node.js with Multer, include only the "Node.js — Multer (Express)" examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned file upload site below, determine whether an attacker can upload a malicious file (e.g., a PHP web shell, a JSP shell, a Python script) by manipulating the filename, extension, or Content-Type header. Write results to `sast/fileupload-batch-[N].md`.
>
> **Your assigned upload sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the framework, storage paths, and how uploads are served.
>
> **Reference — what insecure file upload is and is not**:
>
> Focus on execution or dangerous file types reaching storage without adequate controls. Do **not** flag stored XSS via SVG, SSRF via uploaded XML, DoS via size limits, or IDOR on download as file-upload execution issues (other skills cover those).
>
> **Patterns that reduce risk** — if you see a strong combination (allowlist, sanitization, non-web-root storage, UUID rename), the site is likely **Not Vulnerable** unless bypass still applies.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each upload site, evaluate the following bypass vectors**:
>
> 1. **No extension check**: No validation of any kind on the filename or extension. Any file is accepted. Immediately flag as **Vulnerable**.
>
> 2. **Content-Type / MIME header only**: Validation reads `Content-Type` or `mimetype` from the request headers but does not inspect the actual filename extension or file bytes. Attackers can set `Content-Type: image/png` while uploading `shell.php`. Flag as **Vulnerable**.
>
> 3. **Blocklist-based validation**: An explicit list of forbidden extensions. Check whether the blocklist is exhaustive for the server's technology:
>    - **PHP servers**: Are `.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.phar`, `.shtml` also blocked? If any are missing, flag as **Vulnerable**.
>    - **Java servers**: Are `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf` also blocked?
>    - **ASP.NET servers**: Are `.asp`, `.aspx`, `.ashx`, `.asmx`, `.cer`, `.asa` also blocked?
>    - **Node.js**: Is `.js` execution possible via the server config? Check if `.js` files in the upload dir can be required/executed.
>    - Any blocklist is inherently weaker than an allowlist — flag as **Likely Vulnerable** even if seemingly complete.
>
> 4. **Case sensitivity bypass**: Blocking `.php` but not `.PHP`, `.Php`, `.pHp`. Check whether the comparison uses `.toLowerCase()` / `.lower()` / `strtolower()` / case-insensitive matching.
>
> 5. **Double extension / multi-extension**: `shell.php.jpg` — if the code extracts the extension using a method that takes the last segment after the last dot, this should be caught by an allowlist. However, on Apache servers with `AddHandler` misconfig, the leftmost recognized extension may be used for execution. Check how the extension is extracted:
>    - Safe: `filename.rsplit('.', 1)[-1]`, `path.extname(filename)` (takes the last extension)
>    - Risky server config: Apache `AddHandler application/x-httpd-php .php` — even `shell.php.jpg` may be executed as PHP
>
> 6. **Path traversal in filename**: If the original filename is used in the storage path without sanitization, `../../webroot/shell.php` can place files in unintended directories. Check for:
>    - Use of `secure_filename()`, `basename()`, `path.basename()`, `Path.GetFileName()`, or `filepath.Base()` — these strip directory separators and are safe
>    - Direct use of `file.filename`, `header.Filename`, `file.getOriginalFilename()`, `$_FILES['name']` in a path join without sanitization — flag as **Vulnerable**
>
> 7. **File stored in web-executable directory**: Even with a correct extension allowlist, if uploads go to a directory served by the web server (e.g., `static/uploads/`, `public/uploads/`, `wwwroot/uploads/`) and the web server is configured to execute scripts, a bypass in extension validation becomes critical. Note whether the storage path is web-accessible.
>
> 8. **No content-based validation (magic bytes)**: The server trusts the extension without verifying the actual file content. A file named `shell.jpg` with PHP code inside is still dangerous if the extension check can be bypassed and the server executes it. Note absence of magic-byte checking as a contributing weakness.
>
> **Classification**:
> - **Vulnerable**: No validation at all, or a clearly bypassable check (content-type only, missing common extensions in blocklist, missing `.lower()`, path traversal in filename).
> - **Likely Vulnerable**: Blocklist that appears complete but is inherently weaker than an allowlist; or an allowlist with potential edge cases (e.g., does not account for uppercase extensions).
> - **Not Vulnerable**: Strict allowlist of safe extensions (applied case-insensitively), combined with filename sanitization and/or server-generated UUID rename, files stored outside web root or behind a controlled download endpoint.
> - **Needs Manual Review**: Validation logic is in a shared helper or middleware that could not be fully read; or storage path is dynamic and could not be determined.
>
> **Output format** — write to `sast/fileupload-batch-[N].md`:
>
> ```markdown
> # File Upload Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "No extension validation — any file type accepted" or "Content-Type header used as sole check"]
> - **Bypass vector**: [Exact technique — e.g., "Upload shell.php directly" or "Set Content-Type: image/png while uploading a .php file" or "Use .phtml extension not covered by blocklist"]
> - **Storage path**: [Where the file lands — web-accessible or not]
> - **Impact**: [e.g., "Attacker uploads PHP web shell and achieves RCE by accessing /uploads/shell.php"]
> - **Remediation**: [Specific fix — switch to allowlist, add `.lower()`, use secure_filename, move storage outside web root]
> - **Dynamic Test**:
>   ```
>   [curl or HTTP request demonstrating the bypass.
>    Example: curl -X POST https://app.example.com/upload \
>      -F "file=@shell.php;type=image/png" \
>      then access: https://app.example.com/static/uploads/shell.php?cmd=id]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "Blocklist-based extension check — inherently incomplete"]
> - **Bypass vector**: [Possible bypass — e.g., "Try .phtml, .phar, .php5 if server is Apache/PHP"]
> - **Storage path**: [Where the file lands]
> - **Concern**: [Why it's still a risk]
> - **Remediation**: [Replace blocklist with allowlist]
> - **Dynamic Test**:
>   ```
>   [payload to attempt bypass]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Strict allowlist of png/jpg/gif with .lower(), UUID rename, stored outside web root"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why validation logic or storage path could not be determined]
> - **Suggestion**: [What to trace manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/fileupload-batch-*.md` file and merge them into a single `sast/fileupload-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/fileupload-batch-1.md`, `sast/fileupload-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (total sites analyzed equals the number from recon; counts per classification sum across batches).
4. Write the merged report to `sast/fileupload-results.md` using this format:

```markdown
# File Upload Analysis Results: [Project Name]

## Executive Summary
- Upload sites analyzed: [total from recon]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/fileupload-results.md`, **delete all intermediate batch files** (`sast/fileupload-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 upload sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely discovery**: find every place a user-supplied file is received and stored. Do not deeply analyze validation in Phase 1 — just note what is visible. That is Phase 2's job.
- **Phase 2 is purely bypass analysis**: for each assigned upload site, examine the validation logic and determine whether it can be bypassed through extension manipulation, case variation, content-type spoofing, or path traversal.
- **Phase 3 is merge only**: combine batch files into `sast/fileupload-results.md` and remove intermediates; do not re-analyze code in Phase 3.
- An allowlist is always stronger than a blocklist. Any blocklist-based approach should be flagged as at minimum **Likely Vulnerable** because blocklists are almost always incomplete.
- Content-Type (MIME type from the HTTP header) is **fully attacker-controlled** — never treat it as a security control.
- Case sensitivity matters: `.PHP` bypasses a check for `.php` if `.toLowerCase()` is missing. Always check.
- Path traversal in filenames is a separate attack vector from extension bypass — check for both.
- Even a correct extension check is weakened if the file is stored in a web-executable directory. Note storage location in every finding.
- Magic byte checking (reading actual file bytes) is defense-in-depth but does not replace extension allowlisting — a valid image with PHP code appended can still be dangerous.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete `sast/fileupload-recon.md` and all `sast/fileupload-batch-*.md` files after the final `sast/fileupload-results.md` is written.
