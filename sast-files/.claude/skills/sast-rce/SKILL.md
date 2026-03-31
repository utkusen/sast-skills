---
name: sast-rce
description: >-
  Detect Remote Code Execution (RCE) vulnerabilities in a codebase using a
  three-phase approach: recon (find dangerous execution sinks), batched verify
  (trace user input to sinks in parallel subagents, 3 sinks each), and merge
  (consolidate batch results). Covers OS command injection, eval-like sinks,
  and unsafe deserialization. Requires sast/architecture.md (run sast-analysis
  first). Outputs findings to sast/rce-results.md. Use when asked to find RCE,
  command injection, or unsafe deserialization bugs.
---

# Remote Code Execution (RCE) Detection

You are performing a focused security assessment to find Remote Code Execution vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find dangerous execution sinks), **batched verify** (trace whether user-supplied input reaches each sink in parallel batches of 3), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Remote Code Execution

Remote Code Execution (RCE) occurs when an attacker can cause the application to execute arbitrary OS commands or application-level code that they control. This is typically the highest-severity vulnerability class, often resulting in complete server compromise.

RCE arises from three primary root causes:

1. **OS Command Injection**: User input is embedded unsafely into an OS command string, allowing shell metacharacters to inject additional commands.
2. **Code Injection (eval-like)**: User input is passed to functions that interpret it as executable code (`eval`, `exec`, `Function()`, etc.).
3. **Unsafe Deserialization**: User-supplied serialized data is deserialized using a gadget-prone deserializer, triggering arbitrary code execution via crafted payloads.

### What RCE IS

- Passing user input directly or indirectly into OS command execution functions with shell interpretation enabled
- Using `eval()`, `exec()`, `Function()`, or equivalent constructs with user-controlled strings
- Deserializing user-supplied bytes/strings with inherently unsafe deserializers (pickle, PHP unserialize, Java native serialization, Ruby Marshal, etc.)
- Using `yaml.load()` without a safe loader on user-supplied content
- Dynamic `require()`/`import()` with user-controlled module paths
- PHP file inclusion (`include`/`require`) with user-controlled paths

### What RCE is NOT

Do not flag these as RCE:

- **SSRF**: Making HTTP requests to attacker-controlled URLs — different vulnerability class (no code execution)
- **Path Traversal**: Reading/writing arbitrary files — separate class (unless the read file is then executed/deserialized)
- **SSTI**: Template injection via template engines — a separate though related class; flag as SSTI, not RCE
- **XSS**: JavaScript execution in a victim's browser — client-side only, not server-side RCE
- **SQL Injection**: Injecting into database queries — different class (even if `xp_cmdshell` can lead to OS commands, flag it as SQLi)
- **Safe subprocess list-form calls**: `subprocess.run(["ls", user_arg])` with a list and no `shell=True` — arguments are passed directly to the OS without shell expansion; not vulnerable to command injection
- **Safe deserialization**: `json.loads()`, `yaml.safe_load()`, `xml.etree.ElementTree.parse()` — these formats have no code execution semantics

### Patterns That Prevent RCE

When you see these patterns, the code is likely **not vulnerable**:

**1. Subprocess list form without shell interpretation**
```
# Python — list args, no shell=True
subprocess.run(["convert", "-resize", size, input_file, output_file])
subprocess.Popen(["git", "clone", repo_url])

# Node.js — spawn with separate args (no shell)
child_process.spawn("ffmpeg", ["-i", inputFile, outputFile])

# Java — ProcessBuilder with list
new ProcessBuilder("ls", "-la", dir).start()

# Ruby — system() with multiple args (not a single interpolated string)
system("ffmpeg", "-i", "input.mp4", "-f", format, "output")
```

**2. Safe deserialization formats**
```
# Python — JSON instead of pickle
import json
data = json.loads(user_input)  # no code execution semantics

# Python — safe YAML loader
import yaml
data = yaml.safe_load(user_input)  # restricts to basic types only

# Java — Jackson without enableDefaultTyping, with concrete target type
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(json, MyClass.class);  # safe
```

**3. Strict allowlist before command construction**
```
# Python — allowlist for dynamic arguments
ALLOWED_FORMATS = {"png", "jpg", "webp"}
if fmt not in ALLOWED_FORMATS:
    return abort(400)
subprocess.run(["convert", infile, f"output.{fmt}"])

# Node.js — allowlist for dynamic args
const ALLOWED_COMMANDS = ['ls', 'pwd'];
if (!ALLOWED_COMMANDS.includes(cmd)) return res.status(400).end();
spawn(cmd, []);
```

---

## Vulnerable vs. Secure Examples

### OS Command Injection — Python

```python
# VULNERABLE: shell=True with f-string
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout
# Payload: ?host=127.0.0.1;id  → executes "id"

# VULNERABLE: os.system with string formatting
def convert_image(filename):
    size = request.form.get('size')
    os.system(f"convert {filename} -resize {size} output.jpg")

# SECURE: list-form subprocess, no shell
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return result.stdout
```

### OS Command Injection — Node.js

```javascript
// VULNERABLE: exec with template literal
app.get('/search', (req, res) => {
  const query = req.query.q;
  exec(`grep -r "${query}" /var/log/app/`, (err, stdout) => {
    res.send(stdout);
  });
});
// Payload: ?q=foo" /etc/passwd "

// VULNERABLE: execSync with concatenation
function runScript(userScript) {
  return execSync('node scripts/' + userScript);
}

// SECURE: spawn with separate args
app.get('/search', (req, res) => {
  const query = req.query.q;
  const proc = spawn('grep', ['-r', query, '/var/log/app/']);
  proc.stdout.on('data', (data) => res.write(data));
  proc.on('close', () => res.end());
});
```

### OS Command Injection — PHP

```php
// VULNERABLE: shell_exec with user input
function generateThumbnail($file) {
    $size = $_GET['size'];
    shell_exec("convert {$file} -resize {$size} thumb.jpg");
}

// VULNERABLE: backtick operator
function checkHost() {
    $host = $_POST['host'];
    $result = `ping -c 1 $host`;
    return $result;
}

// SECURE: escapeshellarg (reduces risk — but prefer removing shell entirely)
function generateThumbnail($file) {
    $size = escapeshellarg($_GET['size']);
    $file = escapeshellarg($file);
    shell_exec("convert $file -resize $size thumb.jpg");
}
```

### OS Command Injection — Ruby

```ruby
# VULNERABLE: string interpolation in system()
get '/convert' do
  format = params[:format]
  system("ffmpeg -i input.mp4 -f #{format} output")
end

# VULNERABLE: backtick with user input
def check_dns
  `nslookup #{params[:host]}`
end

# SECURE: system() with separate args (no shell expansion)
get '/convert' do
  format = params[:format]
  ALLOWED = %w[mp4 avi mkv]
  return 400 unless ALLOWED.include?(format)
  system("ffmpeg", "-i", "input.mp4", "-f", format, "output")
end
```

### Code Injection — Python eval/exec

```python
# VULNERABLE: eval with user input
@app.route('/calculate')
def calculate():
    expr = request.args.get('expr')
    result = eval(expr)  # attacker can run __import__('os').system('id')
    return str(result)

# VULNERABLE: exec with user code
@app.route('/run')
def run_code():
    code = request.json.get('code')
    exec(code)  # full arbitrary code execution
    return "ok"

# SECURE: ast.literal_eval for safe expression parsing (literals only)
from ast import literal_eval
@app.route('/parse')
def parse():
    data = request.args.get('data')
    result = literal_eval(data)  # only parses strings/numbers/lists/dicts/bools
    return str(result)
```

### Code Injection — JavaScript eval / Function

```javascript
// VULNERABLE: eval with user input
app.post('/formula', (req, res) => {
  const formula = req.body.formula;
  const result = eval(formula);  // RCE: process.exit(), require('child_process')...
  res.json({ result });
});

// VULNERABLE: new Function() constructor
function compute(userExpression) {
  const fn = new Function('x', `return ${userExpression}`);
  return fn(42);
}

// VULNERABLE: vm.runInNewContext (sandbox escape via __proto__ pollution)
const vm = require('vm');
app.post('/eval', (req, res) => {
  const result = vm.runInNewContext(req.body.code);
  res.json({ result });
});

// SECURE: use a math expression library (no arbitrary code)
const { evaluate } = require('mathjs');
app.post('/formula', (req, res) => {
  const result = evaluate(req.body.formula);  // sandboxed math expressions only
  res.json({ result });
});
```

### Unsafe Deserialization — Python pickle

```python
# VULNERABLE: deserializing user-supplied pickle data
@app.route('/load', methods=['POST'])
def load_session():
    data = request.get_data()
    session = pickle.loads(data)  # attacker controls __reduce__ → RCE
    return jsonify(session)

# VULNERABLE: base64-encoded pickle from cookie
@app.route('/profile')
def profile():
    session_cookie = request.cookies.get('session')
    data = base64.b64decode(session_cookie)
    user = pickle.loads(data)  # crafted cookie → arbitrary code at deserialization
    return render_template('profile.html', user=user)

# SECURE: use JSON (no code execution semantics)
@app.route('/profile')
def profile():
    session_cookie = request.cookies.get('session')
    user = json.loads(base64.b64decode(session_cookie))
    return render_template('profile.html', user=user)
```

### Unsafe Deserialization — Java

```java
// VULNERABLE: ObjectInputStream.readObject() on user-supplied stream
@PostMapping("/deserialize")
public ResponseEntity<?> deserialize(@RequestBody byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject();  // gadget chains (Commons Collections, Spring, etc.) → RCE
    return ResponseEntity.ok(obj);
}

// VULNERABLE: Jackson with enableDefaultTyping
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // attacker specifies arbitrary class type in JSON → RCE
MyData data = mapper.readValue(userJson, MyData.class);

// SECURE: Jackson with concrete type, no enableDefaultTyping
ObjectMapper mapper = new ObjectMapper();
MyData data = mapper.readValue(userJson, MyData.class);  // safe with concrete target type
```

### Unsafe Deserialization — PHP

```php
// VULNERABLE: unserialize() with user input
function loadProfile() {
    $data = base64_decode($_COOKIE['profile']);
    $user = unserialize($data);  // PHP object injection → POP chain → RCE
    return $user;
}

// VULNERABLE: unserialize from POST body
$obj = unserialize($_POST['data']);

// SECURE: json_decode instead
function loadProfile() {
    $data = base64_decode($_COOKIE['profile']);
    $user = json_decode($data, true);  // no code execution semantics
    return $user;
}
```

### Unsafe Deserialization — Ruby Marshal

```ruby
# VULNERABLE: Marshal.load with user-supplied data
post '/restore' do
  data = Base64.decode64(params[:state])
  object = Marshal.load(data)  # arbitrary Ruby object graph → RCE via gadgets
  object.process
end

# SECURE: use JSON
post '/restore' do
  data = JSON.parse(Base64.decode64(params[:state]))
  # work with plain data structures only
end
```

### Unsafe Deserialization — Node.js

```javascript
// VULNERABLE: node-serialize (known RCE via IIFE in serialized string)
const serialize = require('node-serialize');
app.post('/restore', (req, res) => {
  const obj = serialize.unserialize(req.body.data);  // IIFE payload → RCE
  res.json(obj);
});

// VULNERABLE: js-yaml v3 yaml.load (executes JS functions in YAML tags)
const yaml = require('js-yaml');
const data = yaml.load(userInput);  // !!js/function payload → RCE

// SECURE: yaml.safeLoad (v3) or FAILSAFE_SCHEMA (v4)
const data = yaml.safeLoad(userInput);  // only loads plain data types
```

### Unsafe YAML — Python

```python
# VULNERABLE: yaml.load without Loader
import yaml
data = yaml.load(user_input)  # !!python/object/apply: payload → RCE

# SECURE: yaml.safe_load
data = yaml.safe_load(user_input)  # only loads basic data types
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find Dangerous Execution Sinks

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where OS commands are executed, code is dynamically evaluated, or data is deserialized using an unsafe deserializer. Flag ANY dynamic variable passed to these sinks, regardless of where it originates. Write results to `sast/rce-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, language, frameworks, and any serialization patterns in use.
>
> ---
>
> **Category 1 — OS Command Execution Sinks**
>
> Look for functions that execute OS commands where the command string or arguments may be dynamically constructed. Flag when any non-constant variable appears in a dangerous position:
>
> **Python:**
> - `os.system(var)` — always flag if any variable
> - `os.popen(var)` — always flag if any variable
> - `subprocess.run(var, shell=True)`, `subprocess.call(var, shell=True)`, `subprocess.Popen(var, shell=True)`, `subprocess.check_output(var, shell=True)` — flag if `shell=True` AND a variable appears in the command string, OR if the command is a string (not a list) with any variable
> - `subprocess.run(f"cmd {var}")` without `shell=True` — flag: passing a string (not list) to subprocess can still be unsafe
> - `commands.getoutput(var)`, `commands.getstatusoutput(var)` — always flag
>
> **Node.js / JavaScript:**
> - `child_process.exec(var)`, `child_process.execSync(var)` — flag if any variable in command string
> - `child_process.execFile(var, ...)` — flag if command or args contain variables
> - `child_process.spawn(var, ...)` or `spawn(cmd, args)` with `shell: true` and variable in command — flag
> - `shelljs.exec(var)`, `execa(var)` — flag if variable in command
>
> **PHP:**
> - `exec(var)`, `system(var)`, `passthru(var)`, `shell_exec(var)`, `popen(var, ...)`, `proc_open(var, ...)` — flag if any variable in command string
> - Backtick operator: `` `...{$var}...` `` or `` `$var` `` — always flag
>
> **Ruby:**
> - `system(var)`, `exec(var)`, `spawn(var)`, `IO.popen(var)`, `Open3.popen3(var)` — flag if string form with interpolated variable
> - Backtick operator: `` `...#{var}...` `` — always flag
> - `%x{...#{var}...}` — always flag
>
> **Java:**
> - `Runtime.getRuntime().exec(var)` — flag if string argument contains variable concatenation
> - `new ProcessBuilder(var)` or `ProcessBuilder` constructed from variable-containing list — flag
>
> **Go:**
> - `exec.Command(var, ...)` — flag if command name or arguments are dynamically built from variables (especially from string splits of external input)
>
> **C# / .NET:**
> - `Process.Start(var)` — flag if FileName or Arguments are variable
> - `ProcessStartInfo { FileName = var, Arguments = var }` — flag
>
> ---
>
> **Category 2 — Code Evaluation Sinks**
>
> Look for functions that interpret strings as executable code:
>
> **Python:**
> - `eval(var)` — flag if argument is a variable
> - `exec(var)` — flag if argument is a variable
> - `compile(var, ...)` followed by `exec()` — flag
> - `importlib.import_module(var)`, `__import__(var)` — flag if module name is a variable
>
> **JavaScript / Node.js:**
> - `eval(var)` — flag if argument is a variable
> - `new Function(var)`, `new Function('x', var)` — flag if body is a variable
> - `setTimeout(var, delay)`, `setInterval(var, delay)` — flag if first arg is a string variable
> - `vm.runInNewContext(var)`, `vm.runInContext(var)`, `vm.runInThisContext(var)` — flag if variable
> - `require(var)` — flag if module path is a variable (dynamic require with external input → path traversal + potential code execution)
>
> **PHP:**
> - `eval(var)` — always flag if variable in argument
> - `preg_replace(pattern, replacement, subject)` with `/e` modifier in pattern — always flag
> - `assert(var)` with string argument — flag if variable
> - `create_function('', var)` — flag if body is variable
> - `call_user_func(var)`, `call_user_func_array(var, ...)` — flag if function name is a variable
>
> **Ruby:**
> - `eval(var)`, `instance_eval(var)`, `class_eval(var)`, `module_eval(var)` — flag if variable
> - `binding.eval(var)` — flag if variable
>
> ---
>
> **Category 3 — Unsafe Deserialization Sinks**
>
> Look for deserialization of data that may originate externally. For deserialization sinks, flag every usage — the question of whether data is user-controlled is Phase 2's job:
>
> **Python:**
> - `pickle.loads(var)`, `pickle.load(file_var)` — flag always (pickle is inherently unsafe with untrusted data)
> - `marshal.loads(var)`, `marshal.load(file_var)` — flag always
> - `yaml.load(var)` without explicit `Loader=yaml.SafeLoader` — flag (any form without a safe loader)
> - `jsonpickle.decode(var)` — flag always
> - `shelve` accessed with externally-influenced keys
>
> **Java:**
> - `ObjectInputStream.readObject()`, `ObjectInputStream.readUnshared()` — flag always
> - `XMLDecoder.readObject()` — flag always
> - `XStream.fromXML(var)` — flag always (unless XStream security filters are explicitly configured)
> - `ObjectMapper` with `.enableDefaultTyping()` or `.activateDefaultTyping(...)` configured on it — flag the readValue call
> - `Kryo.readObject(var, ...)`, `Kryo.readClassAndObject(var)` — flag if input stream comes from external source
>
> **PHP:**
> - `unserialize(var)` — flag always when argument is a variable
>
> **Ruby:**
> - `Marshal.load(var)`, `Marshal.restore(var)` — flag always
> - `YAML.load(var)` (Psych) without `permitted_classes: []` — flag
>
> **Node.js:**
> - `require('node-serialize').unserialize(var)` — flag always
> - `yaml.load(var)` (js-yaml v3 default unsafe load) — flag
>
> **.NET:**
> - `BinaryFormatter.Deserialize(var)` — flag always
> - `SoapFormatter.Deserialize(var)` — flag always
> - `NetDataContractSerializer.ReadObject(var)` — flag
> - `JavaScriptSerializer.Deserialize(var)` — flag if argument is variable
> - `LosFormatter.Deserialize(var)` — flag always
>
> ---
>
> **What to skip** (these are safe and should not be flagged):
> - `subprocess.run(["cmd", arg1, arg2])` with a list and no `shell=True` — no shell expansion
> - `json.loads(var)`, `JSON.parse(var)`, `json_decode(var)` — safe format with no code execution
> - `yaml.safe_load(var)` or `yaml.load(var, Loader=yaml.SafeLoader)` — safe loader
> - `ast.literal_eval(var)` — only parses Python literals, not arbitrary code
>
> ---
>
> **Output format** — write to `sast/rce-recon.md`:
>
> ```markdown
> # RCE Recon: [Project Name]
>
> ## Summary
> Found [N] potential RCE sinks: [X] OS command, [Y] code injection, [Z] unsafe deserialization.
>
> ## Sinks Found
>
> ### 1. [Descriptive name — e.g., "shell=True subprocess in image converter"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Category**: [OS Command Injection / Code Injection / Unsafe Deserialization]
> - **Sink**: [the dangerous function call — e.g., subprocess.run(..., shell=True)]
> - **Dynamic argument(s)**: `var_name` — [brief note on what it appears to represent]
> - **Code snippet**:
>   ```
>   [the relevant code around the sink]
>   ```
>
> [Repeat for each sink]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/rce-recon.md`. If the recon found **zero sinks** (the summary reports "Found 0" or the "Sinks Found" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/rce-results.md`, **delete** `sast/rce-recon.md`, and stop:

```markdown
# RCE Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one potential sink.

### Phase 2: Trace User Input to Sinks (Batched)

After Phase 1 completes, read `sast/rce-recon.md` and split the sinks into **batches of up to 3 sinks each** (numbered sections under `## Sinks Found`: `### 1.`, `### 2.`, etc.). Launch **one subagent per batch in parallel**. Each subagent traces taint only for its assigned sinks and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/rce-recon.md` and count the numbered sink sections (`### 1.`, `### 2.`, ...).
2. Divide them into batches of up to 3. For example, 8 sinks → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those sink sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sinks.
5. Each subagent writes to `sast/rce-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project is Python-focused, include the Python OS command, eval, pickle, and YAML subsections that apply. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned RCE sink, determine whether a user-supplied value reaches the dangerous argument. Our goal is to find code execution vulnerabilities. Write results to `sast/rce-batch-[N].md`.
>
> **Your assigned sinks** (from the recon phase):
>
> [Paste the full text of the assigned sink sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use the architecture to understand request entry points, middleware, and how data flows through the application.
>
> **RCE reference — what to look for**:
>
> Trace each sink's dynamic argument(s) back to their origin. RCE requires attacker-controlled data to reach a dangerous sink (OS command with shell interpretation, eval-like execution, or unsafe deserialization).
>
> **What RCE is NOT** — do not flag these as RCE:
> - **SSRF**, **path traversal**, **SSTI**, **XSS**, **SQLi** — other classes (see skill preamble).
> - **Safe subprocess list-form** with no shell: arguments passed without shell expansion are not command injection.
> - **Safe formats**: `json.loads`, `yaml.safe_load`, `ast.literal_eval` — no code execution semantics.
>
> **Mitigations that prevent exploitation** — if present and effective, the sink is likely safe:
> 1. **Subprocess list form without shell**: `subprocess.run(["cmd", var])` without `shell=True` — no shell metacharacter injection.
> 2. **Strict allowlist** before use: fixed set of safe values only.
> 3. **Safe deserialization**: JSON, `yaml.safe_load`, concrete typed Jackson reads without default typing.
>
> **Vulnerable vs. secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each sink, trace the dynamic argument(s) backwards to their origin**:
>
> 1. **Direct user input** — the variable is assigned directly from a request source with no transformation:
>    - HTTP query params: `request.GET.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `c.Query("x")`
>    - Path parameters: `request.path_params['id']`, `req.params.id`, `params[:id]`
>    - Request body / form fields: `request.POST.get(...)`, `req.body.x`, `params[:x]`, `$_POST['x']`
>    - HTTP headers: `request.headers.get(...)`, `req.headers['x']`
>    - Cookies: `request.COOKIES.get(...)`, `req.cookies.x`
>    - File upload content: `request.files['file'].read()`, `req.file.buffer`
>    - WebSocket messages, queue/event payloads
>
> 2. **Indirect user input** — the variable is derived from user input through transformations, function calls, or intermediate assignments. Trace the full chain:
>    - Variable assigned from a function return value → check that function's parameter origin
>    - Variable passed as a function argument → check the call site(s)
>    - Variable conditionally assigned — check all branches
>
> 3. **Externally-influenced deserialization data** — for deserialization sinks: Is the raw bytes/string coming from a network socket, HTTP request body, cookie, file upload, or a database value that was originally user-supplied? Any externally-controllable byte stream fed to an unsafe deserializer is exploitable.
>
> 4. **Server-side / hardcoded value** — the variable comes from config, an environment variable, a hardcoded constant, or server-side logic with no external influence — NOT exploitable.
>
> **Mitigations to check for each sink**:
> - **Allowlist validation**: Is the variable validated against a fixed set of known-safe values before use? If strict and complete, mark as Not Vulnerable.
> - **Integer/type cast**: Does casting to `int`/`float` actually prevent injection in this context? Effective only for purely numeric arguments with no quoting issues.
> - **escapeshellarg / escapeshellcmd** (PHP): Reduces risk but is not elimination — flag as Likely Vulnerable; shell escaping has bypass history in certain contexts.
> - **Subprocess list form**: `subprocess.run(["cmd", var])` without `shell=True` — arguments are passed directly to the OS, no shell expansion. This IS an effective mitigation for command injection (mark as Not Vulnerable for injection; the value is still passed to the command, but cannot inject new commands).
> - **Safe deserializer in place**: If `json.loads()`, `yaml.safe_load()`, etc. are used instead — skip (Phase 1 should not have flagged these).
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the dangerous sink with no effective mitigation.
> - **Likely Vulnerable**: User input probably reaches the sink (indirect flow) or only weak mitigation is present (shell escaping, partial validation, unclear allowlist).
> - **Not Vulnerable**: The argument is server-side only, OR effective mitigation is in place (subprocess list form, strict allowlist, safe deserializer format).
> - **Needs Manual Review**: Cannot determine the argument's origin with confidence (passes through opaque helpers, complex conditional flows, or external libraries).
>
> **Output format** — write to `sast/rce-batch-[N].md`:
>
> ```markdown
> # RCE Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Category**: [OS Command Injection / Code Injection / Unsafe Deserialization]
> - **Issue**: [e.g., "HTTP query param `host` flows directly into shell=True subprocess call"]
> - **Taint trace**: [Step-by-step from entry point to the sink — e.g., "request.args.get('host') → host → subprocess.run(f'ping -c 1 {host}', shell=True)"]
> - **Impact**: [What an attacker can do — execute arbitrary OS commands, read /etc/passwd, establish reverse shell, achieve full server compromise, etc.]
> - **Remediation**: [Specific fix — use list-form subprocess, replace eval with safe alternative, switch to json.loads/yaml.safe_load, etc.]
> - **Dynamic Test**:
>   ```
>   [curl command or payload to confirm the finding.
>    Show the exact parameter, payload, and what to look for in the response.
>    Examples:
>      curl "https://app.example.com/ping?host=127.0.0.1;id"
>      curl "https://app.example.com/ping?host=127.0.0.1%3Bid"
>      For deserialization: show how to craft a malicious payload with ysoserial or pickletools]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Category**: [OS Command Injection / Code Injection / Unsafe Deserialization]
> - **Issue**: [e.g., "Variable likely sourced from user input via helper function" or "escapeshellarg applied but bypassable in some contexts"]
> - **Taint trace**: [Best-effort trace with the uncertain step identified]
> - **Concern**: [Why it's still a risk despite uncertainty]
> - **Remediation**: [Fix]
> - **Dynamic Test**:
>   ```
>   [payload to attempt]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Argument is hardcoded constant" or "subprocess called with list form, no shell=True — shell injection impossible" or "strict allowlist gates the value before use"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the variable's origin could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Follow `build_command()` in utils.py to check where its return value originates"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/rce-batch-*.md` file and merge them into a single `sast/rce-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/rce-batch-1.md`, `sast/rce-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/rce-results.md` using this format:

```markdown
# RCE Analysis Results: [Project Name]

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

5. After writing `sast/rce-results.md`, **delete all intermediate batch files** (`sast/rce-batch-*.md`) and **delete** `sast/rce-recon.md`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sinks per subagent**. If there are 1-3 sinks total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sinks' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any sink where a non-constant variable appears in a dangerous position, regardless of where that variable comes from. Do not trace user input in Phase 1.
- **Phase 2 is purely taint analysis**: for each sink found in Phase 1, trace the dynamic argument back to its origin. If it comes from a user-controlled source, the site is a real vulnerability.
- **For deserialization sinks**: any externally-controllable byte stream is dangerous — HTTP bodies, cookies, file uploads, WebSocket frames, queue messages. Be conservative and flag all deserialization sinks where data flow from an external source cannot be ruled out.
- **For OS command sinks**: `subprocess.run(["cmd", var])` with list form and no `shell=True` is NOT command injection — the argument is passed directly to the process without shell interpretation. Only flag when shell interpretation is possible (string command + `shell=True`, or `exec()`/`system()` equivalents).
- **For `eval`-like sinks**: there is almost no safe way to use `eval()` with user input. Any eval-like sink receiving external data should be flagged Vulnerable.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Taint can flow indirectly through middleware, helper functions, class attributes, and intermediate variables. Trace the full chain.
- Second-order RCE is possible: a value stored from user input may later be deserialized or evaluated in a different code path (e.g., a user-supplied config stored in DB and later `eval()`'d by a cron job).
- For Java deserialization: the presence of dangerous gadget libraries in the classpath (Apache Commons Collections, Spring Framework, etc.) determines exploitability. Flag the deserialization call; note any relevant libraries from `architecture.md`.
- Clean up intermediate files: delete `sast/rce-recon.md` and all `sast/rce-batch-*.md` files after the final `sast/rce-results.md` is written (Phase 3 merge step 5 performs this).
