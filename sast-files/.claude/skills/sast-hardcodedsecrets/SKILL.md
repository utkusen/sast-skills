---
name: sast-hardcodedsecrets
description: >-
  Detect hardcoded sensitive data (API keys, access tokens, private keys,
  passwords, etc.) in publicly accessible code — frontend JavaScript, mobile
  apps, client-side bundles, and HTML templates. Uses a three-phase approach:
  recon (find secret candidates), batched verify (confirm real secrets in public
  code paths, 3 candidates each), and merge (consolidate batch results).
  Requires sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/hardcodedsecrets-results.md. Use when asked to find hardcoded secrets,
  leaked API keys, or exposed credentials.
---

# Hardcoded Secrets in Public Code Detection

You are performing a focused security assessment to find hardcoded sensitive data that is exposed in publicly accessible code. This skill uses a three-phase approach with subagents: **recon** (find all potential secret candidates), **batched verify** (confirm each is a real secret in publicly reachable code, in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What Are Hardcoded Secrets in Public Code

Hardcoded secrets are sensitive credentials — API keys, access tokens, private keys, passwords, signing secrets, database connection strings — embedded directly in source code as string literals.

This skill focuses specifically on secrets that end up in **publicly accessible code**, meaning an attacker can extract them **without any server-side access**. A secret hardcoded in backend server code is bad practice but not directly exploitable by an external attacker inspecting the deployed application. A secret hardcoded in frontend JavaScript or a mobile app binary **is** directly extractable.

The core question: *Can an external attacker obtain this secret from the deployed application without server access?*

### What to Report (Publicly Accessible Code)

These code paths are accessible to attackers after deployment:

- **Frontend JavaScript/TypeScript** — any `.js`, `.ts`, `.jsx`, `.tsx` file that runs in the browser. This includes:
  - React, Angular, Vue, Svelte components and pages
  - Next.js client components (files with `"use client"` or files under `app/` without `"use server"`)
  - Nuxt.js pages and client plugins
  - Vanilla JS in `public/`, `static/`, or `assets/` directories
  - Webpack/Vite/Rollup entry points and their imported modules
  - Any file imported by a client-side entry point (even if it lives in a `utils/` or `lib/` folder)
- **Mobile application code** — extractable via reverse engineering (decompiling APK, inspecting IPA):
  - Android: Java/Kotlin source files
  - iOS: Swift/Objective-C source files
  - React Native: JavaScript bundles
  - Flutter: Dart source files
  - Xamarin: C# source files
- **HTML files and templates served to clients** — inline `<script>` blocks, `data-` attributes, meta tags
- **Client-side configuration files** — files in `public/`, `static/`, `assets/`, `www/` directories
- **Electron/desktop app source** — extractable from ASAR archives
- **WebAssembly source/companion JS** — secrets in JS glue code or extractable from WASM

### What NOT to Report (Backend-Only Code)

Do not flag secrets in these locations — they are not publicly accessible:

- **Server-side application code** — Express route handlers (server-only), Django views, Flask routes, Spring controllers, Rails controllers, Go HTTP handlers, PHP controllers — code that runs exclusively on the server
- **Server-side API route files** — Next.js `app/api/` routes, Nuxt server routes, SvelteKit `+server.ts` files
- **Environment files** — `.env`, `.env.local`, `.env.production` (unless served statically)
- **Server-side configuration** — `config/database.yml`, `settings.py`, `application.properties`, `appsettings.json`
- **CI/CD pipeline files** — `.github/workflows/`, `Jenkinsfile`, `.gitlab-ci.yml`
- **Docker/infrastructure files** — `Dockerfile`, `docker-compose.yml`, Kubernetes manifests
- **Backend utility/service files** — files that are only imported by server-side code
- **Test files** — test fixtures and test configuration (unless the test files are shipped to the client)
- **Migration files** — database migrations

### Distinguishing Frontend from Backend

This is critical and requires understanding the project architecture:

**Next.js**: Files under `app/` with `"use client"` directive or without `"use server"` are client components. Files under `app/api/` are server-only. Files under `pages/api/` are server-only. Files under `pages/` (non-api) render on both server and client — secrets here ARE exposed. `next.config.js` runs server-side only but `NEXT_PUBLIC_*` env vars are embedded in client bundles.

**Nuxt.js**: Files under `pages/`, `components/`, `composables/` are client-accessible. Files under `server/` are server-only.

**React (CRA/Vite)**: Everything in `src/` is bundled for the client. `REACT_APP_*` and `VITE_*` env vars are embedded in client builds.

**Angular**: Everything in `src/` is bundled for the client.

**Vue (Vite)**: Everything in `src/` is bundled for the client. `VITE_*` env vars are embedded.

**Express/Fastify/Koa**: All server-side unless serving static files from a `public/` or `static/` directory.

**Django/Flask**: Python code is server-side. Templates are rendered server-side (secrets in template context don't reach the client unless explicitly rendered into JS). Static files in `static/` are client-accessible.

**Rails**: Ruby code is server-side. Assets in `app/assets/javascripts/` or `app/javascript/` are client-accessible.

**Mobile apps**: ALL source code is considered publicly accessible via reverse engineering.

---

## Types of Secrets to Look For

### High-Confidence Patterns (Regex-Identifiable)

These have distinctive formats that make them identifiable with high confidence:

| Secret Type | Pattern |
|---|---|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` |
| AWS Secret Access Key | 40-character base64 string near an `AKIA` key |
| Google API Key | `AIza[0-9A-Za-z\\-_]{35}` |
| Google OAuth Client Secret | `GOCSPX-[0-9A-Za-z\\-_]{28}` |
| GitHub Personal Access Token | `ghp_[0-9A-Za-z]{36}`, `github_pat_[0-9A-Za-z_]{82}` |
| GitHub OAuth App Secret | `gho_[0-9A-Za-z]{36}` |
| GitLab Personal Access Token | `glpat-[0-9A-Za-z\\-_]{20}` |
| Slack Bot/User Token | `xoxb-[0-9A-Za-z\\-]+`, `xoxp-[0-9A-Za-z\\-]+` |
| Slack Webhook URL | `hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` |
| Stripe Secret Key | `sk_live_[0-9A-Za-z]{24,}` |
| Stripe Publishable Key | `pk_live_[0-9A-Za-z]{24,}` (publishable keys are designed for client-side — skip unless paired with a secret key) |
| Twilio Account SID + Auth Token | `AC[0-9a-f]{32}` (SID), 32-hex auth token nearby |
| SendGrid API Key | `SG\.[0-9A-Za-z\\-_]{22}\.[0-9A-Za-z\\-_]{43}` |
| Mailgun API Key | `key-[0-9a-zA-Z]{32}` |
| Firebase Config | `apiKey`, `authDomain`, `projectId` together in a config object — only flag if it includes a server/admin key, not the standard client config |
| Private RSA/EC/SSH Key | `-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----` |
| JWT Secret / Signing Key | String assigned to variables like `JWT_SECRET`, `jwt_secret`, `signingKey`, `HMAC_KEY` |
| Database Connection String with Password | `postgresql://user:pass@`, `mysql://user:pass@`, `mongodb://user:pass@`, `redis://:pass@` |
| Generic API Key Assignment | Variable named `*api_key*`, `*apiKey*`, `*API_KEY*`, `*secret*`, `*SECRET*`, `*token*`, `*TOKEN*`, `*password*`, `*PASSWORD*` assigned a string literal that looks like a real credential |
| Heroku API Key | `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}` in a Heroku context |
| Azure Storage Key | Base64 string ~88 chars assigned to storage account key variables |
| OpenAI API Key | `sk-[A-Za-z0-9]{48}` or `sk-proj-[A-Za-z0-9\\-_]{100,}` |
| Anthropic API Key | `sk-ant-[A-Za-z0-9\\-_]{90,}` |

### Variable Name Patterns (Require Value Inspection)

Search for variables/constants with these name patterns and check if the assigned value looks like a real credential:

- `api_key`, `apiKey`, `API_KEY`, `ApiKey`
- `secret`, `SECRET`, `secret_key`, `secretKey`, `SECRET_KEY`
- `access_token`, `accessToken`, `ACCESS_TOKEN`
- `auth_token`, `authToken`, `AUTH_TOKEN`
- `private_key`, `privateKey`, `PRIVATE_KEY`
- `password`, `PASSWORD`, `passwd`, `PASSWD`
- `client_secret`, `clientSecret`, `CLIENT_SECRET`
- `signing_key`, `signingKey`, `SIGNING_KEY`
- `encryption_key`, `encryptionKey`, `ENCRYPTION_KEY`
- `bearer_token`, `BEARER_TOKEN`
- `credentials`, `CREDENTIALS`
- `connection_string`, `connectionString`, `DATABASE_URL`

### What is NOT a Real Secret (False Positives to Ignore)

- **Placeholder values**: `"your-api-key-here"`, `"TODO"`, `"xxx"`, `"changeme"`, `"REPLACE_ME"`, `"INSERT_KEY"`, `"<api_key>"`, `"dummy"`, `"test"`, `"example"`, `"sample"`, `"placeholder"`
- **Empty strings**: `""`, `''`
- **Environment variable references**: `process.env.API_KEY`, `os.environ["SECRET"]`, `ENV["KEY"]` — these read from the environment at runtime, not hardcoded
- **Public keys**: Public keys (not private) are designed to be shared — not a secret
- **Publishable/public API keys**: Stripe `pk_test_*`, `pk_live_*`; Firebase client config `apiKey` (designed for client-side use); Google Maps client key (restricted by HTTP referrer)
- **Test/development keys**: `sk_test_*` (Stripe test), keys in files clearly named as test fixtures
- **Type definitions / interfaces**: TypeScript `interface Config { apiKey: string }` — no actual value
- **Documentation strings**: Comments explaining what a key looks like
- **Hash values**: SHA256/MD5 hashes that are not secrets (e.g., content hashes, checksums)
- **Build-time constants**: Version strings, build IDs, commit hashes

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Secret Candidates

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a hardcoded secret (API key, access token, private key, password, signing secret, connection string) appears as a string literal. Write results to `sast/hardcodedsecrets-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, project structure, and which files are frontend vs. backend.
>
> **What to search for**:
>
> Scan the entire codebase. At this stage, flag ALL potential secrets regardless of whether they are in frontend or backend code — the filtering happens in Phase 2.
>
> 1. **High-confidence regex patterns** — search for these distinctive formats:
>    - AWS keys: `AKIA[0-9A-Z]{16}`
>    - Google API keys: `AIza[0-9A-Za-z\-_]{35}`
>    - GitHub tokens: `ghp_`, `github_pat_`, `gho_`, `ghs_`
>    - Slack tokens: `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`
>    - Stripe secret keys: `sk_live_`, `sk_test_`
>    - SendGrid keys: `SG\.`
>    - OpenAI keys: `sk-` followed by 48+ alphanumeric characters
>    - Anthropic keys: `sk-ant-`
>    - Private key headers: `-----BEGIN.*PRIVATE KEY-----`
>    - Connection strings with embedded passwords: `://[^:]+:[^@]+@`
>
> 2. **Variable assignment patterns** — search for variables with secret-related names assigned string literal values:
>    - Search for patterns like: `apiKey = "..."`, `api_key = '...'`, `API_KEY: "..."`, `secret: "..."`, `token = "..."`, `password = "..."`, `client_secret = "..."`
>    - Include all casing conventions: camelCase, snake_case, SCREAMING_SNAKE_CASE, PascalCase
>    - Look in JS/TS objects, JSON files, YAML/TOML config, Python dicts, environment-like configs
>
> 3. **Inline string literals** that match known key formats:
>    - Long random alphanumeric strings (32+ characters) assigned to auth-related variables
>    - Base64-encoded strings in authentication contexts
>    - Hex strings (64+ characters) used as keys or secrets
>    - UUIDs used as API keys or secrets
>
> **What to skip during recon**:
> - Environment variable reads: `process.env.*`, `os.environ[*]`, `ENV[*]`, `System.getenv(*)` — these are not hardcoded
> - Type definitions with no values: `apiKey: string`, `type Config = { secret: string }`
> - Obvious placeholders: `"your-key-here"`, `"TODO"`, `"xxx"`, `"changeme"`, `"REPLACE_ME"`, `"<api_key>"`, `"dummy"`, `"test-key"`, `"example"`, `"sample"`, empty strings
> - Comments that merely describe or document secrets
> - Public keys (non-private cryptographic keys)
> - Hash values used as checksums or content identifiers
> - Files in `.git/`, `node_modules/`, `vendor/`, `venv/`, `__pycache__/`, `dist/`, `build/` directories
>
> **Output format** — write to `sast/hardcodedsecrets-recon.md`:
>
> ```markdown
> # Hardcoded Secrets Recon: [Project Name]
>
> ## Summary
> Found [N] potential hardcoded secret candidates.
>
> ## Candidates
>
> ### 1. [Descriptive name — e.g., "AWS Access Key in API config"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Secret type**: [AWS key / Google API key / Generic API key / Private key / Password / JWT secret / Connection string / etc.]
> - **Variable/context**: [variable name or context where the secret appears]
> - **Detection method**: [regex match / variable name pattern / inline literal]
> - **Code snippet**:
>   ```
>   [Show the line(s) containing the secret — REDACT the middle portion of the actual value, e.g., "AKIA****EXAMPLE" or "sk_live_****abcd"]
>   ```
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/hardcodedsecrets-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Candidates" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/hardcodedsecrets-results.md` and stop:

```markdown
# Hardcoded Secrets Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Confirm Real Secrets in Public Code (Batched)

After Phase 1 completes, read `sast/hardcodedsecrets-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/hardcodedsecrets-recon.md` and count the numbered candidate sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 candidates -> 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/hardcodedsecrets-batch-N.md` where N is the 1-based batch number.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: Verify the following hardcoded secret candidates. For each one, determine (1) whether it is a real secret and (2) whether it is in publicly accessible code. Write results to `sast/hardcodedsecrets-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, frontend/backend separation, build pipeline, and which directories contain client-side vs. server-side code.
>
> **For each candidate, answer TWO questions:**
>
> **Question 1: Is this a real secret?**
>
> Check whether the value is an actual credential vs. a false positive:
> - Does the string have the entropy and format of a real key/token? (Real API keys are typically 20+ random characters)
> - Is it a known placeholder or example value? ("your-key-here", "changeme", "test", "example", "TODO", "xxx", "REPLACE_ME", etc.)
> - Is it a test/development key? (Stripe `sk_test_*`, sandbox credentials, keys in test fixtures)
> - Is it a public/publishable key by design? (Stripe `pk_live_*`, Firebase client `apiKey`, Google Maps browser key)
> - Is it actually an environment variable reference that got picked up by mistake?
> - Is it a hash, checksum, or non-secret identifier?
>
> If the value is NOT a real secret, classify as **Not Vulnerable** and explain why.
>
> **Question 2: Is this in publicly accessible code?**
>
> Determine whether an external attacker can extract this secret from the deployed application:
>
> **PUBLICLY ACCESSIBLE (report these):**
> - Frontend JavaScript/TypeScript that runs in the browser (React, Angular, Vue, Svelte components/pages)
> - Next.js client components (files with `"use client"` or client-rendered pages)
> - Nuxt.js `pages/`, `components/`, client-side `plugins/`
> - Any `.js`/`.ts` file that is imported by a client-side entry point (trace the import chain)
> - Files in `public/`, `static/`, `assets/`, `www/` directories that are served directly
> - HTML files with inline `<script>` blocks
> - Mobile app source code — Android (Java/Kotlin), iOS (Swift/Objective-C), React Native JS, Flutter Dart, Xamarin C# — ALL mobile code is extractable via reverse engineering
> - Electron app source (extractable from ASAR)
> - Client-side configuration objects embedded in JavaScript (e.g., Firebase config, analytics init)
>
> **NOT PUBLICLY ACCESSIBLE (do not report):**
> - Server-side route handlers (Express, Django, Flask, Rails, Spring, Go, PHP controllers)
> - Server-side API routes (Next.js `app/api/`, Nuxt `server/`, SvelteKit `+server.ts`)
> - Backend services, middleware, utilities only imported by server code
> - `.env` files, server config files, Docker/CI files
> - Test files and fixtures not shipped to clients
> - Database migrations
> - Build scripts and tooling
>
> **How to determine if a file is client-side:**
> 1. Check the file path — is it under a client-side directory? (`src/` in CRA/Vite React, `pages/` in Next.js, `app/` in Angular, `src/` in Vue)
> 2. Trace the import chain — is this file imported (directly or transitively) by a client-side entry point?
> 3. Check for server-only markers — `"use server"` directive, file under `api/` or `server/` directories
> 4. Check `sast/architecture.md` for the project's frontend/backend separation pattern
> 5. For ambiguous cases (e.g., shared utility files), err on the side of caution — if it COULD be bundled for the client, treat it as publicly accessible
>
> If the secret is NOT in publicly accessible code, classify as **Not Vulnerable** and explain why (e.g., "Server-side only — Express route handler").
>
> **Classification**:
> - **Vulnerable**: Confirmed real secret in confirmed publicly accessible code. An attacker can extract this from the deployed application.
> - **Likely Vulnerable**: Appears to be a real secret and the file is likely client-accessible, but cannot fully confirm one or both conditions (e.g., ambiguous import chain, uncertain if the value is a real production key).
> - **Not Vulnerable**: Either not a real secret (placeholder, test key, public key) OR not in publicly accessible code (backend-only).
> - **Needs Manual Review**: Cannot determine if the value is a real secret or if the file reaches the client — requires human judgment.
>
> **Output format** — write to `sast/hardcodedsecrets-batch-[N].md`:
>
> ```markdown
> # Hardcoded Secrets Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Secret type**: [AWS key / Google API key / etc.]
> - **Exposure path**: [How an attacker extracts it — e.g., "Bundled into client JS via Webpack, visible in browser DevTools Sources tab" or "Embedded in Android APK, extractable via `apktool d app.apk`"]
> - **Issue**: [Clear description — e.g., "AWS access key hardcoded in React component that is bundled for the browser"]
> - **Impact**: [What an attacker can do with this secret — e.g., "Full access to AWS S3 buckets, potential data exfiltration", "Send emails via SendGrid on behalf of the organization", "Access user data via the API"]
> - **Evidence**:
>   ```
>   [Code snippet with the secret value partially redacted]
>   ```
> - **Remediation**: [Move the secret to a server-side environment variable. If the client needs to call this API, proxy through your backend. For mobile apps, use a backend proxy or OAuth flow instead of embedding keys.]
> - **Verification Steps**:
>   ```
>   [How to confirm this finding:
>    - For web apps: "Open browser DevTools > Sources > search for 'AKIA' in bundled JS files"
>    - For mobile apps: "Run `apktool d app.apk` and grep for the key pattern"
>    - For Electron: "Extract ASAR archive and search for the key"]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Secret type**: [type]
> - **Exposure path**: [Best guess at how it reaches the client]
> - **Issue**: [What's uncertain]
> - **Concern**: [Why it's still a risk]
> - **Evidence**:
>   ```
>   [Code snippet]
>   ```
> - **Remediation**: [Fix recommendation]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Reason**: [e.g., "Placeholder value — 'your-api-key-here'" or "Server-side only — Django view, never reaches the client" or "Stripe publishable key — designed for client use"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [Why automated analysis couldn't determine the status]
> - **Suggestion**: [What to check manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/hardcodedsecrets-batch-*.md` file and merge them into a single `sast/hardcodedsecrets-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/hardcodedsecrets-batch-1.md`, `sast/hardcodedsecrets-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/hardcodedsecrets-results.md` using this format:

```markdown
# Hardcoded Secrets Analysis Results: [Project Name]

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

5. After writing `sast/hardcodedsecrets-results.md`, **delete all intermediate batch files** (`sast/hardcodedsecrets-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **The key distinction is public accessibility**: a hardcoded AWS key in a Django view is bad practice but NOT a finding for this skill (it's server-side). The same key in a React component IS a finding because it ships to the browser.
- **Trace the import chain when uncertain**: A file at `src/utils/config.ts` might be imported by both server and client code. Check who imports it. If ANY client-side code path imports it, the secrets are exposed.
- **Mobile apps are always public**: All source code in Android, iOS, React Native, Flutter, and Xamarin apps should be treated as extractable. APKs can be decompiled with `apktool`/`jadx`, IPAs can be inspected, JS bundles in React Native are plaintext.
- **Firebase client config is generally NOT a secret**: The standard Firebase client config (`apiKey`, `authDomain`, `projectId`, etc.) is designed for client-side use and protected by Firebase Security Rules. Only flag Firebase **admin/service account** keys or **server keys** (e.g., `FIREBASE_ADMIN_SDK`, service account JSON with `private_key`).
- **Stripe publishable keys are NOT secrets**: `pk_live_*` and `pk_test_*` are designed for client-side use. Only flag `sk_live_*` and `sk_test_*` (secret keys).
- **`NEXT_PUBLIC_*`, `REACT_APP_*`, `VITE_*` env vars**: These are embedded into client bundles at build time. If the code references `process.env.NEXT_PUBLIC_API_KEY`, that IS client-accessible — but the actual hardcoded value would be in the `.env` file, which is typically gitignored. Only flag if the actual secret value is hardcoded in source code, not if it's read from an env var.
- **Redact secrets in output**: When showing code snippets, always partially redact the secret value (e.g., `AKIA****WXYZ`, `sk_live_****abcd`). Never write the full secret value in the results file.
- When in doubt about public accessibility, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete `sast/hardcodedsecrets-recon.md` and all `sast/hardcodedsecrets-batch-*.md` files after the final `sast/hardcodedsecrets-results.md` is written.
