# LLM SAST Skills

A collection of agent skills that turn your LLM coding assistant into a fully functional SAST scanner to find vulnerabilities in your codebase. Works natively with Claude Code, Codex, Opencode, Cursor and any other assistant that supports agent skills. No third-party tools required.

Claude Code with Opus model is recommended. But if the cost is a concern, use any IDE and model you trust.

![Process in Claude Code](demo.gif)

## How It Works

`CLAUDE.md` (for Claude Code) or `AGENTS.md` (for Opencode and other IDEs) orchestrates the entire assessment workflow automatically. The assessment runs in three steps:

1. **Codebase Analysis** -- The `sast-analysis` skill maps the technology stack, architecture, entry points, data flows, and trust boundaries. It writes its findings to `sast/architecture.md`.

2. **Vulnerability Detection (parallel)** -- All 13 vulnerability detection skills run in parallel as subagents. Each skill follows a two-phase approach: first a recon/discovery phase to find candidate sections, then a verification phase to confirm exploitability. Results are written to `sast/*-results.md`.

3. **Report Generation** -- The `sast-report` skill consolidates all findings into a single `sast/final-report.md`, ranked by severity with full remediation guidance and dynamic test instructions.

## What It Detects

| Skill | Vulnerability Class |
|---|---|
| sast-analysis | Codebase reconnaissance, architecture mapping, threat modeling |
| sast-sqli | SQL Injection |
| sast-graphql | GraphQL injection |
| sast-xss | Cross-Site Scripting (XSS) |
| sast-rce | Remote Code Execution (command injection, eval, unsafe deserialization) |
| sast-ssrf | Server-Side Request Forgery |
| sast-idor | Insecure Direct Object Reference |
| sast-xxe | XML External Entity |
| sast-ssti | Server-Side Template Injection |
| sast-jwt | Insecure JWT implementations |
| sast-missingauth | Missing authentication and broken function-level authorization |
| sast-pathtraversal | Path / directory traversal |
| sast-fileupload | Insecure file upload |
| sast-businesslogic | Business logic flaws (price manipulation, workflow bypass, race conditions, etc.) |
| sast-hardcodedsecrets | Hardcoded API keys, tokens, and credentials in client-facing code |
| sast-csrf | Cross-Site Request Forgery |
| sast-openredirect | Open redirect (unvalidated redirect to attacker-controlled URL) |
| sast-cors | CORS misconfiguration (permissive Access-Control-Allow-Origin/credentials) |
| sast-ldap | LDAP injection |
| sast-nosql | NoSQL injection (MongoDB/Firestore/Dynamo operator injection) |
| sast-prototype | Prototype pollution in JavaScript/TypeScript |
| sast-redos | Regex denial of service (catastrophic backtracking) |
| sast-crypto | Insecure cryptography (weak hash, weak IV, weak PRNG, deprecated cipher) |
| sast-race | Race conditions and TOCTOU bugs |
| sast-pii | PII and credential leakage to logs or error messages |
| sast-deps | Known-vulnerable dependencies (CVEs in package.json/requirements/go.mod) |
| sast-iac | Insecure IaC (Dockerfile/Terraform/Kubernetes manifests) |
| sast-promptinjection | LLM prompt injection (untrusted text reaching a model) |
| sast-llmoutput | Insecure handling of LLM output (command/SQL/HTML injection from model response) |
| sast-report | Consolidated final report ranked by severity |
| sast-triage | False-positive elimination and severity adjustment over the consolidated report |

## Installation

Run the installer from your project root:

```bash
npx sast-skills install
```

The installer asks which assistant to target (`claude`, `agents`, or `all`) and whether to install into the current project or into your user home directory (global). To skip the prompts, pass flags:

```bash
npx sast-skills install --yes --assistant claude --scope project
```

Other commands:

| Command | What it does |
|---|---|
| `npx sast-skills install` | Copy CLAUDE.md/AGENTS.md and the skill files into your project |
| `npx sast-skills update` | Refresh an existing install with the currently bundled skill files |
| `npx sast-skills uninstall` | Remove installed skills (refuses to clobber a modified CLAUDE.md without `--force`) |
| `npx sast-skills doctor` | Verify an install and report `OK` / `MISSING` / `MODIFIED` for each file |
| `npx sast-skills export --input sast/ --format sarif --output report.sarif` | Aggregate `sast/*-results.json` into SARIF, JSON, or HTML |
| `npx sast-skills --version` | Print the installed version |

> **Note:** If your project already contains a `CLAUDE.md` or `AGENTS.md` file, either pass `--force` to overwrite it or back it up first — the installer will refuse to clobber it by default.

## Usage

After installing, open your project in your AI coding assistant and ask:

> Run vulnerability scan

or

> Find vulnerabilities in this codebase

The entry point file (`CLAUDE.md` or `AGENTS.md`) orchestrates the full workflow automatically. It will skip any steps whose output files already exist, so you can safely re-run it after fixing issues.

## Output

All output is written to a `sast/` folder in your project root:

| File | Description |
|---|---|
| `sast/architecture.md` | Technology stack, architecture, entry points, data flows |
| `sast/*-results.md` | Per-vulnerability-class findings (human-readable) |
| `sast/*-results.json` | Canonical machine-readable findings for `sast-skills export` |
| `sast/final-report.md` | Consolidated report ranked by severity |
| `sast/final-report-triaged.md` | Triaged report with false positives removed and severities adjusted |
| `sast/triaged.json` | Canonical triaged findings (preferred by `sast-skills export --triaged`) |

## CI integrations

### GitHub Code Scanning

Drop the bundled composite action into a workflow to upload SARIF to Code Scanning:

```yaml
- uses: mstfknn/sast-skills/.github/actions/scan@main
  with:
    input: sast/
    output: sast-skills.sarif
```

### Pre-commit hook

Copy [hooks/pre-commit](hooks/pre-commit) into `.git/hooks/pre-commit` to make `sast-skills doctor` gate every commit.

### Docker

```bash
docker build -t sast-skills .
docker run --rm -v "$PWD:/work" sast-skills export --input sast/ --format sarif --output report.sarif
```
