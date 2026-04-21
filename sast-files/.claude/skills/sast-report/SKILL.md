---
name: sast-report
description: >-
  Consolidate all SAST vulnerability results from the sast/ folder into a single
  final report ranked by severity and confidentiality impact. Reads all
  *-results.md files and produces sast/final-report.md. Run after all
  vulnerability detection skills complete. Use when asked to generate a final
  report, consolidate findings, or summarize security results.
version: 0.1.0
---

# Final Security Report Generation

You are consolidating all completed SAST vulnerability scan results into a single prioritized security report.

**Prerequisites**: At least one `sast/*-results.md` file must exist. Run the vulnerability detection skills first if they don't.

---

## What to Include

Only include findings with these classifications from each result file:
- `[VULNERABLE]`
- `[LIKELY VULNERABLE]`

Exclude `[NOT VULNERABLE]` and `[NEEDS MANUAL REVIEW]` findings from the main report body (count them only in the summary).

---

## Severity Ranking

Assign each finding a severity tier — **Critical**, **High**, **Medium**, or **Low** — using the table below as your baseline. Adjust up or down based on context (e.g., an IDOR that exposes financial records is High, not Medium).

| Vulnerability Class | Default Severity |
|---------------------|------------------|
| RCE via command injection, eval, or unsafe deserialization | Critical |
| SSTI (Server-Side Template Injection) | Critical |
| SQLi on authentication endpoints | Critical |
| JWT algorithm confusion (alg:none, RS256→HS256) | Critical |
| File upload leading to code execution (webshell) | Critical |
| SQLi with full data extraction capability | High–Critical |
| GraphQL injection (user-controlled operation document enabling unauthorized fields or gateway abuse) | High–Critical |
| XXE with file read or internal SSRF | High–Critical |
| Missing authentication on sensitive endpoints | High–Critical |
| SSRF reaching internal services or cloud metadata | High |
| Path traversal reading sensitive or config files | High |
| File upload with stored content accessible to others | High |
| IDOR on PII, financial, or health data | High |
| XSS (stored/persistent) | High |
| JWT with missing or bypassable claim validation | Medium–High |
| Missing authentication on lower-sensitivity endpoints | Medium |
| IDOR on non-sensitive data | Medium |
| XSS (reflected or DOM) | Medium |
| Business logic flaws (price manipulation, workflow bypass) | Medium |
| Information disclosure of non-sensitive data | Low |

**Confidentiality as a tiebreaker**: When two findings share the same baseline severity, rank higher the one with greater confidentiality impact — i.e., the greater its potential to expose sensitive user data, credentials, or system internals.

---

## Execution

Perform all steps in-session (no subagents needed).

### Step 1: Discover result files

Check which of these files exist in `sast/`:
- `idor-results.md`
- `sqli-results.md`
- `ssrf-results.md`
- `xss-results.md`
- `rce-results.md`
- `xxe-results.md`
- `fileupload-results.md`
- `pathtraversal-results.md`
- `ssti-results.md`
- `jwt-results.md`
- `missingauth-results.md`
- `businesslogic-results.md`
- `graphql-results.md`

Also read `sast/architecture.md` if it exists (use it for the project name and context when writing severity rationale).

### Step 2: Read and extract findings

Read each existing result file. For every finding classified as `[VULNERABLE]` or `[LIKELY VULNERABLE]`, extract:
- Finding title
- Vulnerability type (derived from the source file)
- File / endpoint affected
- Issue description
- Impact description
- Proof / code path
- Remediation
- Dynamic test steps (if present)

### Step 3: Score and sort

Assign each finding a severity level (Critical / High / Medium / Low) using the table above. Sort all findings:

1. Critical first, then High, Medium, Low
2. Within each tier, sort by confidentiality impact (highest first)

### Step 4: Write `sast/final-report.md`

Use exactly this output format:

---

```markdown
# Security Assessment Final Report

**Project**: [name from architecture.md, or infer from codebase]
**Generated**: [current date]
**Scans completed**: [comma-separated list of scan types that had result files]

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |
| **Total confirmed findings** | **N** |

Scans with no confirmed vulnerabilities: [list]
Findings requiring manual review: N (see individual result files for details)

---

## Vulnerability Index

| # | Title | Type | Severity | Endpoint / File |
|---|-------|------|----------|----------------|
| 1 | ... | RCE | Critical | `POST /api/exec` |
| 2 | ... | SQLi | High | `GET /api/users` |

---

## Findings

### Critical

#### [Finding Title] — [Vuln Type]

- **Source scan**: `sast/[type]-results.md`
- **Classification**: Vulnerable *(or "Likely Vulnerable")*
- **Endpoint / File**: ...
- **Severity rationale**: [1–2 sentences explaining why this is Critical, with focus on confidentiality and integrity impact]
- **Issue**: ...
- **Impact**: ...
- **Proof**:
  ```
  [code path or evidence from original finding]
  ```
- **Remediation**: ...
- **Dynamic Test**:
  ```
  [curl command or step-by-step test instructions from original finding]
  ```

---

### High

[Same structure as Critical section]

---

### Medium

[Same structure]

---

### Low

[Same structure]

---

## Appendix: Scan Coverage

| Scan | Result File | Status |
|------|-------------|--------|
| IDOR | `sast/idor-results.md` | Completed / Not run |
| SQLi | `sast/sqli-results.md` | Completed / Not run |
| SSRF | `sast/ssrf-results.md` | Completed / Not run |
| XSS | `sast/xss-results.md` | Completed / Not run |
| RCE | `sast/rce-results.md` | Completed / Not run |
| XXE | `sast/xxe-results.md` | Completed / Not run |
| File Upload | `sast/fileupload-results.md` | Completed / Not run |
| Path Traversal | `sast/pathtraversal-results.md` | Completed / Not run |
| SSTI | `sast/ssti-results.md` | Completed / Not run |
| JWT | `sast/jwt-results.md` | Completed / Not run |
| Missing Auth | `sast/missingauth-results.md` | Completed / Not run |
| Business Logic | `sast/businesslogic-results.md` | Completed / Not run |
| GraphQL injection | `sast/graphql-results.md` | Completed / Not run |
```

---

## Important Reminders

- Include ONLY `[VULNERABLE]` and `[LIKELY VULNERABLE]` findings in the Findings section.
- Mark `[LIKELY VULNERABLE]` findings clearly: append **⚠ Likely Vulnerable** after the finding title.
- Preserve all details from the original findings — do not summarize or truncate Proof, Remediation, or Dynamic Test sections.
- If `sast/architecture.md` exists, use it to enrich the severity rationale with application-specific context (e.g., "this endpoint handles payment data, making confidentiality impact Critical").
- Omit severity sections entirely (e.g., the `### Low` heading) if no findings fall in that tier.
