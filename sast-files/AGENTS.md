# SAST Security Assessment

Your goal is to identify security vulnerabilities in the codebase located in the current directory.

---

## Step 1: Codebase Analysis & Threat Modeling

Before running, check if `sast/architecture.md` already exists. If it does, skip this step.

Run the sast-analysis skill directly (this one stays in-session since later steps depend on reading its output).

**Wait for this step to finish before proceeding.**

---

## Step 2: Vulnerability Detection (Parallel)

Run all checks at the same time. Skip any task where the output file already exists.

- Skip IDOR if `sast/idor-results.md` already exists.
- Skip SQLi if `sast/sqli-results.md` already exists.
- Skip SSRF if `sast/ssrf-results.md` already exists.
- Skip XSS if `sast/xss-results.md` already exists.
- Skip RCE if `sast/rce-results.md` already exists.
- Skip XXE if `sast/xxe-results.md` already exists.
- Skip File Upload if `sast/fileupload-results.md` already exists.
- Skip Path Traversal if `sast/pathtraversal-results.md` already exists.
- Skip SSTI if `sast/ssti-results.md` already exists.
- Skip JWT if `sast/jwt-results.md` already exists.
- Skip Missing Auth if `sast/missingauth-results.md` already exists.
- Skip Business Logic if `sast/businesslogic-results.md` already exists.
- Skip GraphQL injection if `sast/graphql-results.md` already exists.
- Skip Hardcoded Secrets if `sast/hardcodedsecrets-results.md` already exists.

Start **one subagent per check**, all **in parallel**, each with a dedicated task. Give each subagent the same instruction pattern, using the skill name and paths from the table:

> Read `sast/architecture.md` for context, then run the named SAST skill. Write all findings to that skill's results file. Clean up any intermediate recon or threat files for that skill when done.

| Skill | Results file | Typical intermediate files to clean |
|-------|----------------|--------------------------------------|
| sast-idor | `sast/idor-results.md` | `sast/idor-recon.md` |
| sast-sqli | `sast/sqli-results.md` | `sast/sqli-recon.md`, `sast/sqli-batch-*.md` |
| sast-ssrf | `sast/ssrf-results.md` | `sast/ssrf-recon.md` |
| sast-xss | `sast/xss-results.md` | `sast/xss-recon.md` |
| sast-rce | `sast/rce-results.md` | `sast/rce-recon.md`, `sast/rce-batch-*.md` |
| sast-xxe | `sast/xxe-results.md` | `sast/xxe-recon.md` |
| sast-fileupload | `sast/fileupload-results.md` | `sast/fileupload-recon.md`, `sast/fileupload-batch-*.md` |
| sast-pathtraversal | `sast/pathtraversal-results.md` | `sast/pathtraversal-recon.md`, `sast/pathtraversal-batch-*.md` |
| sast-ssti | `sast/ssti-results.md` | `sast/ssti-recon.md` |
| sast-jwt | `sast/jwt-results.md` | `sast/jwt-recon.md` |
| sast-missingauth | `sast/missingauth-results.md` | `sast/missingauth-recon.md`, `sast/missingauth-batch-*.md` |
| sast-businesslogic | `sast/businesslogic-results.md` | `sast/businesslogic-threats.md`, `sast/businesslogic-batch-*.md` |
| sast-graphql | `sast/graphql-results.md` | `sast/graphql-recon.md` |
| sast-hardcodedsecrets | `sast/hardcodedsecrets-results.md` | `sast/hardcodedsecrets-recon.md`, `sast/hardcodedsecrets-batch-*.md` |

Wait for all subagents to finish before proceeding.

### Canonical JSON output

In addition to the human-readable `sast/<skill>-results.md`, each subagent must also emit a machine-readable `sast/<skill>-results.json` file so the `sast-skills export` CLI can aggregate `sast/*-results.json` into SARIF, JSON, or HTML.

Each JSON file must contain a single object with a `findings` array. Each finding follows this canonical schema:

```json
{
  "findings": [
    {
      "id": "<skill>-<sequential-id>",
      "skill": "<skill-name>",
      "severity": "critical|high|medium|low|info",
      "title": "short one-line description",
      "description": "full explanation including exploitability",
      "location": { "file": "relative/path.ext", "line": 123, "column": 10 },
      "remediation": "how to fix"
    }
  ]
}
```

If a skill produces no findings, still write the file with `"findings": []` so the aggregator can verify the scan ran.

---

## Step 3: Report Generation

After all subagents from Step 2 finish, generate the final consolidated report.

Skip this step if `sast/final-report.md` already exists.

Launch a single subagent:

> Read all available `sast/*-results.md` files and `sast/architecture.md` for context, then run the sast-report skill to generate `sast/final-report.md` with all findings ranked by severity and confidentiality impact.

---

## Step 4: Triage

After `sast/final-report.md` is generated, triage every finding to eliminate false positives and correct severities.

Skip this step if `sast/final-report-triaged.md` already exists.

Launch a single subagent that runs the sast-triage skill:

> Read `sast/final-report.md`, all `sast/*-results.json`, and `sast/architecture.md`. Run the sast-triage skill. For each finding, decide if it is a true positive, a false positive, or needs a severity adjustment (up or down), with evidence from the codebase for every change. Write the final triaged report to `sast/final-report-triaged.md` and the machine-readable canonical view to `sast/triaged.json`. Do not modify the original `*-results.json` or `final-report.md` — the triaged files are additive so the raw output stays auditable.

`sast-skills export --input sast/ --triaged` will prefer `sast/triaged.json` over `sast/*-results.json` when both are present.
