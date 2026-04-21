---
name: sast-triage
description: >-
  Post-scan triage of a SAST run. Reads the raw sast/final-report.md and all
  sast/*-results.json files and produces a decided view: each finding is marked
  true positive, false positive, or severity-adjusted (up or down) with
  codebase evidence for every change. Writes sast/final-report-triaged.md and
  sast/triaged.json without modifying the raw scan outputs. Use after the
  sast-report skill has produced the consolidated report.
version: 0.1.0
---

# sast-triage

Your goal is to reduce false positives and correct severities in the consolidated SAST report, **without destroying the raw scan outputs**. The output of this skill is the report the project owner will actually act on.

## When to run

Run **after** `sast/final-report.md` exists and **before** any remediation work begins. Skip if `sast/final-report-triaged.md` already exists.

## Inputs

- `sast/final-report.md` — consolidated human-readable findings.
- `sast/*-results.json` — per-skill canonical findings (each with `id`, `skill`, `severity`, `title`, `description`, `location`, `remediation`).
- `sast/architecture.md` — tech stack, entry points, trust boundaries.

## Outputs

- `sast/final-report-triaged.md` — human-readable triaged report. Group findings by triage status (confirmed → downgraded → upgraded → false positive) with a short evidence note per finding.
- `sast/triaged.json` — canonical triaged findings. **Additive file.** Never overwrite `sast/*-results.json` or `sast/final-report.md`.

### triaged.json schema

```json
{
  "run": { "tool": "sast-skills", "version": "<installed-version>" },
  "findings": [
    {
      "id": "sast-sqli-0001",
      "skill": "sast-sqli",
      "severity": "critical|high|medium|low|info",
      "title": "...",
      "description": "...",
      "location": { "file": "src/api/user.js", "line": 42, "column": 10 },
      "remediation": "...",
      "triage_status": "confirmed|upgraded|downgraded|false_positive",
      "triage_original_severity": "high",
      "triage_evidence": "reachable from POST /api/user via authenticated session, user-controlled `id` param concatenated into query at src/db.js:17"
    }
  ]
}
```

- `triage_status` is **required** on every finding.
- `triage_original_severity` is set only when severity was changed.
- `triage_evidence` is **required** for any status other than `confirmed` — it cites concrete code locations, config, or tests that justify the decision.
- Drop nothing: a false positive stays in the output with `triage_status: "false_positive"` so the decision is auditable.

## Three-phase approach

### Phase 1 — Triage plan

Read `sast/final-report.md` and `sast/*-results.json` end to end. Produce an internal plan grouping findings into batches of at most 5 related findings (same skill or same file when possible). Write the plan to `sast/triage-plan.md` for transparency; clean up at the end.

### Phase 2 — Batched verify (parallel subagents)

Launch one subagent per batch, **all in parallel**. Give each subagent the same instructions, substituting the batch number and the findings:

> For each finding in this batch, reason from the codebase, not from the finding text. Check reachability from a real entry point, existing mitigations (validation, parameterization, framework defaults, auth), whether the code is test/mock/fixture, and whether this is a duplicate of another finding. Assign a `triage_status` from {confirmed, upgraded, downgraded, false_positive}. When changing status or severity, quote at least one concrete file:line of evidence. Write results to `sast/triage-batch-<N>.json` using the schema above.

#### False-positive criteria (any one is sufficient)

- **Unreachable**: no call path from an external entry point (user request, CLI arg, message queue, scheduled job) can reach the sink.
- **Test or mock only**: the code lives under `test/`, `spec/`, `__mocks__/`, `fixtures/`, or is gated behind `NODE_ENV=test`.
- **Mitigated**: a validated, framework-level, or upstream mitigation makes the sink safe (e.g. prepared statements via an ORM, automatic escaping in the view layer, a WAF rule that the finding ignored).
- **Sanitized**: user input is canonicalized/escaped before reaching the sink and the sanitizer is known-correct for the sink's grammar.
- **Duplicate**: the same root cause is already reported in another finding.

#### Severity rubric (both directions)

| Adjust | Trigger |
|---|---|
| Upgrade — raise severity | Sink touches authentication, payments, PII of many users; reachable unauthenticated; chained with another finding to produce RCE/data loss; exists in production path while recon assumed preview. |
| Downgrade — lower severity | Impact limited to the attacker's own account / own tenant; requires admin privileges already; exploit window bounded by rate limits or circuit breakers; preview or feature-flagged off. |
| Keep (confirmed) | No new evidence changes the recon severity. |

**Every upgrade or downgrade must cite concrete evidence in `triage_evidence`.** "Looks less important" is not evidence.

### Phase 3 — Merge

Read all `sast/triage-batch-*.json` files. Deduplicate findings (same `id`), resolve conflicts (prefer the batch with stronger evidence), then emit:

1. `sast/triaged.json` — one consolidated file using the schema above.
2. `sast/final-report-triaged.md` — human-readable report grouped by `triage_status` in this order: confirmed → upgraded → downgraded → false_positive. Within each group, sort by severity desc. For each finding show: title, location, severity (with original if changed), and the triage evidence.

Delete `sast/triage-plan.md` and all `sast/triage-batch-*.json` at the end; the triaged outputs are the only persistent artifacts.

## What this skill does NOT do

- Does not modify `sast/*-results.json` or `sast/final-report.md`. The raw scan stays auditable.
- Does not add new vulnerability classes. It only re-decides findings the scan already produced.
- Does not remediate. Remediation is a separate human or LLM task downstream.
