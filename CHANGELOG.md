# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-04-21

Initial public release.

### Added

- **CLI** (`npx sast-skills`) with commands:
  - `install` — interactive install (clack prompts) or flag-driven (`--yes --assistant claude|agents|all --scope project|global [--force] [--dry-run]`).
  - `update` — refresh an existing install with the bundled skill files.
  - `uninstall` — remove installed skills; refuses to overwrite a modified `CLAUDE.md` without `--force`.
  - `doctor` — verify an install and report `OK` / `MISSING` / `MODIFIED` per file; exits non-zero on issues.
  - `export` — aggregate `sast/*-results.json` into canonical JSON, **SARIF 2.1.0**, or HTML; supports `--triaged` to prefer `sast/triaged.json`, `--output` to write to a file.
- **31 skills** following the canonical three-phase pattern (recon → batched verify → merge):
  - Reconnaissance: `sast-analysis`
  - Injection: `sast-sqli`, `sast-nosql`, `sast-ldap`, `sast-graphql`, `sast-xss`, `sast-ssti`, `sast-rce`, `sast-xxe`, `sast-ssrf`, `sast-openredirect`
  - Access control: `sast-idor`, `sast-missingauth`, `sast-jwt`, `sast-csrf`, `sast-cors`
  - File & path: `sast-pathtraversal`, `sast-fileupload`
  - Supply chain & infra: `sast-deps`, `sast-iac`, `sast-hardcodedsecrets`
  - Crypto & runtime: `sast-crypto`, `sast-prototype`, `sast-redos`, `sast-race`
  - Data exposure: `sast-pii`
  - LLM-specific: `sast-promptinjection`, `sast-llmoutput`
  - Business logic: `sast-businesslogic`
  - Synthesis: `sast-report`, `sast-triage`
- **Orchestration**: four-step flow in `CLAUDE.md` / `AGENTS.md` — analysis → parallel vulnerability scan → consolidated report → triage.
- **Canonical finding schema** in both orchestrator templates — each skill emits `sast/*-results.json` alongside markdown so the `export` CLI can produce SARIF/JSON/HTML.
- **Triage step (Step 4)** — `sast-triage` skill eliminates false positives and adjusts severities with codebase evidence, writing `sast/final-report-triaged.md` + `sast/triaged.json` without mutating the raw scan output.
- **CI integrations**:
  - Reusable composite GitHub Action at `.github/actions/scan/action.yml` (SARIF → Code Scanning).
  - Pre-commit hook template at `hooks/pre-commit`.
  - `Dockerfile` (node:20-alpine) + `.dockerignore`.
- **Developer tooling**:
  - `scripts/sync-skills.js` — mirror `.claude/skills` to `.agents/skills`.
  - `scripts/scaffold-skill.js` — generate a new skill stub in both trees.
  - `scripts/register-skill.js` — auto-patch `CLAUDE.md` / `AGENTS.md` / `README.md` when adding a new skill.
  - `prepublishOnly` runs sync + full test suite.
- **Test suite** — 64+ tests covering CLI behaviour, install / update / uninstall / doctor / export flows, orchestrator contract, skill frontmatter schema, `.claude/skills` ↔ `.agents/skills` drift, markdown lint, release readiness.
- **Documentation** — README, CONTRIBUTING, CHANGELOG, CODE_OF_CONDUCT.

### Known limitations

- Skill body prose is LLM-generated security guidance — production-grade, but detection quality depends on the model running the scan; complement with dedicated scanners (Semgrep, CodeQL, OSV-Scanner) where available.
- Paket sast-files tree'i hem `.claude/skills` hem `.agents/skills` altında taşır (mirror); paket boyutunu küçültmek ileriki sürümde hedeftir.

[Unreleased]: https://github.com/mstfknn/sast-skills/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mstfknn/sast-skills/releases/tag/v0.1.0
