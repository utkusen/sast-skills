---
name: sast-deps
description: >-
  Survey a codebase for known-vulnerable dependencies (direct and transitive)
  using a three-phase approach: recon (inventory all ecosystem manifests and
  lockfiles), batched verify (match package@version pairs against CVE/GHSA/OSV
  advisories in parallel subagents, 3 ecosystem files each), and merge
  (consolidate batch results). Also flags end-of-life runtimes, risky
  ecosystem defaults, and supply-chain markers. Requires sast/architecture.md
  (run sast-analysis first). Outputs findings to sast/deps-results.md and
  sast/deps-results.json. Use when asked to audit dependencies, check for
  CVEs, find vulnerable packages, or run an SCA-style review.
version: 0.1.0
---

# Vulnerable Dependencies

**Prerequisites**: sast/architecture.md must exist.

You are performing a software-composition-analysis-style review of a codebase. The goal is to enumerate every direct and transitive dependency with a version, then flag versions that are listed in a published CVE, GHSA, or ecosystem advisory and affect the application's actual usage context.

This skill is closer to an **inventory / survey** than a taint-tracing vulnerability hunt. You are not looking for bugs in the application's own code — you are looking for bugs in the *third-party code it ships with*. The core activity is careful enumeration and cross-referencing against public vulnerability databases.

## What is a Vulnerable Dependency

A vulnerable dependency is a direct or transitive dependency version, pinned in a lockfile or manifest, that has a published CVE or advisory which affects the application's usage context.

The definition has three parts, and all three must hold for a finding to be real:

1. **A specific package@version is actually present.** The lockfile says `lodash@4.17.15`, not just `lodash` "somewhere". Ranges in `package.json`, `requirements.txt`, or `Cargo.toml` are not enough on their own — the resolved version in the lockfile is what actually ships.
2. **A published advisory affects that version.** There is a CVE, GHSA ID, RustSec advisory, PyPA advisory, Go vulnerability ID, or ecosystem-specific note whose affected-range includes the pinned version, and whose fix version is higher than the pinned version (or no fix exists yet — "zero-day-ish" cases).
3. **The application's usage context is plausibly affected.** Some CVEs only apply to a specific sub-module, feature flag, or platform. A prototype-pollution bug in `lodash.merge` does not matter if the app only uses `lodash.chunk`. A Windows-specific path-handling bug does not matter on a Linux-only container image. Usage context matters — but when in doubt, err on the side of reporting, because transitive use is hard to rule out from static inspection alone.

### What Vulnerable Deps ARE

- `lodash@4.17.15` locked in `package-lock.json` (prototype pollution in `merge`, `mergeWith`, `defaultsDeep` — fixed in 4.17.21, CVE-2020-8203, GHSA-p6mc-m468-83gw).
- `express@4.16.0` with `body-parser` consuming unbounded request bodies — resource-exhaustion / DoS via large payloads when no `limit` is configured (fixed behavior in newer Express + explicit `limit` option).
- `django@2.2.10` in `requirements.txt` with SQL injection in `QuerySet.order_by()` when passing user-controlled field names (CVE-2021-35042, fixed in 2.2.24).
- `log4j-core-2.14.1.jar` in `pom.xml` (Log4Shell, CVE-2021-44228, remote code execution via JNDI lookup in log messages — fixed in 2.17.1).
- `spring-core@5.3.17` with Spring4Shell gadget chain (CVE-2022-22965, fixed in 5.3.18 / 5.2.20).
- A transitive `minimist@0.2.1` pulled in by a direct dep (prototype pollution, GHSA-vh95-rmgr-6w4m, fixed in 0.2.4 / 1.2.6).
- A Python 3.7 runtime pinned in a Dockerfile or `.python-version` — EOL since 2023-06-27; no further security patches.
- A Node.js 14 `FROM node:14` in the Dockerfile — EOL since 2023-04-30.
- A typosquat candidate: `colors` suddenly pulling from a suspicious fork, or `event-stream`-like historically-hijacked packages still pinned to a malicious version.

### What Vulnerable Deps are NOT

- Bugs in the application's own first-party code. A SQL injection in `app/routes/users.py` is for `sast-sqli`, not this skill.
- Libraries listed in `package.json` but **not resolved** in the lockfile because they are `devDependencies` that never ship to prod. (Caveat: if the build-time chain itself is attacker-influencing — e.g. a malicious `postinstall` script or a compromised build tool — that *is* a finding; see "supply-chain markers" below.)
- Unused libraries: a dep that appears in `package.json` but has no `import` / `require` / no symbol usage anywhere in source. Report these with lower severity or as an info finding — they still ship, and transitive consumers might still hit them, but the direct attack surface is reduced.
- Abstract "old-ish looking" deps without an actual advisory. "This version is 2 years old" is not a finding by itself. Outdated is not the same as vulnerable.
- Advisories on a different major version than what is pinned. CVE affects `v1.x`, app uses `v2.x` — not a finding (unless the CVE range explicitly includes both).

### Patterns That Prevent Vulnerable Deps

When reading a project, note whether any of the following exist. Their presence reduces residual risk and should be mentioned in the report so the reader understands the control environment:

- **Pinned and code-reviewed dependencies.** A lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`) committed to source control, with lockfile changes visible in PR diffs. Floating `^` or `~` ranges without a committed lockfile is a smell.
- **Automated update bots.** Dependabot (`.github/dependabot.yml`), Renovate (`renovate.json` / `.renovaterc`), or Snyk PRs indicate the team regularly receives and merges security-patch PRs. Absence of any such config is itself an info-severity observation.
- **Committed lockfiles.** `package-lock.json` in `.gitignore` is a failure pattern — it means non-deterministic installs per developer and per CI run.
- **Native auditors in CI.** A CI job that runs `npm audit --audit-level=high`, `pnpm audit`, `yarn audit`, `pip-audit`, `safety check`, `bundle-audit`, `govulncheck ./...`, `cargo audit`, `mvn org.owasp:dependency-check-maven:check`, or `gradle dependencyCheckAnalyze`. These tools have live CVE data and are more authoritative than an LLM's static knowledge.
- **Dependency-review action on PRs.** GitHub's `actions/dependency-review-action` or equivalent, failing PRs that introduce a new high-severity advisory.
- **SBOM generation.** A CycloneDX or SPDX SBOM produced as a build artifact (`cyclonedx-bom`, `syft`, `cdxgen`). SBOMs give downstream consumers clean CVE matching and indicate a mature supply-chain posture.
- **Pinned container base images by digest.** `FROM node:18@sha256:...` instead of `FROM node:18`. This prevents silent tag repointing.
- **`npm ci` / `pip install --require-hashes` / `cargo install --locked`** in CI and Dockerfile build steps, to enforce lockfile-based installs.

If none of these are present, that itself is a meaningful observation — the team has no systematic way to catch the next CVE, so the set of findings is likely to grow uncontrolled until one is adopted.

## Vulnerable vs. Secure Examples

Below are illustrative lockfile-shaped snippets. Actual lockfiles are much larger; these show the shape of what constitutes a finding.

**Vulnerable (`package-lock.json` fragment):**

```json
"node_modules/lodash": {
  "version": "4.17.15",
  "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
  "integrity": "sha512-..."
}
```

Lodash `<4.17.21` has multiple prototype-pollution CVEs (CVE-2019-10744, CVE-2020-8203, CVE-2021-23337). Fixed in 4.17.21.

**Secure:**

```json
"node_modules/lodash": {
  "version": "4.17.21",
  "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
  "integrity": "sha512-..."
}
```

---

**Vulnerable (`package.json` + no `limit` config):**

```json
"dependencies": {
  "express": "^4.16.0",
  "body-parser": "^1.18.0"
}
```

```js
app.use(bodyParser.json());               // default limit, bypassable on some versions
app.use(bodyParser.urlencoded({ extended: true }));
```

Old body-parser versions + no explicit `limit` → large-payload DoS. `express@<4.17.3` also has a ReDoS-adjacent `qs` issue (CVE-2022-24999 via `qs`).

**Secure:**

```json
"dependencies": {
  "express": "^4.19.2"
}
```

```js
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));
```

---

**Vulnerable (`requirements.txt`):**

```
Django==2.2.10
PyYAML==5.3
requests==2.19.1
urllib3==1.24.1
Pillow==7.1.0
```

- `Django 2.2.10` — multiple CVEs, including SQLi and XSS, fixed across the 2.2.x patch line.
- `PyYAML 5.3` — arbitrary-code execution via `yaml.load()` without `SafeLoader` on some deserialization paths (CVE-2020-14343, fixed in 5.4).
- `urllib3 1.24.1` — CRLF injection and redirect-handling issues (CVE-2019-11324, fixed in 1.24.2+, and later issues through 1.26.x).
- `Pillow 7.1.0` — multiple image-parsing buffer overflows and DoS (fixed across 8.x / 9.x / 10.x).

**Secure (with `pip-audit` clean + committed `Pipfile.lock` / `poetry.lock`):**

```
Django==4.2.11
PyYAML==6.0.1
requests==2.32.3
urllib3==2.2.2
Pillow==10.3.0
```

---

**Vulnerable (`pom.xml`):**

```xml
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.14.1</version>
</dependency>
```

Log4Shell (CVE-2021-44228), followup CVE-2021-45046, CVE-2021-45105, CVE-2021-44832. Fix: upgrade to 2.17.1+ (Java 8) / 2.12.4 (Java 7).

---

**Vulnerable (`go.mod` + `go.sum`):**

```
require (
  github.com/dgrijalva/jwt-go v3.2.0+incompatible
  golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975
)
```

`dgrijalva/jwt-go` is archived and unmaintained, with CVE-2020-26160 (audience bypass). Migrate to `github.com/golang-jwt/jwt/v5`. Old `golang.org/x/crypto` has `ssh` and `cryptobyte` issues fixed in later versions.

## Execution

### Phase 1: Recon — Inventory Dependencies

Read `sast/architecture.md` for the tech-stack context, then inventory every dependency source. Cast a wide net — a polyglot repo often has more than one ecosystem.

**Ecosystem files to look for (absolute paths relative to repo root):**

- **Node.js / JS / TS**: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`, per-workspace `package.json` files in monorepos.
- **Python**: `requirements.txt` (and any `requirements-*.txt`), `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml` (`[project.dependencies]` and `[tool.poetry.dependencies]`), `setup.py`, `setup.cfg`, `constraints.txt`, `uv.lock`.
- **Go**: `go.mod`, `go.sum`, vendored `vendor/modules.txt`.
- **Rust**: `Cargo.toml`, `Cargo.lock`.
- **Java / JVM**: `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`, `settings.gradle*`, `ivy.xml`.
- **Ruby**: `Gemfile`, `Gemfile.lock`, `*.gemspec`.
- **PHP**: `composer.json`, `composer.lock`.
- **.NET**: `*.csproj`, `packages.lock.json`, `paket.lock`, `paket.dependencies`.
- **Swift / iOS**: `Package.swift`, `Package.resolved`, `Podfile`, `Podfile.lock`.
- **Android**: `build.gradle` (app + project), `gradle/libs.versions.toml`.
- **Elixir / Erlang**: `mix.exs`, `mix.lock`.
- **Container base images**: `Dockerfile`, `Containerfile`, `*.Dockerfile`, `docker-compose.yml` images.
- **OS packages**: `apt`, `apk`, `yum` calls inside Dockerfiles — note the installed versions if pinned.
- **Runtime pins**: `.nvmrc`, `.node-version`, `.python-version`, `.ruby-version`, `.tool-versions` (asdf), `go.work`, `rust-toolchain.toml`, `engines` field in `package.json`.

For each manifest, record:

- **Direct dependencies** with the range declared (e.g. `express: ^4.16.0`).
- **Resolved versions** from the lockfile (e.g. `express@4.16.1` + its transitive chain).
- **Transitive dependencies** — the lockfile is authoritative. Skimming top-level direct deps misses 90% of the attack surface in modern Node projects.
- **Runtime and platform pins** — Node version, Python version, Go version, JDK version, base-image tag and digest.

**Output of Phase 1** (keep in scratch, do not ship as a final artifact): a list of `ecosystem-file → [package@version, ...]` plus `runtime → version` pairs. Group by ecosystem so the verify phase can batch.

Flag these recon-level observations already:

- **End-of-life runtimes** (severity: high). Python 2.x, Python 3.7 and older (EOL), Node.js 14 and older (EOL), Go 1.19 and older (unsupported), Java 8 without paid LTS. An EOL runtime receives no security patches — any future CVE in the interpreter itself is unfixed.
- **Missing lockfile** for an ecosystem that supports one. `package.json` without `package-lock.json` / `yarn.lock`; `pyproject.toml` declaring Poetry without `poetry.lock` committed; `Cargo.toml` without `Cargo.lock` (for apps, not libs).
- **Floating tags** in Dockerfiles (`FROM node:latest`, `FROM python:3`) — non-reproducible, silently re-pointable.
- **Absence of any SCA signal** — no dependabot config, no renovate, no CI audit job, no SBOM.

### Phase 2: Verify — CVE Match (Batched)

Group the manifests from Phase 1 into batches of **3 ecosystem files per subagent** and run them in parallel. Each subagent gets:

- The ecosystem files for its batch.
- A copy of `sast/architecture.md` for context on how the deps are actually used.
- Instructions to produce a per-batch file, `sast/deps-batch-<N>.md`, with raw findings.

For each `package@version`, the subagent attempts to match against its knowledge of CVE / GHSA / OSV / ecosystem advisories. For each potential match, record:

- **Package name and ecosystem** (e.g. `npm:lodash`, `pypi:django`, `maven:org.apache.logging.log4j:log4j-core`).
- **Pinned version** (from lockfile when available, otherwise the manifest range).
- **CVE ID** (e.g. `CVE-2021-44228`).
- **GHSA / RustSec / PyPA / Go vuln / advisory ID** (e.g. `GHSA-jfh8-c2jp-5v3q`).
- **Affected version range** (e.g. `>=2.0.0,<2.17.1`).
- **Fixed version** (e.g. `2.17.1`, or `none — unpatched`).
- **Severity** (use advisory severity: critical / high / medium / low).
- **Direct vs transitive** — is this declared in the project's own manifest, or pulled in via a parent? Transitive findings usually require bumping or overriding the parent.
- **Exploit context** — what class of bug (RCE, SSRF, deserialization, prototype pollution, DoS, path traversal, XXE, privilege escalation, logic flaw, crypto weakness). Whether the app's usage actually reaches the vulnerable code path, if determinable from a quick grep.
- **Runtime gating** — Java-version-specific, Windows-only, feature-flag-gated advisories. Note when exploitation depends on something the app may or may not have.

**Honesty about LLM limitations.** An LLM's knowledge of CVEs is finite and has a training cutoff. New advisories are published daily. This means:

- A `No match` from the model is **not** a clean bill of health. Absence of evidence is not evidence of absence.
- Version-range math is error-prone. Double-check boundary versions against the advisory text.
- Every verify-phase finding (and the summary) must explicitly recommend running a live auditor to supplement. Suggested commands per ecosystem:
  - Node: `npm audit --audit-level=low`, or `pnpm audit`, or `yarn npm audit` (Yarn Berry).
  - Python: `pip-audit -r requirements.txt` or `pip-audit` in a poetry-exported requirements file; `safety check`.
  - Go: `govulncheck ./...` (symbol-level reachability aware).
  - Rust: `cargo audit`.
  - Ruby: `bundle-audit check --update`.
  - Java (Maven): `mvn org.owasp:dependency-check-maven:check`.
  - Gradle: `./gradlew dependencyCheckAnalyze`.
  - Cross-ecosystem: `osv-scanner -r .`, `trivy fs --scanners vuln .`, `grype dir:.`, `syft packages dir:. -o cyclonedx-json | grype`.

Each batch subagent should end its batch file with a "Recommended auditor commands for this batch" section.

**Supply-chain markers to look for during verify** (in addition to CVE matching):

- **Typosquat candidates**: suspiciously named packages near a popular one (`lodahs` vs `lodash`, `cross-env.js` vs `cross-env`, `colorss` vs `colors`). Flag if present.
- **Recently-hijacked packages** pinned to the known-bad version window: `event-stream@3.3.6`, `ua-parser-js@0.7.29 / 0.8.0 / 1.0.0`, `colors@1.4.44-liberty-2`, `faker@6.6.6`, `node-ipc` sabotaged versions. Add any others the model is confident about.
- **Unpinned install scripts**: `curl | bash` or `wget | sh` inside Dockerfiles pointing at moving tags.
- **Packages installed from a Git URL or tarball URL** instead of the registry — note and flag if the URL is not a known vendor.
- **Scoped-to-unscoped name collisions**: a private `@company/foo` paired with a suspiciously-identical public `foo` (dependency-confusion vector).

### Phase 3: Merge — Consolidate Batch Results

After all batch subagents finish, read every `sast/deps-batch-*.md` file, de-duplicate findings (a transitive package may appear via two manifests, two workspaces, etc.), and consolidate into the final outputs:

- `sast/deps-results.md` — human-readable report following the Findings template below. Group by severity, then by ecosystem.
- `sast/deps-results.json` — canonical JSON following the schema in the top-level `CLAUDE.md`. One finding per `(package, ecosystem, CVE)` triple, or per observation (EOL runtime, missing lockfile) when there is no CVE.

After writing both files, **delete the intermediate `sast/deps-batch-*.md` and any `sast/deps-recon.md` scratch file** so only the canonical outputs remain.

## Findings

Use this template in `sast/deps-results.md`. One entry per finding; multiple CVEs for one package may be combined in a single entry if they share a fix version, or split if they have different fix versions.

```markdown
### [SEVERITY] <ecosystem>:<package>@<pinned-version> — <short summary>

- **CVE**: CVE-YYYY-NNNNN (and any siblings; or "none — observation-only" for EOL runtime / missing lockfile findings)
- **Advisory ID**: GHSA-xxxx-xxxx-xxxx / RUSTSEC-YYYY-NNNN / PYSEC-YYYY-NNN / GO-YYYY-NNNN
- **Ecosystem**: npm / pypi / maven / go / cargo / rubygems / composer / nuget / container / runtime
- **Affected range**: `>=X.Y.Z,<A.B.C`
- **Fixed version**: `A.B.C` (or "no fix available — mitigations: ...")
- **Pinned in**: `path/to/package-lock.json` (line N) — or `path/to/pom.xml`, `path/to/Dockerfile`, etc.
- **Direct or transitive**: direct / transitive (via `<parent-package>`)
- **Class**: RCE / SSRF / prototype pollution / deserialization / DoS / path traversal / XSS-in-template / crypto weakness / auth bypass / other
- **Exploit context**: Is the vulnerable code path reachable in this codebase? Which call sites in `sast/architecture.md`'s entry points touch it? If unclear, state "reachability not confirmed from static inspection — err on the side of patching."
- **Evidence**: Quote the lockfile stanza or manifest line. Include the resolved URL and integrity hash when present — it anchors the finding to a specific artifact.
- **Remediation**:
  1. Bump `<package>` to `>=<fixed-version>`.
  2. If transitive: add an `overrides` (npm), `resolutions` (yarn), `constraints.txt` (pip), or `dependencyManagement` (Maven) entry pinning the transitive to a fixed version, and/or bump the parent that pulls it in.
  3. Re-run `npm ci` / `pip install --require-hashes` / equivalent and re-run the auditor to confirm the advisory is gone.
- **References**:
  - https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
  - https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
  - Upstream changelog / release notes link
```

For the observation-only entries (EOL runtime, missing lockfile, no CI auditor, supply-chain marker), use a simplified form:

```markdown
### [SEVERITY] <observation title>

- **Observation**: <what was found>
- **Evidence**: `<file>:<line>` — quote the offending line or config
- **Impact**: Why this matters (no patches for EOL runtime; non-reproducible installs for missing lockfile; etc.)
- **Remediation**: Concrete next step (upgrade runtime, commit lockfile, add audit job, etc.)
```

Conclude `sast/deps-results.md` with a **Summary** section that includes:

1. Counts by severity (critical / high / medium / low / info).
2. Counts by ecosystem.
3. Counts of direct vs transitive.
4. An explicit note: *"This scan reflects the model's CVE knowledge at training-cutoff time and is **not** a substitute for a live vulnerability-database scan. Run `npm audit`, `pip-audit`, `govulncheck`, `cargo audit`, or `osv-scanner` as appropriate for each ecosystem to supplement these findings."*
5. The list of recommended auditor commands for the specific ecosystems present in this repo.
6. Observations about the control environment: presence/absence of dependabot/renovate config, committed lockfiles, CI audit jobs, SBOM generation, pinned base images. These contextualize how quickly the team can respond to future CVEs, independent of the specific findings above.
