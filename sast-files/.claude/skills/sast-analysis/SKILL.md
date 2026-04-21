---
name: sast-analysis
description: >-
  Perform codebase analysis and architecture mapping as the first phase of a
  security assessment. Explores the tech stack, frameworks, entry points, data
  flows, and trust boundaries. Outputs sast/architecture.md. Run this before any
  vulnerability detection skill. Use when asked to analyze a codebase for
  security or when sast/architecture.md does not yet exist.
version: 0.1.0
---

# Codebase Analysis

You are performing the first phase of a security assessment. Your goal is to deeply understand the codebase. You are NOT looking for specific vulnerabilities yet. This is pure reconnaissance.

Create a `sast/` folder in the project root (if it doesn't already exist). This phase produces one output file inside it:

`sast/architecture.md` — technology stack, architecture, entry points, data flows

## Phase 1: Technology Reconnaissance

Explore the codebase and identify:

- **Languages**: All programming languages used and their versions if specified
- **Frameworks**: Web frameworks, ORM layers, template engines, task queues
- **Package managers & dependencies**: Lock files, dependency manifests (package.json, requirements.txt, go.mod, Gemfile, pom.xml, etc.)
- **Infrastructure hints**: Dockerfiles, docker-compose, Kubernetes manifests, Terraform, CI/CD configs
- **Databases**: SQL, NoSQL, cache layers, message brokers — look at connection strings, ORM models, migration files
- **Authentication & authorization**: Auth libraries, middleware, session configs, OAuth/OIDC providers, JWT usage, API key patterns
- **External integrations**: Third-party APIs, payment processors, email services, cloud SDKs, webhook handlers
- **Entry points**: HTTP routes, GraphQL schemas, gRPC service definitions, CLI commands, WebSocket handlers, scheduled jobs, message consumers

Start by reading dependency manifests, project configs, and directory structure. Then drill into source code to confirm findings.

## Phase 2: Architecture Mapping

Based on Phase 1, build a mental model of:

1. **Service boundaries**: Is this a monolith or microservices? What talks to what?
2. **Data flow**: How does user input enter the system, get processed, get stored, and get returned?
3. **Trust boundaries**: Where does the system transition between trusted and untrusted contexts? (e.g., user input -> backend, backend -> database, service -> service, server -> client)
4. **Privilege levels**: What roles/permissions exist? How are they enforced? Is there an admin panel?
5. **Sensitive data inventory**: PII, credentials, tokens, financial data, health records — where is each stored and how does it move?

**Write the results of Phase 1 and Phase 2 to `sast/architecture.md`.** Use this format:

```markdown
# Architecture: [Project Name]

## Technology Stack

| Category | Details |
|---|---|
| Languages | ... |
| Frameworks | ... |
| Databases | ... |
| Auth mechanism | ... |
| Infrastructure | ... |
| External services | ... |

## Architecture Overview

[Describe the architecture: monolith vs microservices, how components interact,
main modules and their responsibilities]

## Data Flow

[Trace how user input enters the system, gets processed, stored, and returned.
Cover the primary flows (e.g., registration, login, core business actions).]

## Entry Points

| Entry Point | Type | Auth Required | Description |
|---|---|---|---|
| ... | HTTP/GraphQL/WS/etc. | Yes/No | ... |

## Trust Boundaries

[List each trust boundary and what crosses it]

## Sensitive Data Inventory

| Data Type | Where Stored | How Accessed | Protection |
|---|---|---|---|
| ... | ... | ... | ... |
```

## Important Reminders

- Do NOT report specific vulnerabilities (like "line 42 has SQL injection"). That comes in later phases.
- Be thorough in exploration. Read actual source code, not just config files. Look at how auth middleware is applied, how queries are built, how file uploads are handled.
- If the codebase is large, prioritize security-sensitive areas: auth, payment, data access, file handling, admin functionality.
