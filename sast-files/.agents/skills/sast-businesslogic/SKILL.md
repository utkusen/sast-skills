---
name: sast-businesslogic
description: >-
  Detect business logic vulnerabilities in a codebase using a three-phase
  approach: threat modeling (domain analysis and attack scenarios), batched
  verify (check exploitable gaps in parallel subagents, 3 scenarios each),
  and merge (consolidate batch results). Covers price manipulation, workflow
  bypass, limit violations, race conditions, reward abuse, etc. Requires
  sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/businesslogic-results.md. Use when asked to find business logic, logic
  flaws, or abuse-of-function bugs.
version: 0.1.0
---

# Business Logic Vulnerability Detection

You are performing a focused security assessment to find business logic vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **threat modeling** (understand the domain and generate attack scenarios), **batched verify** (check whether scenarios are exploitable in parallel batches of 3), and **merge** (consolidate batch results).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What are Business Logic Vulnerabilities

Business logic vulnerabilities arise when an application's intended workflow, rules, or constraints can be manipulated to produce unintended outcomes — without exploiting technical flaws like injection or memory corruption. The attacker operates within the application's own features but uses them in ways the developers did not anticipate.

The core pattern: *the application accepts input that is syntactically valid and passes authentication/authorization, but violates a business rule that was never enforced in code.*

### What Business Logic Vulnerabilities ARE

- Submitting a negative quantity to a purchase endpoint, receiving a credit instead of a charge
- Applying the same one-time discount coupon multiple times in parallel requests
- Skipping the payment step in a multi-step checkout by replaying a later step's request
- Posting a rating of 9999 to a movie rating endpoint that should cap ratings at 5
- Transferring a negative amount to move money from the recipient to the sender
- Redeeming a referral bonus by referring yourself with a second account
- Re-using a single-use reset token or voucher that was never invalidated
- Purchasing an item that is out of stock due to a race condition between inventory check and reservation
- Accessing a premium subscription feature after downgrading to a free plan
- Winning an auction by retracting a high bid after others have been eliminated

### What Business Logic Vulnerabilities are NOT

Do not flag these as business logic issues:

- **SQL injection, XSS, RCE, XXE, SSRF, SSTI**: These are injection/technical flaws — separate skills cover them
- **Missing authentication**: Endpoint requires no login at all → that's "Unauthenticated Access"
- **IDOR**: Accessing another user's resource by changing an ID → that's a separate access-control class
- **Brute-force / rate limiting**: Generic rate-limit bypass on login → that's not a business logic flaw unless it enables specific business rule circumvention

---

## Business Logic Attack Categories

Use these categories to guide threat modeling. Not all categories apply to every application — identify which ones are relevant based on the architecture summary.

### 1. Price & Payment Manipulation
- Negative prices or zero prices on purchase endpoints
- Arbitrary price override in request body (mass assignment of price field)
- Currency or unit confusion (e.g., cents vs. dollars)
- Floating-point precision abuse in monetary arithmetic
- Applying discounts that reduce total below zero

### 2. Quantity & Numeric Limit Violations
- Negative quantities (ordering −5 items to receive a credit)
- Quantities exceeding per-user or per-order limits
- Integer overflow/underflow in quantity or balance calculations
- Out-of-range values for bounded fields (ratings, scores, percentages)

### 3. Workflow & Multi-Step Process Bypass
- Skipping mandatory steps in a sequential process (payment, email verification, ID check)
- Replaying a completion token from a previous successful flow to bypass steps
- Direct-access to a later-stage endpoint without completing earlier stages
- Submitting a terminal state transition without going through intermediate states (state machine violations)

### 4. Coupon, Discount & Voucher Abuse
- Applying the same coupon multiple times (single-use not enforced)
- Stacking discounts that were not intended to be combined
- Using an expired coupon or voucher
- Generating or guessing valid coupon codes

### 5. Race Conditions & Concurrency Abuse
- Double-spending: sending two concurrent purchase requests to consume a balance once
- Concurrent coupon redemption draining credit beyond allowed amount
- TOCTOU (time-of-check / time-of-use) on inventory: check passes for both requests, both reservations succeed
- Parallel withdrawal/transfer requests exceeding account balance

### 6. Refund & Chargeback Abuse
- Requesting a refund after the digital good has been consumed or downloaded
- Partial refund on an already-partially-refunded order
- Refund without returning physical item (if logic is not enforced server-side)

### 7. Reward, Referral & Loyalty Abuse
- Self-referral using a second account to earn a referral bonus
- Earning signup bonuses multiple times across multiple accounts
- Loyalty point farming through artificial activity
- Sharing or transferring non-transferable rewards

### 8. Subscription & Entitlement Bypass
- Accessing paid/premium features after downgrading or cancelling
- Trial period abuse (repeatedly creating new accounts for trial access)
- Feature flag or plan check performed only at subscription creation, not at feature access time
- Entitlement cached at session start and not re-evaluated after plan change

### 9. Auction & Bidding Logic
- Retracting a winning bid after competing bids have been rejected
- Shill bidding: artificially inflating price with controlled accounts
- Bypass of reserve price enforcement
- Bid manipulation via concurrent requests

### 10. Inventory & Stock Logic
- Purchasing out-of-stock items due to missing stock validation
- Reserving more stock than available via concurrent requests
- Negative inventory resulting from refund-without-restock logic
- Phantom inventory: item appears available but cannot be fulfilled

### 11. Time & Date Logic
- Using time-limited offers after expiration (expiry checked client-side or weakly server-side)
- Backdating transactions or bookings
- Exploiting "grace period" logic to extend benefits indefinitely
- System clock manipulation if server trusts client-supplied timestamps

### 12. Transfer & Balance Logic
- Transferring a negative amount (sender receives money from recipient)
- Self-transfer to exploit bonus or fee logic
- Transferring more than the available balance due to missing server-side check
- Rounding errors exploited across many micro-transactions

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Threat Modeling — Domain Analysis & Attack Scenario Generation

Launch a subagent with the following instructions:

> **Goal**: Analyze the codebase to understand its business domain and generate a concrete, prioritized list of business logic attack scenarios specific to this application. Write results to `sast/businesslogic-threats.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand what the application does, what features it has, and what business rules it is supposed to enforce. Focus entirely on understanding the domain — do not verify vulnerabilities yet.
>
> **Step 1 — Identify the business domain and features**:
>
> Read `sast/architecture.md` and then explore the codebase to answer:
> - What does this application do? (e-commerce, marketplace, SaaS, social platform, fintech, gaming, booking, etc.)
> - What financial or transactional features exist? (payments, subscriptions, credits, tokens, wallets, invoices, refunds)
> - What quantitative limits or rules exist? (ratings, scores, quantities, usage limits, quotas)
> - What multi-step workflows exist? (checkout, onboarding, KYC, booking, auctions)
> - What promotional or reward features exist? (coupons, referrals, loyalty points, bonuses, vouchers)
> - What role or tier distinctions exist? (free vs. paid, user vs. premium, trial vs. full)
> - What inventory or capacity constraints exist? (stock, seats, slots, bandwidth)
>
> To discover features, search for:
> - Route/endpoint definitions and their names
> - Model/entity names (Order, Payment, Subscription, Coupon, Wallet, Bid, etc.)
> - Business-rule-related field names (price, quantity, balance, rating, score, limit, quota, expiry, status)
> - Validation logic or constraint-related code
>
> **Step 2 — Generate attack scenarios**:
>
> For each relevant business domain area found, generate specific attack scenarios. Each scenario must be:
> - **Specific to this codebase** — name the actual endpoint, model, or feature involved
> - **Actionable** — describe exactly what an attacker would send/do
> - **Grounded** — reference the code or data model that makes this scenario plausible
>
> Use the attack categories below as a checklist. Only include categories that are relevant to this application:
>
> - **Price/payment manipulation**: Can a user send an arbitrary price in the request? Is price trusted from client?
> - **Quantity/value out of range**: Can a user send negative quantities, zero, or values exceeding defined limits?
> - **Workflow bypass**: Can a user skip a mandatory step in a multi-step process?
> - **Coupon/discount abuse**: Can a coupon be used multiple times or after expiration?
> - **Race conditions**: Are there check-then-act patterns on shared resources (inventory, balance, coupon usage)?
> - **Refund abuse**: Can a refund be requested after the product is consumed?
> - **Reward/referral abuse**: Can referral or signup bonuses be farmed?
> - **Entitlement bypass**: Are premium features checked at access time or only at subscription time?
> - **Transfer/balance logic**: Can negative transfers or self-transfers be made?
> - **Time/date logic**: Are time-limited offers enforced server-side?
> - **Inventory logic**: Is stock validated atomically before reservation?
>
> **Output format** — write to `sast/businesslogic-threats.md`:
>
> ```markdown
> # Business Logic Threat Model: [Project Name]
>
> ## Application Domain
> [2–3 sentence summary of what the application does and its key business features]
>
> ## Business Features Identified
> - [Feature 1]: [brief description, relevant models/endpoints]
> - [Feature 2]: ...
>
> ## Attack Scenarios
>
> ### 1. [Short title, e.g. "Negative quantity purchase for credit"]
> - **Category**: [e.g. Quantity & Numeric Limit Violations]
> - **Target**: [Endpoint or feature, e.g. `POST /api/orders`]
> - **Description**: [What an attacker would do and what outcome they expect]
> - **Relevant code**: [File and line range where the relevant logic lives]
> - **Business rule that should be enforced**: [What the application is supposed to do]
> - **Risk level**: [High / Medium / Low]
>
> ### 2. ...
>
> [Use sequential numbering ### 3., ### 4., ... for every scenario — required for batching in Phase 2.]
>
> ## Categories Not Applicable
> [List any categories from the checklist that are not relevant to this application and why]
> ```

### Phase 2: Verify — Check Whether Scenarios Are Exploitable (Batched)

After Phase 1 completes, read `sast/businesslogic-threats.md` and split the attack scenarios into **batches of up to 3 scenarios each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned scenarios and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/businesslogic-threats.md` and count the numbered scenario sections (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 8 scenarios → 3 batches (1–3, 4–6, 7–8).
3. For each batch, extract the full text of those scenario sections from the threats file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned scenarios.
5. Each subagent writes to `sast/businesslogic-batch-N.md` where N is the 1-based batch number.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned attack scenario, determine whether the business rule is properly enforced in code or whether the attack is exploitable. Our goal is to find business logic vulnerabilities. Write results to `sast/businesslogic-batch-[N].md`.
>
> **Your assigned scenarios** (from the threat modeling phase):
>
> [Paste the full text of the assigned scenario sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand validation patterns, ORM usage, and where business rules are typically enforced. Trace the code paths referenced in each scenario.
>
> **What business logic flaws are NOT** — do not flag these here:
> - **SQL injection, XSS, RCE, XXE, SSRF, SSTI**: separate skills
> - **Missing authentication**: Unauthenticated Access
> - **IDOR**: another access-control class
> - **Generic brute-force** unless it clearly circumvents a business rule
>
> **For each scenario, perform the following checks**:
>
> **1. Is the business rule enforced server-side?**
> - Is the constraint validated in the backend handler, service layer, or ORM/database?
> - Or is it only validated client-side (frontend form validation, JavaScript min/max attributes)?
> - Client-side-only validation = exploitable.
>
> **2. Is the validation complete and covers all edge cases?**
> - Does it check for negative values where applicable?
> - Does it check upper bounds, not just lower bounds?
> - Does it handle concurrent requests (is the check atomic, or is there a TOCTOU window)?
> - Does it re-validate at the point of use, not just at an earlier step?
>
> **3. For workflow bypass scenarios**:
> - Does each step verify that previous required steps were completed?
> - Are step completion flags stored server-side (not just in a cookie or session that can be replayed)?
> - Can a terminal endpoint be called directly without going through earlier steps?
>
> **4. For coupon/voucher scenarios**:
> - Is the coupon marked as used atomically with the transaction (in the same DB transaction)?
> - Is concurrent redemption protected (SELECT FOR UPDATE, optimistic locking, atomic compare-and-swap)?
> - Is the expiry date checked server-side at redemption time?
>
> **5. For race condition scenarios**:
> - Is stock/balance check and decrement done atomically (in a single DB transaction or with row-level locking)?
> - Is there any idempotency key or deduplication logic to prevent duplicate concurrent requests?
>
> **6. For entitlement/subscription scenarios**:
> - Is the user's current plan/tier checked at the point of feature access?
> - Or is it cached at login/session start and never re-evaluated?
>
> **7. For transfer/balance scenarios**:
> - Is there a server-side check that the transfer amount is positive?
> - Is there a server-side check that the sender has sufficient balance?
> - Are these checks done within a database transaction to prevent race conditions?
>
> **Classification**:
> - **Exploitable**: The business rule is absent, bypassable, or only enforced client-side.
> - **Likely Exploitable**: The rule exists but has gaps (race condition window, missing edge case, bypassable condition).
> - **Not Exploitable**: Proper server-side enforcement exists and covers edge cases.
> - **Needs Manual Review**: Cannot determine with confidence (complex logic, external service dependency, etc.).
>
> **Output format** — write to `sast/businesslogic-batch-[N].md`:
>
> ```markdown
> # Business Logic Batch [N] Results
>
> ## Findings
>
> ### [EXPLOITABLE] Scenario title
> - **Category**: [Attack category]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Business Rule Violated**: [What rule the application should enforce]
> - **Issue**: [Clear description of what validation is missing or broken]
> - **Impact**: [What an attacker can achieve — free goods, financial loss, unfair advantage, etc.]
> - **Proof**: [Show the code path demonstrating the missing enforcement]
> - **Remediation**: [Specific fix for this scenario]
> - **Dynamic Test**:
>   ```
>   [Step-by-step instructions or curl commands to confirm the finding on the live app.
>    Include exact HTTP method, endpoint, headers, and request body.
>    Describe what response or side effect confirms the vulnerability.]
>   ```
>
> ### [LIKELY EXPLOITABLE] Scenario title
> - **Category**: [Attack category]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Business Rule Violated**: [What rule should be enforced]
> - **Issue**: [What enforcement gap or race condition exists]
> - **Concern**: [Why this is likely exploitable despite partial enforcement]
> - **Proof**: [Show the code path with the weak/partial check]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [Step-by-step instructions or curl commands, e.g. two concurrent requests, to confirm.]
>   ```
>
> ### [NOT EXPLOITABLE] Scenario title
> - **Category**: [Attack category]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Business Rule**: [What the application is supposed to enforce]
> - **Protection**: [How it is enforced — server-side validation, DB constraint, atomic transaction, etc.]
>
> ### [NEEDS MANUAL REVIEW] Scenario title
> - **Category**: [Attack category]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [Why automated analysis couldn't determine the status]
> - **Suggestion**: [What to examine manually or test dynamically]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/businesslogic-batch-*.md` file and merge them into a single `sast/businesslogic-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/businesslogic-batch-1.md`, `sast/businesslogic-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/businesslogic-results.md` using this format:

```markdown
# Business Logic Analysis Results: [Project Name]

## Executive Summary
- Scenarios analyzed: [total across all batches]
- Exploitable: [N]
- Likely Exploitable: [N]
- Not Exploitable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 EXPLOITABLE first, then LIKELY EXPLOITABLE, then NEEDS MANUAL REVIEW, then NOT EXPLOITABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/businesslogic-results.md`, **delete all intermediate batch files** (`sast/businesslogic-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run **after** Phase 1 completes — it depends on the threat model output.
- Phase 3 must run **after** all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 scenarios per subagent**. If there are 1–3 scenarios total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned scenarios' text from the threats file, not the entire threats file. This keeps each subagent's context small and focused.
- Focus strictly on **business logic flaws** — do not flag injection bugs, auth bypass, or IDOR issues here.
- Threat modeling in Phase 1 should be **application-specific**: generic scenarios not grounded in the actual codebase are not useful.
- Server-side validation is the only valid protection. Client-side validation, frontend form constraints, and API documentation that says "must be positive" are not security controls.
- Race conditions on financial operations are high-severity even if they appear to require exact timing — automated tools (Turbo Intruder, concurrent curl) make them trivial to exploit.
- When in doubt, classify as "Needs Manual Review" rather than "Not Exploitable". False negatives in a security assessment are worse than false positives.
- Pay attention to ORM and database-level constraints (CHECK constraints, unique indexes, transactions with locking) — these can provide enforcement that is not visible in application code alone.
- Clean up intermediate files: delete `sast/businesslogic-threats.md` and all `sast/businesslogic-batch-*.md` files after the final `sast/businesslogic-results.md` is written.
