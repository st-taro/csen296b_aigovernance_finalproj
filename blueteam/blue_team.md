# Blue-Team Build Plan: Refund Me Maybe

The complete blue-team plan. It covers what is already built (Phase 1) and
what is still to build (Phases 2 and 3).

Each defence is named the same way as its commit: what it does, followed by
the red-team tests it answers, e.g. "Strict policy validation (RT 4.2, 4.6)".
RT numbers refer to [../redteam/plan.md](../redteam/plan.md). Threat IDs
(`T-3`, `S4`, `R1`, ...) refer to the threat register in
[../threat_model/threat_model.md](../threat_model/threat_model.md); `R1`, `R2`
and `T-10` appear in brackets where there is no red-team test of their own.

**Branch:** `blue-team`. **Tests:** [../tests/test_blue_team.py](../tests/test_blue_team.py).
Run `python -m pytest -q` for all tests, or `python -m pytest -q tests/test_blue_team.py`.

## Status overview

`Done` = built, tested and committed · `Planned` = not built yet.

| Phase | Defence | Threat | Control | Status |
|---|---|---|---|---|
| 1 | Strict policy validation (RT 4.2, 4.6) | T-6, T-7 | `policy_validation` | Done |
| 1 | Empty scope means no customer data (RT 3.1d) | S3 | `case_scope` | Done |
| 1 | Same answer for "not yours" and "not found" (RT 5.2) | I2 | `case_scope` | Done |
| 1 | No unauthenticated recon (RT 5.3) | I3 | `recon_auth` | Done |
| 1 | Reject non-finite and out-of-range amounts (RT 2.7, 2.1) | T-5 | `input_validation` | Done |
| 1 | Two-person rule for policy activation (RT 4.5) | T-6 | `two_person_policy` | Done |
| 1 | Reset sandbox keeps the audit log (R1, RT 8.4) | R1 | `audit_protect` | Done |
| 2 | Validate `order_id`, `reason` and description at the boundary (RT 1.3) | T-2 | `input_validation` | Planned |
| 2 | Refunds stay atomic across worker processes (RT 2.3, 2.4) | T-3 | `atomic_refunds` | Planned |
| 2 | Shared replay cache and message-ID checks (RT 3.1b, 3.1c) | S2 | `bus_signature` | Planned |
| 2 | Atomic supervisor decision (T-10) | T-10 | `supervisor_lock` | Planned |
| 2 | Fence chat history and policy text in prompts (RT 7.5, 4.3) | T-8, T-9 | `input_filter` | Planned |
| 2 | Email recipient and links (RT 6.1, 6.5) | I7 | `email_recipient`, `output_filter` | Planned |
| 2 | Keep the kill switch reachable (RT 8.2) | S4 | `auth_resilience` | Planned |
| 3 | Per-user rate limits (RT 6.6, 8.3) | D1 | `rate_limit` | Planned |
| 3 | Keyword-stuffed policy chunks (RT 7.4) | T-8 | `policy_validation` | Planned |
| 3 | Normalise text before the injection filter (RT 1.2) | T-1 | `input_filter` | Planned |
| 3 | Hardened policy uploads (RT 4.4) | D4 | `policy_validation` | Planned |
| 3 | Admins don't see case PII (RT 5.4) | I4 | `pii_minimisation` | Planned |
| 3 | No raw bank numbers in logs (RT 5.5) | I5 | `output_filter` | Planned |
| 3 | Stop earlier after revocation (RT 8.1) | K1 | `kill_switch` | Planned |
| 3 | Supervisor approval needs a reason (RT 7.6) | S5, K3 | `supervisor_review` | Planned |
| 3 | Anchor the audit chain outside the database (R2, RT 8.4) | R2 | `audit_protect` | Planned |
| 3 | Per-agent bus keys, external endpoint off by default (RT 3.1d) | S3 | `bus_signature` | Planned |

## Rules every defence follows

1. **Named control.** Each defence sits behind a control name, so
   `GUARDRAILS=off` or `GUARDRAIL_DISABLE=<name>` brings back the old
   behaviour and logs `would_block`. New names are listed per item and must be
   added to `app/config.py`, `.env.example` and the control inventory in
   `docs/ARCHITECTURE.md`.
2. **Test first.** Add tests to `tests/test_blue_team.py` named after the RT ID.
   Check that they fail on the code before the fix and pass after it. Where it
   matters, add a monitor-mode test (control off → old behaviour + `would_block`).
3. **Outside the LLM.** Prefer the database, gateway and API boundary to prompt
   changes. Prompt changes (fencing, filters) are extra layers only.
4. **Fail closed.** When a check cannot decide, it blocks, escalates or puts the
   case on hold. It never approves.
5. **After each item:** run `python -m pytest -q`, update the status overview
   above and the threat register, and commit with one commit per item (no
   trailers in commit messages).

---

## Phase 1: confirmed leaks (built)

Every Phase 1 test was checked to fail on the code before its fix. Most also
have a monitor-mode test showing the old behaviour plus a `would_block` row.
Shared helper: `app/controls.py` `violation()` blocks or logs `would_block`
for controls that live outside the gateway.

### Strict policy validation (RT 4.2, 4.6) · Done

- **Threat:** T-6, T-7.
- **Control:** new `policy_validation`.
- **Problem:** the policy parser accepted `nan`, negative and zero limits, an
  empty `eligible_reasons` and a 365-day window. A `nan` limit passed the
  clamp (`nan > 100` is false), and the gateway then computed `min(nan, 100)`,
  which is `nan`. As a result `check_single_limit` never fired, every case
  escalated and `/api/system` returned 500. The upload returned 500, but the
  policy was saved and active anyway.
- **Built:**
  - Rules must be plain ASCII dollar amounts or day counts: finite and > 0;
    window between 1 and `MAX_PURCHASE_WINDOW_DAYS` (90); a non-empty list of
    known reasons, excluding `other`.
  - Rules are read only from the `policy-rules` block, so prose lines cannot
    set them (this also covers part of RT 4.3).
  - An invalid upload gets HTTP 400 with a `blocked` audit row, and nothing is
    saved.
  - The gateway fails closed: a corrupt stored limit counts as 0, so the
    approval is blocked (`gateway._effective_limit`).
- **Code:** `app/policy.py` (`parse_rules`, `strict_errors`, `PolicyRejected`),
  `app/gateway.py`, `app/main.py` `upload_policy`.
- **Tests:** 13 invalid variants (`nan`, `inf`, `1e309`, negative, zero,
  `$1,000`, Unicode digits, 365/0-day window, empty/unknown/`other` reasons) → 400,
  nothing saved, active policy unchanged, `/api/system` still 200. A valid
  policy is still clamped and accepted; prose rules are ignored; the gateway
  fails closed; monitor mode restores the lenient parser.
- **Red-team effect:** RT 4.2 variants and RT-11 now get 400 → HELD.

### Empty scope means no customer data (RT 3.1d) · Done

- **Threat:** S3.
- **Control:** `case_scope` (extended).
- **Problem:** a correctly signed external `/bus/deliver` message runs with
  scope `""`. Several tools filtered only when the scope was truthy, so `""`
  meant "everything": `list_emails`, `refund_report`, `list_cases`,
  `search_cases` and `search_profiles` returned every customer's data.
  `receive_email` and `organize_email` had no scope check, so spoofed inbound
  mail could be filed.
- **Built:**
  - External messages may only call `search_policies` and `weekly_total`
    (`bus.EXTERNAL_TOOLS`).
  - Inside the tools, an empty scope returns nothing (`gateway.no_customer_access`).
    The admin console's refund report is unchanged.
  - `receive_email` checks the sender, and `organize_email` the mail's owner,
    against the run's customer.
- **Code:** `app/bus.py`, `app/gateway.py`, `app/agents/records.py`,
  `app/agents/email_agent.py`, `app/agents/reporting.py`.
- **Tests:** 8 signed external calls (mail, reports, cases, profiles, inbound
  mail, folder moves) → blocked, nothing filed. Policy search still works.
  Empty-scope tools return nothing, admin reports still work, a customer
  cannot file mail as someone else, and monitor mode shows the leak.

### Same answer for "not yours" and "not found" (RT 5.2) · Done

- **Threat:** I2.
- **Control:** `case_scope`.
- **Problem:** chat said "belongs to another customer" for an existing case and
  "not found" for a missing one, so it revealed which case IDs exist. REST
  already returned 404 for both.
- **Built:**
  - Both cases now return `case X not found`.
  - Gateway checks may return a third, audit-only element, so the audit row
    still records the real reason (`gateway._split`).
- **Code:** `app/gateway.py` `check_case_scope`.
- **Tests:** chat errors for CASE-0001 (carol's) and CASE-9999 are identical
  once the IDs are normalised; the audit row says "another customer"; REST is
  404 for both.

### No unauthenticated recon (RT 5.3) · Done

- **Threat:** I3.
- **Control:** new `recon_auth`.
- **Problem:** `/health` and `/api/system` returned guardrail state, limits,
  the active policy, every agent and tool, and the kill-switch state to
  anyone, with no login.
- **Built:**
  - `/health` returns only `{status: ok}`.
  - `/api/system` without a session → 401 with an audit row.
  - Customers get only the LLM name and whether authority is revoked; admins
    and supervisors get the full view.
  - The UI header no longer calls `/api/system` before sign-in.
- **Code:** `app/main.py`, `app/static/app.js`.
- **Tests:** anonymous → 401 and a minimal `/health`; customer view has no
  recon fields; staff views are full; monitor mode restores the old output.
- **Red-team effect:** the red-team harness and `rt_suite.py` read
  `/api/system` without logging in, so they stop at preflight with this
  control on. Run them with `GUARDRAIL_DISABLE=recon_auth`, or sign in as
  supervisor for that call.

### Reject non-finite and out-of-range amounts (RT 2.7, 2.1) · Done

- **Threat:** T-5.
- **Control:** new `input_validation`.
- **Problem:** JSON `NaN` and `Infinity` parse as floats and pass Pydantic. NaN
  crashed the insert (HTTP 500). Infinity was stored and then broke every page
  that lists the case, because JSON cannot encode it.
- **Built:**
  - `POST /api/cases` rejects non-finite, ≤ 0 and > `MAX_REQUEST_AMOUNT`
    (100,000) amounts with 422 and an audit row, before storing anything.
  - The `submit_case` tool repeats the finite check for the chat and bus
    paths, where a model can emit `1e309`.
- **Code:** `app/main.py` `submit_case`, `app/agents/intake.py`.
- **Tests:** `NaN`, `±Infinity`, `1e309`, `-10`, `0`, `1e9` → 422, no case,
  supervisor pages still 200. The planner path rejects Infinity. In monitor
  mode a negative amount reaches the engine and is denied.
- **Behaviour change:** zero and negative amounts now get 422 at the API
  instead of a "denied" case.

### Two-person rule for policy activation (RT 4.5) · Done

- **Threat:** T-6.
- **Control:** new `two_person_policy`.
- **Problem:** one admin could upload a policy and have it live at once, or
  re-activate any older, looser version.
- **Built:**
  - An upload is stored inactive with a pending activation request.
  - `POST /api/policies/{id}/activate`, including a rollback, also only
    creates a request (HTTP 202).
  - A supervisor approves or rejects it (`POST /api/policies/requests/{id}/decision`).
    The requester can never approve their own request, and each request is
    decided once.
  - Re-activating the policy that is already active is a no-op, so the
    red-team "restore" steps still work. Every step is audited.
  - UI: the admin Policies page lists requests (the button now reads "Request
    activation"); supervisors get a **Policy approvals** tab that shows the
    requested rules next to the active policy.
- **Code:** `app/policy.py` (`request_activation`, `decide_request`,
  `list_requests`), `app/main.py`, `app/db.py` (`policy_requests` table),
  `app/static/app.js`.
- **Tests:**
  - An upload waits; an admin can't approve; a supervisor approval activates
    it; a second decision gets 409.
  - A rollback needs approval, and a rejection leaves the stricter policy
    active.
  - Re-activating the active policy is a no-op; self-approval is refused;
    monitor mode activates at once.

### Reset sandbox keeps the audit log (R1, RT 8.4) · Done

- **Threat:** R1.
- **Control:** new `audit_protect`.
- **Problem:** Reset sandbox dropped every table, including `audit_log`, so an
  admin could erase the evidence trail.
- **Built:**
  - Reset re-seeds every table except `audit_log`, and records itself in the
    hash chain.
  - Sessions, login lockouts and all synthetic data are still reset (the
    red-team runner relies on this).
- **Code:** `app/db.py` `seed(keep=)`, `app/main.py` `reset_sandbox`.
- **Tests:** the first audit row and its hash survive a reset, the chain
  verifies, the data is re-seeded and lockouts are cleared. In monitor mode
  the reset wipes the log and writes a `would_block` row.

---

## Phase 2: correctness under attack

### Validate `order_id`, `reason` and description at the boundary (RT 1.3)

- **Threat:** T-2.
- **Control:** `input_validation` (exists).
- **Problem:** `order_id` has no format or length check. It is uppercased,
  stored, put unfenced into the Refunds and email prompts and the case
  vector document. A 20 KB `order_id` or one with newline-separated
  instructions is accepted.
- **Build:**
  - `POST /api/cases`: `order_id` must match `^ORD-\d{4}$` after strip/upper
    (max 20 chars); `reason` must be one of the known reasons; `description`
    max `MAX_INPUT_CHARS`. Otherwise 422 + `blocked` audit row, nothing stored.
  - Repeat the `order_id` check inside the `submit_case` tool, so the chat and
    bus paths are covered too (the planner can emit any string).
- **Tests:** newline + instructions in `order_id`, a 20 KB `order_id`, an
  unknown reason, a 4,001-char description → 422, no case, no vector doc.
  The SQL-injection payloads from RT 6.2 in `order_id` → 422, never 5xx.
- **Red-team effect:** RT 6.2 order_id probes now get 422 (still HELD).

### Refunds stay atomic across worker processes (RT 2.3, 2.4)

- **Threat:** T-3.
- **Control:** new `atomic_refunds`.
- **Problem:** `_CONSEQUENTIAL_LOCK` is a `threading.RLock`, so it only works
  inside one process. Under `uvicorn --workers 4`, two workers can both read
  "week-to-date $400" or "order not refunded" and both pay. Separately, the app
  cannot start fresh with 4 workers: they all seed an empty DB and crash on
  `UNIQUE constraint failed: users.username` (found by the RT 2.4 script).
- **Build:**
  - `db.immediate()` context manager: takes the process lock, runs
    `BEGIN IMMEDIATE` (SQLite's cross-process write lock) and defers commits
    until the block ends (rollback on exception). Set `PRAGMA busy_timeout`
    (e.g. 10 s) so other workers wait instead of failing.
  - The gateway runs the checks *and* the action of every consequential tool
    inside `db.immediate()`, so the weekly-cap read and the refund insert are
    one transaction.
  - `CREATE UNIQUE INDEX ux_refunds_order ON refunds(order_id)` as a last line
    of defence. With the control off, startup drops the index so config B can
    still show the race.
  - Seeding runs inside `db.immediate()`, re-checks "already seeded" inside the
    transaction and uses `INSERT OR IGNORE`.
- **Known limit:** the vector store is not multi-process safe (the JSON
  fallback overwrites one file; Chroma's persistent client is not designed for
  several writer processes). Money and audit live in SQLite, so the race
  fix does not depend on it. Record this as residual risk.
- **Tests:** a multiprocessing test where 4 processes share one `DATA_DIR` and
  each issues refunds for the same order and for orders that together exceed
  $500. Expect at most one refund per order and an autonomous total of $500 or
  less. Plus a test that 4 processes seeding an empty DB at once all succeed.
- **Red-team effect:** RT 2.4 (`--include-disruptive`) should now be HELD, and
  its single-process pre-seed workaround is no longer needed.

### Shared replay cache and message-ID checks (RT 3.1b, 3.1c)

- **Threat:** S2.
- **Control:** `bus_signature` (exists).
- **Problem:** the replay cache is an in-memory dict per process, so with
  several workers a message can be replayed to another worker. Message IDs
  of `null`, numbers or 10 KB strings are accepted as cache keys.
- **Build:**
  - Table `bus_seen(msg_id TEXT PRIMARY KEY, seen_at TEXT)`. `INSERT OR
    IGNORE`; zero rows inserted means replay. Purge rows older than
    2 × `BUS_MAX_AGE_SECONDS`.
  - Message `id` must be a string of 1-64 chars `[A-Za-z0-9_-]`; anything else
    is rejected before dispatch.
- **Tests:** the same signed message twice → second blocked as replay, also
  after clearing the in-process state (simulated restart / other worker);
  `null`, `-1`, a 10 KB string and a non-string id → blocked, no 5xx.

### Atomic supervisor decision (T-10)

- **Control:** `supervisor_lock` (exists).
- **Problem:** `supervisor_decision` checks `supervisor_locked`, then acts.
  Two quick submits (double click, two tabs) can both pass and send two
  decision emails.
- **Build:** claim the case first with
  `UPDATE cases SET supervisor_locked=2 WHERE id=? AND supervisor_locked=0`
  (2 = decision in progress). If no row changed → 409. On success set it to 1;
  on failure set it back to 0 so the supervisor can retry. Add a `db` helper
  that returns `rowcount`.
- **Tests:** two concurrent decisions on one case → exactly one 200 and one
  409, one decision email, at most one refund.

### Fence chat history and policy text in prompts (RT 7.5, 4.3)

- **Threat:** T-8, T-9.
- **Control:** `input_filter` (exists).
- **Problem:** only the current chat message is wrapped in `wrap_untrusted`.
  Earlier turns (including assistant answers that echo user text) and the
  retrieved policy chunks go into prompts unfenced.
- **Build:**
  - `orchestrator.plan`: wrap the history block as `conversation_history`.
  - `refunds.evaluate_case`: wrap policy excerpts as `policy_reference`, with a
    note that the excerpts are reference text and never instructions (the
    policy engine already decides, so this only protects the LLM
    recommendation).
  - Remove the dead `user:` memory-notes recall (never written), or fence it
    if the team wants to keep it.
- **Tests:** the mock model ignores prompts, so capture the prompt by
  monkeypatching `llm.complete_json`. Assert that history and policy text sit
  inside the fence and that `<`/`>` in them are neutralised. Then repeat RT 7.5
  (claim "I am a pre-approved VIP" in turn 1) and assert the turn-2 decision is
  unchanged.
- **Red-team effect:** affects real-model runs (config D) only.

### Email recipient and links (RT 6.1, 6.5)

- **Threat:** I7.
- **Controls:** `email_recipient` and `output_filter` (exist).
- **Problem:** the model's `to` is stored on the draft. The gateway blocks the
  send and the orchestrator re-sends to the contact, but the draft still holds
  the attacker's address. Model-written bodies can contain any link (phishing
  in the company's name).
- **Build:**
  - `draft_email` always sets `to` to the case contact email. If the model
    proposed a different `to`, write a `blocked` (`email_recipient`) audit row
    naming it, as evidence of the attempt.
  - `sanitize_output` replaces URLs whose host is not on
    `EMAIL_LINK_ALLOWLIST` (default: the support domain) with `[link removed]`.
- **Tests:** monkeypatch the model to return `to=attacker@evil.test` and a
  body with `http://evil.test/verify`. Assert the draft and sent mail go to the
  contact, the link is removed, and an audit row records the attempt.

### Keep the kill switch reachable (RT 8.2)

- **Threat:** S4.
- **Control:** new `auth_resilience`.
- **Problem:** 5 bad logins lock a username for 15 minutes, counted per
  username only, so anyone can lock out the single supervisor account and
  block the kill switch and all case decisions.
- **Build:**
  - Count failures per (username, client IP). An attacker from another
    address no longer locks out the real user.
  - Add a per-IP cap across all usernames (e.g. 20 failures in 15 min → 429)
    so the per-pair counter does not help password spraying.
  - Read the client IP from the socket. Trust `X-Forwarded-For` only when
    `TRUST_PROXY=true`.
  - Seed a second supervisor account (`supervisor2`), so one locked account
    does not stop oversight.
  - Break-glass CLI: `python -m app.breakglass revoke --reason "..."` writes
    the kill-switch state straight to the database, with an audit row
    (`actor=breakglass:<os user>`). It needs host access, so it bypasses the
    web login entirely.
- **Tests:** 5 bad logins from IP A, then the real login from IP B succeeds
  (monkeypatch the IP helper). The per-IP cap returns 429. The break-glass
  revoke holds the next case `on_hold` and leaves an audit row.
- **Red-team effect:** RT 8.2 attacks and logs in from the same machine, so it
  will still report DEGRADED for that one IP. Our test shows the cross-IP
  case, and `supervisor2` / break-glass keep the kill switch reachable.

---

## Phase 3: hardening

### Per-user rate limits (RT 6.6, 8.3)

- **Threat:** D1.
- **Control:** `rate_limit` (exists, extended).
- **Build:**
  - Table `rate_events(key, ts)`, shared across workers and cleared by Reset
    sandbox. Limits are configurable; suggested defaults:
    - case submissions: 8 per minute and 50 per day per customer;
    - chat: 10 messages per minute per user;
    - support emails: 10 per minute per customer.
  - Over the limit → HTTP 429 with `Retry-After` and an audit row.
  - Chat messages over `MAX_INPUT_CHARS` → 422 instead of silent truncation
    to 8,000.
- **Tests:** the 9th case in a minute → 429; an 8,001-char chat → 422; the
  counters reset with the sandbox.
- **Red-team effect:** RT 8.3 counts 429s, so it should report HELD. RT 2.3
  sends 6 parallel requests per customer, under the limit, so it still tests
  the race.

### Keyword-stuffed policy chunks (RT 7.4)

- **Threat:** T-8.
- **Control:** `policy_validation` (exists).
- **Build:** when a policy is indexed, skip chunks of 12 or more words whose
  unique-word ratio is below 0.4 (the same measure the RT 7.4 script uses) and
  list them in the upload warnings. If more than half the chunks are dropped,
  reject the upload. The two-person rule already means a stuffed document
  needs a supervisor's approval to go live.
- **Tests:** upload the RT 7.4 document; the stuffed chunk is not indexed, the
  real 30-day rule ranks first for "How many days do I have to request a
  refund?", and a normal policy loses no chunks.

### Normalise text before the injection filter (RT 1.2)

- **Threat:** T-1.
- **Control:** `input_filter` (exists).
- **Build:** before the regex runs:
  - NFKC-normalise the text;
  - remove zero-width and bidi characters;
  - map common look-alike letters (Cyrillic, Greek) to Latin;
  - collapse whitespace;
  - run a second pass with digit look-alikes mapped (`0→o`, `1→i`, `3→e`);
  - also scan decoded base64 runs of 16 or more characters.

  Add patterns for paraphrases ("set aside earlier guidance") and the ENI
  persona ("unrestricted … mode", "no refusals").
- **Tests:** every RT 1.2 variant is flagged; a set of normal damage
  descriptions is not (false-positive check). The filter stays an early
  warning; the policy engine still decides.

### Hardened policy uploads (RT 4.4)

- **Threat:** D4.
- **Control:** `policy_validation` (exists).
- **Build:**
  - Detect the file type from its first bytes, not the name: `%PDF-` for PDF;
    a zip with `word/document.xml` for DOCX; otherwise UTF-8 text. Reject a
    mismatch.
  - PDF: at most 50 pages; reject encrypted files.
  - DOCX: at most 1,000 zip entries, 20 MB unzipped and a compression ratio
    of 100.
  - Parse in a worker process with a 10 s timeout, and cap the extracted text
    at 200k chars.
- **Tests:** a zip-bomb DOCX, a `.pdf` that is really text, a malformed PDF,
  a 60-page PDF → 400, server stays up, parse time bounded.

### Admins don't see case PII (RT 5.4)

- **Threat:** I4.
- **Control:** new `pii_minimisation`.
- **Build:** for admins, `GET /api/cases` and `/api/cases/{id}`:
  - mask the contact email (`a***@customer.example`);
  - replace the description with `[visible to supervisors only]`;
  - drop the order details.

  Write an audit row for each admin case-detail read. Supervisors and
  customers are unchanged.
- **Tests:** admin responses contain no contact email or description; the
  supervisor's view is unchanged.

### No raw bank numbers in logs (RT 5.5)

- **Threat:** I5.
- **Control:** `output_filter` (exists).
- **Build:**
  - Redact the LLM call log (`raw` and `output`), and stored bus messages and
    responses, before they are saved.
  - Extend `redact` to formatted numbers (`000-111-222-333`,
    `000 111 222 333`).
- **Tests:** after a chat, a profile view and a refund, grep `/api/llm-calls`,
  `/api/bus`, `/api/audit`, `/logs`, the reports and the drive for every
  seeded account number, plain and formatted. None should appear.

### Stop earlier after revocation (RT 8.1)

- **Threat:** K1.
- **Control:** `kill_switch` (exists).
- **Build:** `process_case` checks agent authority before its first step. When
  revoked, the case goes straight to `on_hold` with no LLM calls, drafts or
  storage. `evaluate_case` checks again before calling the model.
- **Tests:** revoke, submit a case → `on_hold`, no new entries in the LLM call
  log, no draft email; restore + rerun → normal processing.

### Supervisor approval needs a reason (RT 7.6)

- **Threat:** S5, K3.
- **Control:** new `supervisor_review`.
- **Build:**
  - Approving needs a note of at least 10 characters.
  - If the policy engine said **deny**, approval also needs an explicit
    `override: true`.
  - The audit row stores the engine result next to the decision.
  - UI: a confirm dialog shows the engine result before an override.
- **Tests:** approval without a note → 400; overriding a deny without
  `override` → 400; with both → allowed and audited with the engine result.

### Anchor the audit chain outside the database (R2, RT 8.4)

- **Threat:** R2.
- **Control:** `audit_protect` (exists).
- **Build:**
  - Every 50 rows (and on each verify), append `{seq, hash, ts}` to
    `logs/audit_anchor.jsonl`, signed with HMAC under `AUDIT_ANCHOR_KEY`
    from the environment.
  - `verify_chain` also checks that each anchored `seq` still has the anchored
    hash. That catches a recomputed chain, unless the attacker also holds the
    anchor key.
- **Residual risk:** a host insider with the key can still rewrite both. A
  real deployment would send anchors to an external write-once store.
- **Tests:** edit a row and recompute the whole chain in SQLite → `verify`
  still reports the break, at the first anchored row.

### Per-agent bus keys, external endpoint off by default (RT 3.1d)

- **Threat:** S3.
- **Control:** `bus_signature` (exists).
- **Build:**
  - Each sender gets its own random key: `BUS_KEY_<AGENT>` from the
    environment, or a keys file created at first start in `DATA_DIR` with
    restricted permissions. A leaked key now only impersonates one agent.
  - `POST /bus/deliver` returns 404 unless `BUS_EXTERNAL_ENABLED=true`.
- **Tests:** a message signed with the orchestrator key but labelled as
  `refunds` fails; `/bus/deliver` is 404 by default.
- **Red-team effect:** config F and RT 3.x need `BUS_EXTERNAL_ENABLED=true`
  plus the relevant `BUS_KEY_*`.

---

## When all phases are done

- **Evidence:** run the full red-team set in config A (all on) and config B
  (`GUARDRAILS=off`). Save both summaries, plus `pytest` output, for the
  report's before/after table.
- **Threat model:** update the threat register statuses and fill in
  `threat_model/MAESTRO_mapping.md`, which is still an empty template.
- **Residual risks:** list them in the report:
  - prompt injection is contained, not removed;
  - a compromised supervisor can still approve anything;
  - vector-store multi-process safety;
  - calendar vs rolling weekly window;
  - audit anchoring held only on the host.
