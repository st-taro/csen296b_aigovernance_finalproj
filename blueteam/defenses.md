# Blue-Team Defences: Refund Me Maybe

Defences built against the red-team findings in
[../redteam/plan.md](../redteam/plan.md) and the threat register in
[../threat_model/threat_model.md](../threat_model/threat_model.md). Each
defence keeps the red-team ID it answers (`BT 4.6` answers `RT 4.6`).

## How the defences are built

- **Every defence is a named control.** A control blocks while it is on.
  With `GUARDRAILS=off`, or the control named in `GUARDRAIL_DISABLE`, the old
  behaviour comes back and the audit log records a `would_block` row. That
  gives the before/after (config B / config C) evidence and lets the team run
  the red-team scripts against the undefended system.
- **Each defence has regression tests** in
  [../tests/test_blue_team.py](../tests/test_blue_team.py), named after the
  red-team ID. They run the attack in-process with the naive (hijackable) mock
  model and assert the control holds. Most also switch the control off and
  assert the old behaviour plus a `would_block` row. Each test was checked to
  **fail on the code before the fix**.
- **The fixes sit outside the LLM** (gateway, API boundary, database), so they
  hold whatever the model does.

Run: `python -m pytest -q` (all tests) or `python -m pytest -q tests/test_blue_team.py`.

## Status

`Done` = built and tested · `Planned` = not built yet.

### Phase 1: confirmed leaks

| BT | Threat | Control | What changed | Code | Status |
|---|---|---|---|---|---|
| 4.2, 4.6 | T-6, T-7 policy poisoning (`nan` limit disables the single-limit check; `-1`, `0`, empty reasons, 365-day window accepted) | `policy_validation` | Rules must be plain ASCII amounts / day counts, finite, > 0, window 1-`MAX_PURCHASE_WINDOW_DAYS` (90), known non-empty reasons. Read only from the `policy-rules` block (prose can't set rules, also covers part of RT 4.3). Invalid upload → HTTP 400 + `blocked` audit row, nothing saved. Gateway limits fail closed (0) on a corrupt stored value | `policy.py` `parse_rules`, `gateway.py` `_effective_limit`, `main.py` `upload_policy` | Done |
| 3.1d | S3 a signed external bus message reads all customers' mail, refunds, cases and profiles, or files spoofed mail | `case_scope` | External messages may only call `search_policies` and `weekly_total`. Inside the tools, an empty scope returns nothing (was: everything) in `list_cases`, `search_cases`, `search_profiles`, `list_emails`, `refund_report` (admin console reports unchanged). `receive_email` / `organize_email` check the sender or owner | `bus.py`, `gateway.py` `no_customer_access`, `agents/*` | Done |
| 5.2 | I2 case-ID enumeration through chat | `case_scope` | "Not yours" and "not found" return the same `case X not found`. The audit row keeps the real reason (checks may return an audit-only detail) | `gateway.py` `check_case_scope`, `_split` | Done |
| 5.3 | I3 unauthenticated recon | `recon_auth` | `/health` → `{status: ok}`. `/api/system` → 401 without a session; customers get only LLM name and whether authority is revoked; staff get the full view. UI header updated | `main.py`, `static/app.js` | Done |
| 2.7, 2.1 | T-5 NaN/Infinity amounts (500 on submit; stored Infinity breaks every page listing the case) | `input_validation` | `POST /api/cases` rejects non-finite, ≤ 0 and > `MAX_REQUEST_AMOUNT` amounts with 422 + audit row before storing anything. `submit_case` re-checks finiteness for the chat and bus paths | `main.py` `submit_case`, `agents/intake.py` | Done |
| 4.5 | T-6 one admin activates any policy, including rolling back to a looser one | `two_person_policy` | Upload and activate create a pending request (activate → 202). A supervisor approves or rejects it; the requester can never approve their own; one decision per request. Re-activating the active policy is a no-op. UI: admin request list, supervisor **Policy approvals** tab | `policy.py` `request_activation` / `decide_request`, `main.py`, `db.py` `policy_requests`, `static/app.js` | Done |
| R1 (8.4) | Admin erases the audit trail with Reset sandbox | `audit_protect` | Reset re-seeds every table except `audit_log` and records itself in the chain. Lockouts and sessions are still cleared | `db.py` `seed(keep=)`, `main.py` `reset_sandbox` | Done |

### Phase 2: correctness under attack (planned)

| BT | Threat | Planned defence |
|---|---|---|
| 1.3 | T-2 injection through `order_id` | `order_id` format `^ORD-\d{4}$` and length cap at the API (`input_validation`) |
| 2.3, 2.4 | T-3 weekly cap / one-refund race across workers; the app also crashes when 4 workers seed an empty DB at once | Unique index on `refunds(order_id)`; weekly-cap check + insert in one `BEGIN IMMEDIATE` transaction; idempotent, locked seed |
| 3.1b | S2 replay cache is per process | Replay cache in SQLite with a unique message ID |
| T-10 | Supervisor double submit | Atomic `UPDATE … WHERE supervisor_locked=0` |
| 7.5, 4.3 | T-8, T-9 unfenced chat history and policy chunks | `wrap_untrusted` around history and retrieved policy text |
| 6.1, 6.5 | I7 model-supplied `to`; phishing links | Always the case contact; URL allow-list in email bodies |
| 8.2 | S4 supervisor lockout blocks the kill switch | Second supervisor account; per-source lockout; break-glass revoke script |

### Phase 3: hardening (planned)

| BT | Planned defence |
|---|---|
| 6.6, 8.3 | Per-user rate limits in SQLite, HTTP 429 |
| 7.4 | Reject or flag low-diversity (keyword-stuffed) chunks when indexing a policy |
| 1.2 | Normalise text (NFKC, zero-width removal, look-alikes, base64) before the injection regex |
| 4.4 | Upload hardening: magic-byte type check, page / unzip-size / parse-time limits |
| 5.4 | Mask case PII for admins |
| 5.5 | Redact the LLM call log and stored bus messages |
| 8.1 | Kill-switch check at the start of each case run, before LLM calls |
| 7.6 | Supervisor must give a reason to approve; warning when the engine said deny |
| R2 | Anchor the audit-chain head outside the database |
| 3.1d | Per-agent bus keys instead of one master key; `/bus/deliver` off by default |

## Effect on the red-team scripts

The scripts in `redteam/` are unchanged. With the Phase 1 defences on:

- `redteam/attacks/harness.py` preflight and `redteam/tests/rt_suite.py` read
  `/api/system` without logging in, so they now stop with HTTP 401. Run them with
  `GUARDRAIL_DISABLE=recon_auth`, or sign in as supervisor for that call.
- RT 4.x / RT-11 policy uploads now get 400 (invalid rules) or stay pending
  (two-person rule). Their "restore the original policy" step still works,
  because re-activating the active policy is a no-op.
- Reset sandbox still clears data, sessions and lockouts; only the audit log is kept.
