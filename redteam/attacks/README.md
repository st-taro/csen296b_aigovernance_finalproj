# Live red-team attack scripts

Implements the attacks in `Red_Team_Attacks.pdf` against a running instance, guardrails ON, ideally with a
live LLM. Sandbox only (synthetic data, no real money). The scripts observe and record; they never change `app/`.

```bash
# set LLM_PROVIDER (+ key) in .env, then:
.venv/bin/uvicorn app.main:app --port 8000
.venv/bin/python redteam/attacks/run_all.py --section 5 --reset
.venv/bin/python redteam/attacks/run_all.py --only 2.1,2.2 --repeat 3
.venv/bin/python redteam/attacks/run_all.py --include-disruptive --reset      # also 2.4, 8.2, 8.3
.venv/bin/python redteam/attacks/run_all.py --allow-mock --section 5          # dry run on the mock model
```

Output: `redteam/results/live-<timestamp>/` with one JSON per attack (request/response evidence, audit rows,
raw model calls), `summary.json`, and `report.md` (table, "gaps to look at", roll-up by PDF section 9 area).

| Section | File | Status |
|---|---|---|
| 1 Prompt injection | `s1_injection.py` | not written yet |
| 2 Money and limits | `s2_money.py` | 2.4 needs `--include-disruptive` (starts a 4-worker server on :8011) |
| 3 Agent bus | `s3_bus.py` | not written yet |
| 4 Policy poisoning | `s4_policy.py` | PDF rows 3-6 are blank |
| 5 Disclosure | `s5_disclosure.py` | |
| 6 Email / output | `s6_email_output.py` | |
| 7 Memory / RAG | `s7_memory_rag.py` | PDF rows 5-6 are blank |
| 8 Kill switch | `s8_killswitch.py` | 8.2 and 8.3 need `--include-disruptive`; `RT_SPAM_N` sets 8.3 volume |

Outcomes: `HELD`, `FILTER_MISSED_BUT_HELD`, `EXPLOITED`, `LEAK`, `DEGRADED`, `INFO`, `SKIPPED`, `ERROR`.
Behavioural attacks (7.x, 8.1) often end as `INFO`; read the evidence file, not just the verdict.
Live runs cost API tokens (2.3 sends 20 parallel cases; 8.3 sends volume on purpose).
Mock-model results only show the harness works, not how a real model behaves.
