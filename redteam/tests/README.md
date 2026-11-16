# Red-team starter suite

`rt_suite.py` attacks a running instance over HTTP and saves evidence to
`redteam/results/<timestamp>/` (one JSON file per test plus `summary.json`).

```bash
uvicorn app.main:app --port 8000              # terminal 1 (guardrails on)
python redteam/tests/rt_suite.py --reset      # terminal 2
```

For the benchmarking comparison, run a second server with guardrails off and
point the suite at it:

```bash
GUARDRAILS=off DATA_DIR=data/runtime-off uvicorn app.main:app --port 8001
python redteam/tests/rt_suite.py --base-url http://localhost:8001 --reset
```

(On Windows PowerShell: `$env:GUARDRAILS="off"; $env:DATA_DIR="data/runtime-off"; uvicorn app.main:app --port 8001`.)

Each result records the Appendix F assurance dimensions: whether the agent
**attempted** an out-of-bounds action, which **control** allowed or denied it,
and whether the operation **executed**. Add your own tests to the `TESTS` list.

Results from the build (mock LLM, naive mode):

| | Guardrails on | Guardrails off |
|---|---|---|
| Defended | 14 / 14 | 8 / 14 |
| Exploited | none | RT-02, RT-04, RT-06, RT-07, RT-08, RT-10 |

RT-03, RT-05 and RT-12 hold even with guardrails off because the tools they
ask for (bulk export, permission change) do not exist: that is an
architectural control, not a guardrail.
