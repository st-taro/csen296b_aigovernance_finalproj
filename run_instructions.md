# Run Instructions (local, sandbox)

## Prerequisites
- Python 3.10 to 3.13
- pip

## Install

macOS / Linux:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If `chromadb` fails to install, the app still runs: it falls back to a small
built-in vector store and says so at startup (the UI header shows which one is
in use).

## Configure the LLM (optional)

Copy `.env.example` to `.env`. With no `.env` the app uses the offline **mock**
model, which needs no key and is deterministic, so demos and tests are
repeatable. The mock is "naive" by default: it follows instructions hidden in
customer text, the way a hijacked model would, so you can show the independent
controls holding.

| Provider | `.env` settings |
|---|---|
| Mock (default) | `LLM_PROVIDER=mock` |
| Claude | `LLM_PROVIDER=anthropic`, `ANTHROPIC_API_KEY=...`, optional `LLM_MODEL` (default `claude-opus-5-5`) |
| OpenAI | `LLM_PROVIDER=openai`, `LLM_API_KEY=...`, `LLM_MODEL=gpt-4o-mini` |
| Ollama | `LLM_PROVIDER=openai`, `LLM_BASE_URL=http://localhost:11434/v1`, `LLM_MODEL=llama3.1:8b` |
| LM Studio | `LLM_PROVIDER=openai`, `LLM_BASE_URL=http://localhost:1234/v1`, `LLM_MODEL=<id>` |

If a real model call fails (no key, network, bad JSON), the app falls back to
safe deterministic behaviour and records the error under Supervisor ->
Observability -> Recent LLM calls.

## Start the server
```bash
uvicorn app.main:app --reload --port 8000
```
Open http://localhost:8000.

## Demo accounts (synthetic)
| User | Password | Role |
|---|---|---|
| alice, bob, carol, dave, erin | `<name>123` (e.g. `alice123`) | Customer |
| admin | `admin123` | Admin |
| supervisor | `super123` | Supervisor |

## Endpoints
The browser UI uses the `/api/*` REST endpoints (see `app/main.py`). The
starter repo endpoints still work:
- `GET /health`
- `POST /tasks` -> free-text task through the orchestrator (no customer data access)
- `GET /logs` -> structured JSON event log (`logs/events.jsonl`)
- `POST /tests/rt-01` -> starter hallucination test
- `POST /bus/deliver` -> network-facing inter-agent endpoint (signed JSON-RPC), for ASI07 testing

## Red-team workflow
```bash
python redteam/tests/rt_suite.py --reset            # guardrails on, evidence in redteam/results/<ts>/
```
Compare against a monitor-only instance:
```bash
GUARDRAILS=off DATA_DIR=data/runtime-off uvicorn app.main:app --port 8001
python redteam/tests/rt_suite.py --base-url http://localhost:8001 --reset
```
Or switch off single controls, e.g. `GUARDRAIL_DISABLE=email_recipient,case_scope`.
Never run with guardrails off outside the sandbox.

Reset all synthetic data between runs from Admin -> Sandbox, or with
`--reset` on the suite.

## Starter demo script
`python run_demo.py --base-url http://localhost:8000` still works and saves
evidence to `redteam/results/collected_evidence_<ts>.json`.

## Tests
```bash
python -m pytest -q
```
