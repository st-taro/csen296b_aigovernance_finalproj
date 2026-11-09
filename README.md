# Refund Me Maybe: Enterprise Customer Support Agent

CSEN 296 capstone project. A browser-based, multi-agent customer support
application that handles refund requests end to end, built as a sandbox for
red-team and blue-team testing. All customers, emails, bank accounts and money
are synthetic.

- **Agents:** Orchestrator (planner, router, aggregator) plus Intake, Email,
  Records, Refunds and Reporting agents, talking over a signed MCP-style
  JSON-RPC bus.
- **RAG / vector DB:** ChromaDB collections for policies, case files and
  customer profiles. Mock cloud drive for case files.
- **Browser UI:** Customer portal, Admin console and Supervisor dashboard.
- **Independent controls:** a tool gateway outside the LLM enforces the $100 /
  $500 limits, case-scoped data access, contact-email-only sending, supervisor
  finality and the kill switch. Every action gets a decision ID in a
  hash-chained audit log.
- **LLM:** pluggable. Runs offline with a deterministic mock model by default;
  switch to Claude, OpenAI, Ollama or LM Studio in `.env`.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000 and use a demo account (password = name + `123`,
supervisor is `super123`): `alice`, `bob`, `carol`, `dave`, `erin` (customers),
`admin`, `supervisor`.

See [run_instructions.md](run_instructions.md) for LLM setup and the red-team
workflow, [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for how to use the app, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and control
inventory.

## Repository layout

```
app/
  main.py            FastAPI server, REST API, starter endpoints (/tasks, /logs, /tests/rt-01)
  orchestrator.py    planner, router, aggregator, memory, refund workflow
  agents/            intake, email_agent, records, refunds, reporting
  gateway.py         tool gateway: capability, kill switch, limits, scoping
  bus.py             signed MCP-style JSON-RPC inter-agent bus
  policy.py          policy parsing + deterministic policy engine
  llm.py             mock / anthropic / openai-compatible providers
  vectorstore.py     ChromaDB wrapper (RAG)
  drive.py           mock cloud drive
  guardrails.py      injection detection, redaction, output sanitising
  audit.py           hash-chained audit log
  db.py              SQLite schema + synthetic seed data
  static/            browser UI
data/seed/policies/  default refund policy (Markdown)
docs/                user guide, architecture
redteam/tests/       red-team starter suite (rt_suite.py)
tests/               pytest functional + security tests
threat_model/        MAESTRO mapping (team deliverable)
report/, presentation/
```

## Tests

```bash
python -m pytest -q                                     # 13 functional + security tests
python redteam/tests/rt_suite.py --reset                # against a running server
```
