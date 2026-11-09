"""Append-only, hash-chained audit log.

Every tool call the gateway sees (allowed, blocked, or would_block in monitor
mode), every supervisor action and every kill-switch change is written here
with a decision ID. Each row stores the SHA-256 of the previous row, so editing
or deleting any row breaks the chain and /api/audit/verify reports it
(MAESTRO layer 5: log tampering). No API edits or deletes audit rows.

Rows are also mirrored to logs/events.jsonl for the starter repo's /logs view.
"""
import hashlib
import json
import uuid

from app import config, db
from app.guardrails import redact

GENESIS = "0" * 64


def new_decision_id() -> str:
    return "D-" + uuid.uuid4().hex[:12]


def _row_hash(prev_hash: str, row: dict) -> str:
    material = json.dumps({k: row[k] for k in sorted(row)}, sort_keys=True) + prev_hash
    return hashlib.sha256(material.encode()).hexdigest()


def record(actor: str, outcome: str, *, agent: str = None, tool: str = None,
           case_id: str = None, args: dict = None, control: str = None,
           reason: str = None, run_id: str = None, decision_id: str = None) -> str:
    """Write one audit row and return its decision ID.

    outcome: allowed | blocked | would_block | error | info
    """
    decision_id = decision_id or new_decision_id()
    with db._lock:
        last = db.q1("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        prev = last["hash"] if last else GENESIS
        row = {
            "decision_id": decision_id,
            "ts": db.now_iso(),
            "run_id": run_id,
            "actor": actor,
            "agent": agent,
            "tool": tool,
            "case_id": case_id,
            "args": redact(json.dumps(args or {}, default=str)),
            "outcome": outcome,
            "control": control,
            "reason": redact(reason or ""),
        }
        h = _row_hash(prev, row)
        db.x("INSERT INTO audit_log(decision_id,ts,run_id,actor,agent,tool,case_id,args,outcome,"
             "control,reason,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (row["decision_id"], row["ts"], row["run_id"], row["actor"], row["agent"], row["tool"],
              row["case_id"], row["args"], row["outcome"], row["control"], row["reason"], prev, h))
    try:
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(config.LOG_DIR / "events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({**row, "timestamp": row["ts"], "action": tool or outcome}) + "\n")
    except OSError:
        pass
    return decision_id


def verify_chain() -> dict:
    rows = db.q("SELECT * FROM audit_log ORDER BY seq")
    prev = GENESIS
    for r in rows:
        body = {k: r[k] for k in ("decision_id", "ts", "run_id", "actor", "agent", "tool",
                                  "case_id", "args", "outcome", "control", "reason")}
        if r["prev_hash"] != prev or _row_hash(prev, body) != r["hash"]:
            return {"ok": False, "rows": len(rows), "broken_at_seq": r["seq"]}
        prev = r["hash"]
    return {"ok": True, "rows": len(rows), "head": prev}


def for_case(case_id: str) -> list:
    return db.q("SELECT seq,decision_id,ts,run_id,actor,agent,tool,outcome,control,reason,args "
                "FROM audit_log WHERE case_id=? ORDER BY seq", (case_id,))


def recent(limit: int = 200, outcome: str = None) -> list:
    if outcome:
        return db.q("SELECT * FROM audit_log WHERE outcome=? ORDER BY seq DESC LIMIT ?", (outcome, limit))
    return db.q("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,))
