"""Inter-agent message bus, shaped like MCP (JSON-RPC 2.0 `tools/call`).

The orchestrator and agents never call each other's Python functions
directly. They send a signed JSON-RPC message through this bus:

    {"jsonrpc": "2.0", "id": "...", "method": "tools/call",
     "params": {"name": "<tool>", "arguments": {...}},
     "meta": {"from": "orchestrator", "to": "records", "run_id": "...",
              "case_id": "...", "ts": "...", "sig": "<hmac-sha256>"}}

Controls (ASI07 insecure inter-agent communication):
  - every message is HMAC-signed; the receiver verifies before acting
    (control name: bus_signature)
  - the receiving agent acts under ITS OWN identity, so the gateway checks the
    receiver's capabilities, never a claimed sender identity
  - every message and response is logged to the bus_messages table

`deliver_external()` is the network-facing entry point (POST /bus/deliver),
simulating an exposed agent endpoint the red team can attack with forged or
replayed messages.
"""
import hashlib
import hmac
import json
import uuid

from app import audit, config, db, gateway

AGENTS = {}
_seen_ids = set()


def register_agent(agent):
    AGENTS[agent.name] = agent


def _canonical(msg: dict) -> bytes:
    m = json.loads(json.dumps(msg))
    m.get("meta", {}).pop("sig", None)
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode()


def sign(msg: dict) -> str:
    return hmac.new(config.BUS_SECRET.encode(), _canonical(msg), hashlib.sha256).hexdigest()


def verify(msg: dict) -> bool:
    sig = (msg.get("meta") or {}).get("sig", "")
    return hmac.compare_digest(sign(msg), sig or "")


def build(sender, recipient, tool, args, ctx: gateway.Ctx, method="tools/call") -> dict:
    msg = {"jsonrpc": "2.0", "id": uuid.uuid4().hex[:12], "method": method,
           "params": {"name": tool, "arguments": args or {}},
           "meta": {"from": sender, "to": recipient, "run_id": ctx.run_id,
                    "case_id": ctx.case_id, "ts": db.now_iso()}}
    msg["meta"]["sig"] = sign(msg)
    return msg


def send(sender, recipient, tool, args, ctx: gateway.Ctx):
    """Send a tools/call to an agent and return the tool result. Raises
    gateway.ToolBlocked if a control blocks it."""
    msg = build(sender, recipient, tool, args, ctx)
    return _dispatch(msg, ctx)


def list_tools(recipient: str) -> list:
    return gateway.tools_for(recipient)


def _dispatch(msg: dict, ctx: gateway.Ctx):
    meta = msg.get("meta") or {}
    recipient = meta.get("to")
    valid = verify(msg)
    replay = msg.get("id") in _seen_ids
    _seen_ids.add(msg.get("id"))
    row_id = db.x("INSERT INTO bus_messages(ts,run_id,sender,recipient,message,signature_valid) VALUES (?,?,?,?,?,?)",
                  (db.now_iso(), ctx.run_id, str(meta.get("from")), str(recipient),
                   json.dumps(msg), int(valid and not replay)))
    problem = None
    if not valid:
        problem = "invalid or missing message signature"
    elif replay:
        problem = "replayed message id"
    if problem:
        if config.control_enabled("bus_signature"):
            did = audit.record(ctx.actor, "blocked", agent=str(recipient), tool=msg.get("params", {}).get("name"),
                               case_id=meta.get("case_id"), args=msg.get("params", {}).get("arguments"),
                               control="bus_signature", reason=problem, run_id=ctx.run_id)
            ctx.events.append({"agent": recipient, "tool": msg.get("params", {}).get("name"),
                               "outcome": "blocked", "control": "bus_signature", "reason": problem,
                               "decision_id": did})
            _respond(row_id, {"error": problem})
            raise gateway.ToolBlocked("bus_signature", problem, did)
        audit.record(ctx.actor, "would_block", agent=str(recipient), tool=msg.get("params", {}).get("name"),
                     case_id=meta.get("case_id"), control="bus_signature",
                     reason=f"[guardrail disabled] {problem}", run_id=ctx.run_id)
    agent = AGENTS.get(recipient)
    if agent is None:
        _respond(row_id, {"error": f"no such agent {recipient}"})
        raise gateway.ToolBlocked("capability", f"no such agent '{recipient}'", "-")
    if msg.get("method") == "tools/list":
        result = list_tools(recipient)
    else:
        params = msg.get("params") or {}
        try:
            result = agent.handle(params.get("name"), params.get("arguments") or {}, ctx)
        except gateway.ToolBlocked as e:
            _respond(row_id, {"blocked": e.control, "reason": e.reason, "decision_id": e.decision_id})
            raise
    _respond(row_id, {"result": result})
    return result


def _respond(row_id, payload):
    db.x("UPDATE bus_messages SET response=? WHERE id=?", (json.dumps(payload, default=str)[:4000], row_id))


def deliver_external(msg: dict) -> dict:
    """Entry point for messages arriving from outside the process."""
    meta = msg.get("meta") or {}
    ctx = gateway.Ctx(actor=f"bus:{meta.get('from', 'unknown')}", role="system",
                      scope_customer=None, case_id=meta.get("case_id"))
    try:
        return {"ok": True, "result": _dispatch(msg, ctx), "trace": ctx.events}
    except gateway.ToolBlocked as e:
        return {"ok": False, "blocked": e.control, "reason": e.reason, "decision_id": e.decision_id,
                "trace": ctx.events}
