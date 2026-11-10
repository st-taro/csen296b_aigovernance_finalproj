"""Inter-agent message bus, shaped like MCP (JSON-RPC 2.0 `tools/call`).

The orchestrator and agents never call each other's Python functions
directly. They send a signed JSON-RPC message through this bus:

    {"jsonrpc": "2.0", "id": "...", "method": "tools/call",
     "params": {"name": "<tool>", "arguments": {...}},
     "meta": {"from": "orchestrator", "to": "records", "run_id": "...",
              "case_id": "...", "ts": "...", "sig": "<hmac-sha256>"}}

Controls (ASI07 insecure inter-agent communication), all under the control
name bus_signature:
  - every message is HMAC-signed with a key derived for its sender, so a
    signature made as one agent cannot be relabelled as another; the receiver
    verifies before acting
  - messages older than BUS_MAX_AGE_SECONDS are rejected, and message IDs are
    remembered for that window to reject replays
  - a sender may only message the agents it needs (ROUTES): e.g. Records
    cannot instruct Refunds
  - the receiving agent acts under ITS OWN identity, so the gateway checks the
    receiver's capabilities, never a claimed sender identity
  - every message and response is logged to the bus_messages table

`deliver_external()` is the network-facing entry point (POST /bus/deliver),
simulating an exposed agent endpoint the red team can attack with forged or
replayed messages. Messages arriving there run with no customer scope, so even
a correctly signed message cannot read or change customer records.
"""
import hashlib
import hmac
import json
import threading
import time
import uuid
from datetime import datetime

from app import audit, config, db, gateway

AGENTS = {}

# Which agents each sender may message. Mirrors the real call graph: the
# orchestrator drives every agent, and Refunds asks Records for case facts.
ROUTES = {
    "orchestrator": {"intake", "email", "records", "refunds", "reporting"},
    "refunds": {"records"},
}

_seen_ids = {}                 # message id -> monotonic time first seen
_seen_lock = threading.Lock()


def register_agent(agent):
    AGENTS[agent.name] = agent


def _canonical(msg: dict) -> bytes:
    m = json.loads(json.dumps(msg))
    m.get("meta", {}).pop("sig", None)
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode()


def sender_key(sender: str) -> bytes:
    """Per-sender signing key derived from the master BUS_SECRET."""
    return hmac.new(config.BUS_SECRET.encode(), f"bus-key:{sender}".encode(), hashlib.sha256).digest()


def sign(msg: dict) -> str:
    sender = str((msg.get("meta") or {}).get("from"))
    return hmac.new(sender_key(sender), _canonical(msg), hashlib.sha256).hexdigest()


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


def _freshness_problem(meta: dict):
    try:
        ts = datetime.fromisoformat(str(meta.get("ts")))
    except ValueError:
        return "missing or invalid message timestamp"
    if ts.tzinfo is None:
        return "message timestamp has no timezone"
    age = (db.now() - ts).total_seconds()
    if age > config.BUS_MAX_AGE_SECONDS:
        return f"stale message ({int(age)}s old, max {config.BUS_MAX_AGE_SECONDS}s)"
    if age < -config.BUS_MAX_AGE_SECONDS:
        return "message timestamp is in the future"
    return None


def _is_replay(msg_id) -> bool:
    """Remember message IDs for long enough to cover the freshness window;
    anything older is rejected as stale anyway, so the cache stays small."""
    now = time.monotonic()
    with _seen_lock:
        for k in [k for k, t in _seen_ids.items() if now - t > 2 * config.BUS_MAX_AGE_SECONDS]:
            del _seen_ids[k]
        if msg_id in _seen_ids:
            return True
        _seen_ids[msg_id] = now
        return False


def _dispatch(msg: dict, ctx: gateway.Ctx):
    meta = msg.get("meta") or {}
    recipient = meta.get("to")
    sender = meta.get("from")
    valid = verify(msg)
    replay = _is_replay(msg.get("id"))
    stale = _freshness_problem(meta)
    route_ok = recipient in ROUTES.get(sender, set())
    row_id = db.x("INSERT INTO bus_messages(ts,run_id,sender,recipient,message,signature_valid) VALUES (?,?,?,?,?,?)",
                  (db.now_iso(), ctx.run_id, str(meta.get("from")), str(recipient),
                   json.dumps(msg), int(valid and not replay and not stale and route_ok)))
    problem = None
    if not valid:
        problem = "invalid or missing message signature"
    elif replay:
        problem = "replayed message id"
    elif stale:
        problem = stale
    elif not route_ok:
        problem = f"sender '{sender}' may not message agent '{recipient}'"
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
    """Entry point for messages arriving from outside the process. They get no
    customer scope (scope_customer=""), so the case_scope check blocks any
    customer or case access even when the signature is valid; external callers
    can only use tools that touch no customer data (e.g. search_policies)."""
    meta = msg.get("meta") or {}
    ctx = gateway.Ctx(actor=f"bus:{meta.get('from', 'unknown')}", role="external",
                      scope_customer="", case_id=meta.get("case_id"))
    try:
        return {"ok": True, "result": _dispatch(msg, ctx), "trace": ctx.events}
    except gateway.ToolBlocked as e:
        return {"ok": False, "blocked": e.control, "reason": e.reason, "decision_id": e.decision_id,
                "trace": ctx.events}
