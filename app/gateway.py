"""Tool gateway: the independent execution-boundary control.

Every tool an agent can use is registered here with the set of agents allowed
to call it. Agents never touch the database directly for consequential
actions; they call `gateway.call(agent, tool, args, ctx)`. The gateway:

  1. counts tool calls per run           (rate_limit,   LLM06)
  2. checks the agent may use the tool   (capability,   ASI02/ASI03, LLM06 excessive agency)
  3. checks agent authority is not revoked for consequential tools (kill_switch)
  4. runs the tool's own checks          (case_scope, email_recipient, single_limit,
                                          weekly_limit, order_checks, supervisor_lock)
  5. writes an audit row with a decision ID (allowed / blocked / would_block)

Checks live outside the LLM, so no prompt can switch them off. With
GUARDRAILS=off (sandbox only) violations are logged as `would_block` and the
action still executes, which is how the team produces "functional but
insecure" baseline evidence.
"""
import threading
import uuid
from dataclasses import dataclass, field

from app import audit, config, db


class ToolBlocked(Exception):
    def __init__(self, control, reason, decision_id):
        super().__init__(reason)
        self.control = control
        self.reason = reason
        self.decision_id = decision_id


@dataclass
class Ctx:
    """Who is acting and on whose behalf. Built by the server from the
    authenticated session, never from model output."""
    actor: str                       # e.g. "customer:alice", "supervisor:supervisor", "system"
    role: str                        # customer | admin | supervisor | system
    scope_customer: object = None    # customer id this run may touch; None = any; "" = none
    case_id: str = None              # case this run is bound to (if any)
    human_authorized: bool = False   # True only on the supervisor decision path
    run_id: str = field(default_factory=lambda: "R-" + uuid.uuid4().hex[:10])
    tool_calls: int = 0
    events: list = field(default_factory=list)   # trace of tool calls for the UI

    def child(self, **kw):
        c = Ctx(**{**self.__dict__, **kw})
        c.events = self.events
        return c


@dataclass
class Tool:
    name: str
    fn: object
    agents: set
    consequential: bool = False
    checks: list = field(default_factory=list)
    description: str = ""
    params: dict = field(default_factory=dict)


TOOLS: dict = {}

# Consequential tools (refunds, emails, profile updates) run their checks and
# their action under one lock. Without it, two concurrent runs can both read
# "week-to-date $0" or "order not refunded yet", both pass, and both execute
# (check-then-act race on the weekly limit and one-refund-per-order).
_CONSEQUENTIAL_LOCK = threading.RLock()


def register(name, agents, consequential=False, checks=(), description="", params=None):
    def deco(fn):
        TOOLS[name] = Tool(name, fn, set(agents), consequential, list(checks), description, params or {})
        return fn
    return deco


def tools_for(agent: str) -> list:
    """MCP-style tools/list for one agent."""
    return [{"name": t.name, "description": t.description, "inputSchema": t.params,
             "consequential": t.consequential}
            for t in TOOLS.values() if agent in t.agents]


def authority_revoked() -> bool:
    return bool((db.get_state("agent_authority") or {}).get("revoked"))


def call(agent: str, tool: str, args: dict, ctx: Ctx):
    args = dict(args or {})
    case_id = args.get("case_id") or ctx.case_id
    violations = []

    ctx.tool_calls += 1
    if ctx.tool_calls > config.MAX_TOOL_CALLS_PER_RUN:
        violations.append(("rate_limit", f"run exceeded {config.MAX_TOOL_CALLS_PER_RUN} tool calls"))

    t = TOOLS.get(tool)
    if t is None:
        did = audit.record(ctx.actor, "blocked", agent=agent, tool=tool, case_id=case_id, args=args,
                           control="capability", reason=f"unknown tool '{tool}'", run_id=ctx.run_id)
        ctx.events.append({"agent": agent, "tool": tool, "outcome": "blocked", "control": "capability",
                           "reason": f"unknown tool '{tool}'", "decision_id": did})
        # Unknown tools cannot execute even in monitor mode: there is nothing to run.
        raise ToolBlocked("capability", f"unknown tool '{tool}'", did)

    if t.consequential:
        with _CONSEQUENTIAL_LOCK:
            return _check_and_run(agent, tool, t, args, ctx, case_id, violations)
    return _check_and_run(agent, tool, t, args, ctx, case_id, violations)


def _check_and_run(agent, tool, t, args, ctx, case_id, violations):
    if agent not in t.agents:
        violations.append(("capability", f"agent '{agent}' is not permitted to call '{tool}'"))
    if t.consequential and authority_revoked() and not ctx.human_authorized:
        violations.append(("kill_switch", "agent authority is revoked by a supervisor"))
    for chk in t.checks:
        v = chk(args, ctx)
        if v:
            violations.append(v)

    enforced = [v for v in violations if config.control_enabled(v[0])]
    monitored = [v for v in violations if not config.control_enabled(v[0])]
    if enforced:
        control, reason = enforced[0]
        did = audit.record(ctx.actor, "blocked", agent=agent, tool=tool, case_id=case_id, args=args,
                           control=control, reason=reason, run_id=ctx.run_id)
        ctx.events.append({"agent": agent, "tool": tool, "outcome": "blocked", "control": control,
                           "reason": reason, "decision_id": did})
        raise ToolBlocked(control, reason, did)
    for control, reason in monitored:
        did = audit.record(ctx.actor, "would_block", agent=agent, tool=tool, case_id=case_id, args=args,
                           control=control, reason=f"[guardrail disabled] {reason}", run_id=ctx.run_id)
        ctx.events.append({"agent": agent, "tool": tool, "outcome": "would_block", "control": control,
                           "reason": reason, "decision_id": did})

    decision_id = audit.new_decision_id()
    try:
        result = t.fn(args, ctx, decision_id)
    except ToolBlocked:
        raise
    except Exception as e:
        audit.record(ctx.actor, "error", agent=agent, tool=tool, case_id=case_id, args=args,
                     reason=f"{type(e).__name__}: {e}", run_id=ctx.run_id, decision_id=decision_id)
        ctx.events.append({"agent": agent, "tool": tool, "outcome": "error", "reason": str(e),
                           "decision_id": decision_id})
        raise
    audit.record(ctx.actor, "allowed", agent=agent, tool=tool, case_id=case_id, args=args,
                 reason=_summ(result), run_id=ctx.run_id, decision_id=decision_id)
    ctx.events.append({"agent": agent, "tool": tool, "outcome": "allowed", "decision_id": decision_id,
                       "summary": _summ(result)})
    return result


def _summ(result) -> str:
    if isinstance(result, dict):
        if "summary" in result:
            return str(result["summary"])[:300]
        return ", ".join(f"{k}={v}" for k, v in list(result.items())[:4])[:300]
    if isinstance(result, list):
        return f"{len(result)} item(s)"
    return str(result)[:300]


# ---------------------------------------------------------------------------
# Reusable checks. Each returns None (ok) or (control_name, reason).
# ---------------------------------------------------------------------------
def _case(args, ctx):
    cid = args.get("case_id") or ctx.case_id
    return db.q1("SELECT * FROM cases WHERE id=?", (cid,)) if cid else None


def check_case_scope(args, ctx):
    """The run may only touch the customer it is working for."""
    scope = ctx.scope_customer
    if scope is None:
        return None
    if scope == "":
        if args.get("customer_id") or args.get("case_id"):
            return ("case_scope", f"role '{ctx.role}' may not access customer records")
        return None
    cust = args.get("customer_id")
    if cust and cust != scope:
        return ("case_scope", f"customer {cust} is outside this run's scope ({scope})")
    case = _case(args, ctx)
    if args.get("case_id") and case is None:
        return None  # tool itself reports not-found
    if case and case["customer_id"] != scope:
        return ("case_scope", f"case {case['id']} belongs to another customer")
    return None


def check_email_recipient(args, ctx):
    case = _case(args, ctx)
    to = (args.get("to") or "").strip().lower()
    if not case:
        return ("email_recipient", "outbound email must be tied to a case")
    if to != case["contact_email"].lower():
        return ("email_recipient", f"recipient {to or '(none)'} is not the case contact email")
    return None


def check_supervisor_lock(args, ctx):
    case = _case(args, ctx)
    if case and case["supervisor_locked"] and not ctx.human_authorized:
        return ("supervisor_lock", f"case {case['id']} has a final supervisor decision")
    return None


def _refund_amount(args, ctx):
    case = _case(args, ctx)
    amt = args.get("amount")
    if amt is None and case:
        amt = case["amount"]
    return float(amt or 0), case


def check_single_limit(args, ctx):
    if ctx.human_authorized or args.get("decision", "approve") != "approve":
        return None
    from app.policy import active_policy
    amt, _ = _refund_amount(args, ctx)
    limit = min(float(active_policy()["rules"]["single_refund_limit"]), config.HARD_SINGLE_LIMIT)
    if amt > limit:
        return ("single_limit", f"${amt:.2f} exceeds the ${limit:.2f} autonomous single-refund limit")
    return None


def check_weekly_limit(args, ctx):
    if ctx.human_authorized or args.get("decision", "approve") != "approve":
        return None
    from app.policy import active_policy
    amt, _ = _refund_amount(args, ctx)
    limit = min(float(active_policy()["rules"]["weekly_refund_limit"]), config.HARD_WEEKLY_LIMIT)
    used = db.weekly_autonomous_total()
    if used + amt > limit:
        return ("weekly_limit", f"week-to-date ${used:.2f} + ${amt:.2f} exceeds the ${limit:.2f} weekly limit")
    return None


def check_order(args, ctx):
    if args.get("decision", "approve") != "approve":
        return None
    amt, case = _refund_amount(args, ctx)
    if not case:
        return ("order_checks", "refund must be tied to an existing case")
    order = db.q1("SELECT * FROM orders WHERE order_id=?", (case["order_id"],))
    if not order or order["customer_id"] != case["customer_id"]:
        return ("order_checks", "order does not belong to the case's customer")
    if amt <= 0:
        return ("order_checks", "refund amount must be positive")
    if amt > float(case["amount"]) + 0.001 or amt > float(order["amount"]) + 0.001:
        return ("order_checks", f"${amt:.2f} exceeds the requested/order amount")
    if db.q1("SELECT 1 AS one FROM refunds WHERE order_id=?", (case["order_id"],)):
        return ("order_checks", f"order {case['order_id']} was already refunded")
    return None


def check_policy_engine(args, ctx):
    """An autonomous approval must agree with the deterministic policy engine."""
    if ctx.human_authorized or args.get("decision", "approve") != "approve":
        return None
    from app.policy import evaluate
    case = _case(args, ctx)
    if not case:
        return None
    ev = evaluate(case)
    if ev["result"] != "approve":
        return ("policy_engine", f"policy engine result is '{ev['result']}' ({ev['rule']}), not approve")
    return None
