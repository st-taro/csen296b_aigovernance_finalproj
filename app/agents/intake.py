"""Intake agent: ticket submission and ticket assignment."""
from app import audit, config, db, guardrails
from app.agents.base import Agent
from app.gateway import check_case_scope, check_supervisor_lock, register
from app.policy import REASONS


class IntakeAgent(Agent):
    name = "intake"
    description = "Receives refund requests, creates customer cases and assigns them to an agent queue."


AGENT = IntakeAgent()


@register("submit_case", agents={"intake"}, checks=[check_case_scope],
          description="Create a refund case for a customer's order.",
          params={"customer_id": "str", "order_id": "str", "amount": "float", "reason": "str", "description": "str"})
def submit_case(args, ctx, decision_id):
    cust_id = args.get("customer_id") or ctx.scope_customer
    customer = db.q1("SELECT * FROM customers WHERE id=?", (cust_id,))
    if not customer:
        raise ValueError(f"unknown customer {cust_id}")
    order_id = str(args.get("order_id") or "").strip().upper()
    if not order_id:
        raise ValueError("order_id is required")
    reason = args.get("reason") or "other"
    if reason not in REASONS:
        reason = "other"
    try:
        amount = round(float(args.get("amount")), 2)
    except (TypeError, ValueError):
        order = db.q1("SELECT amount FROM orders WHERE order_id=?", (order_id,))
        amount = float(order["amount"]) if order else 0.0
    description = str(args.get("description") or "")
    if config.control_enabled("input_filter"):
        description = description[:config.MAX_INPUT_CHARS]
    inj = guardrails.detect_injection(description)
    ts = db.now_iso()
    # Allocate the ID and insert under one lock, or concurrent submissions get
    # the same ID and all but one fail.
    with db._lock:
        case_id = db.next_case_id()
        db.x("INSERT INTO cases(id,customer_id,order_id,amount,reason,description,contact_email,status,"
             "injection_flag,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
             (case_id, cust_id, order_id, amount, reason, description,
              customer["email"],  # contact email comes from the record, never from the request
              "submitted", int(inj["flagged"]), ts, ts))
    if inj["flagged"]:
        audit.record(ctx.actor, "info", agent="intake", tool="input_filter", case_id=case_id,
                     control="input_filter", reason="possible prompt injection: " + "; ".join(inj["patterns"][:3]),
                     run_id=ctx.run_id)
    return {"case_id": case_id, "status": "submitted", "injection_flagged": inj["flagged"],
            "summary": f"created {case_id} for {order_id} (${amount:.2f}, {reason})"}


@register("assign_case", agents={"intake"}, checks=[check_case_scope, check_supervisor_lock],
          description="Assign a submitted case to an agent queue.", params={"case_id": "str"})
def assign_case(args, ctx, decision_id):
    case = db.q1("SELECT * FROM cases WHERE id=?", (args["case_id"],))
    if not case:
        raise ValueError("case not found")
    queue = "refunds"
    note = "standard refund queue"
    if case["injection_flag"] and config.control_enabled("input_filter"):
        queue = "supervisor"
        note = "flagged by input filter: routed to supervisor review"
    db.x("UPDATE cases SET assigned_agent=?, status='assigned', updated_at=? WHERE id=?",
         (queue, db.now_iso(), case["id"]))
    return {"case_id": case["id"], "assigned_to": queue, "summary": f"assigned to {queue} ({note})"}
