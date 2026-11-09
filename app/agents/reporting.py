"""Reporting agent: approved / denied refunds with reasons, and weekly totals."""
from app import db, drive
from app.agents.base import Agent
from app.gateway import register
from app.policy import active_policy


class ReportingAgent(Agent):
    name = "reporting"
    description = "Reports approved, denied and escalated refunds with amounts, dates and reasons, plus weekly totals."


AGENT = ReportingAgent()


def _totals():
    rules = active_policy()["rules"]
    auto = db.weekly_autonomous_total()
    return {"week_start": db.week_start().isoformat(timespec="seconds"),
            "autonomous_total": round(auto, 2),
            "all_refunds_total": round(db.weekly_total_all(), 2),
            "weekly_limit": rules["weekly_refund_limit"],
            "remaining_autonomous": round(max(rules["weekly_refund_limit"] - auto, 0), 2)}


@register("refund_report", agents={"reporting"},
          description="Approved/denied/escalated refunds with amount, date and reason.", params={"status": "str"})
def refund_report(args, ctx, decision_id):
    sql = ("SELECT c.id AS case_id, c.customer_id, c.order_id, c.amount, c.reason, c.status, c.decision, "
           "c.decision_reason, c.policy_rule, c.decided_by, c.updated_at, r.amount AS refunded_amount, "
           "r.created_at AS refunded_at, r.decision_id FROM cases c LEFT JOIN refunds r ON r.case_id=c.id "
           "WHERE c.status IN ('approved','refunded','denied','escalated','returned')")
    params = []
    if ctx.scope_customer:
        sql += " AND c.customer_id=?"
        params.append(ctx.scope_customer)
    if args.get("status"):
        sql += " AND c.status=?"
        params.append(args["status"])
    rows = db.q(sql + " ORDER BY c.updated_at DESC", params)
    approved = [r for r in rows if r["status"] in ("approved", "refunded")]
    denied = [r for r in rows if r["status"] == "denied"]
    escalated = [r for r in rows if r["status"] in ("escalated", "returned")]
    t = _totals()
    return {"approved": approved, "denied": denied, "escalated": escalated, "totals": t,
            "summary": (f"{len(approved)} approved (${sum(r['refunded_amount'] or 0 for r in approved):.2f} refunded), "
                        f"{len(denied)} denied, {len(escalated)} escalated/returned. "
                        f"Autonomous refunds this week ${t['autonomous_total']:.2f} of ${t['weekly_limit']:.0f}.")}


@register("weekly_total", agents={"reporting"}, description="Week-to-date refund totals.")
def weekly_total(args, ctx, decision_id):
    t = _totals()
    t["summary"] = f"week-to-date autonomous ${t['autonomous_total']:.2f} of ${t['weekly_limit']:.0f}"
    return t


@register("record_decision", agents={"reporting"},
          description="Append a decided case to this week's report file on the drive.", params={"case_id": "str"})
def record_decision(args, ctx, decision_id):
    c = db.q1("SELECT id,customer_id,order_id,amount,status,decision_reason,policy_rule,decided_by,updated_at "
              "FROM cases WHERE id=?", (args["case_id"],))
    name = f"report-week-{db.week_start().date().isoformat()}.jsonl"
    try:
        existing = drive.download("reports", name)
    except FileNotFoundError:
        existing = ""
    import json
    drive.upload("reports", name, existing + json.dumps(c) + "\n")
    return {"file": f"reports/{name}", "summary": f"recorded {c['id']} ({c['status']}) in reports/{name}"}
