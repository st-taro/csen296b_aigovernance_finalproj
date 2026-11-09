"""Records (document management) agent: customer cases and profiles.

Access   : get_case, list_cases, get_customer_profile
Storage  : store_case_file, update_customer_profile, index_profile
Retrieval: search_cases, search_profiles, search_policies (RAG over the vector DB),
           drive_search (mock cloud drive file search)
"""
from app import config, db, drive, guardrails, policy, vectorstore
from app.agents.base import Agent
from app.gateway import check_case_scope, register


class RecordsAgent(Agent):
    name = "records"
    description = "Looks up, stores and searches customer cases, customer profiles and policy documents (RAG)."


AGENT = RecordsAgent()

PROFILE_EDITABLE = {"phone", "address", "notes"}


def _public_case(c: dict) -> dict:
    keys = ("id", "customer_id", "order_id", "amount", "reason", "description", "status", "assigned_agent",
            "decision", "decision_reason", "policy_rule", "decided_by", "supervisor_locked",
            "injection_flag", "created_at", "updated_at")
    return {k: c.get(k) for k in keys}


def _profile_view(p: dict) -> dict:
    out = dict(p)
    if config.control_enabled("output_filter"):
        out["bank_account"] = guardrails.mask_account(p["bank_account"])
        out["bank_routing"] = guardrails.mask_account(p["bank_routing"])
    return out


def profile_doc(p: dict) -> str:
    return (f"Customer profile {p['id']}: {p['name']}, email {p['email']}, phone {p['phone']}, "
            f"address {p['address']}. Tier {p['tier']}. Bank: {p['bank_name']} account {p['bank_account']} "
            f"routing {p['bank_routing']}. Current balance ${p['balance']:.2f}. Notes: {p['notes'] or 'none'}.")


def case_doc(c: dict) -> str:
    return (f"Case {c['id']} for customer {c['customer_id']}, order {c['order_id']}, amount ${c['amount']:.2f}, "
            f"reason {c['reason']}. Status {c['status']}. Decision {c['decision'] or 'pending'}: "
            f"{c['decision_reason'] or ''}\nCustomer description: {c['description']}")


def _scope_where(ctx, args):
    if ctx.scope_customer and config.control_enabled("case_scope"):
        return {"customer_id": ctx.scope_customer}
    if args.get("customer_id"):
        return {"customer_id": args["customer_id"]}
    return None


# ---------------------------------------------------------------- access
@register("get_case", agents={"records"}, checks=[check_case_scope],
          description="Get one case by ID.", params={"case_id": "str"})
def get_case(args, ctx, decision_id):
    c = db.q1("SELECT * FROM cases WHERE id=?", (args.get("case_id"),))
    if not c:
        raise ValueError(f"case {args.get('case_id')} not found")
    out = _public_case(c)
    out["summary"] = f"{c['id']}: {c['status']}" + (f" ({c['decision_reason']})" if c["decision_reason"] else "")
    return out


@register("list_cases", agents={"records"}, checks=[check_case_scope],
          description="List cases for a customer (or all cases for supervisors).", params={"customer_id": "str"})
def list_cases(args, ctx, decision_id):
    cust = args.get("customer_id") or (ctx.scope_customer or None)
    if cust:
        rows = db.q("SELECT * FROM cases WHERE customer_id=? ORDER BY created_at DESC", (cust,))
    else:
        rows = db.q("SELECT * FROM cases ORDER BY created_at DESC")
    return {"cases": [_public_case(r) for r in rows],
            "summary": ", ".join(f"{r['id']} ({r['status']})" for r in rows[:10]) or "no cases"}


@register("get_customer_profile", agents={"records"}, checks=[check_case_scope],
          description="Get a customer profile (bank details masked).", params={"customer_id": "str"})
def get_customer_profile(args, ctx, decision_id):
    cid = args.get("customer_id") or ctx.scope_customer
    p = db.q1("SELECT * FROM customers WHERE id=?", (cid,))
    if not p:
        raise ValueError(f"customer {cid} not found")
    v = _profile_view(p)
    v["summary"] = f"{p['name']} ({p['id']}), {p['email']}, balance ${p['balance']:.2f}, account {v['bank_account']}"
    return v


# ---------------------------------------------------------------- storage
def check_profile_fields(args, ctx):
    bad = set((args.get("fields") or {}).keys()) - PROFILE_EDITABLE
    if bad:
        return ("capability", f"fields {sorted(bad)} cannot be changed by an agent")
    return None


@register("update_customer_profile", agents={"records"}, consequential=True,
          checks=[check_case_scope, check_profile_fields],
          description="Update editable profile fields (phone, address, notes).",
          params={"customer_id": "str", "fields": "dict"})
def update_customer_profile(args, ctx, decision_id):
    fields = {k: str(v)[:500] for k, v in (args.get("fields") or {}).items()}
    allowed_cols = PROFILE_EDITABLE | {"bank_account", "bank_routing", "bank_name", "balance", "email", "name"}
    sets = {k: v for k, v in fields.items() if k in allowed_cols}  # unknown columns never reach SQL
    if not sets:
        raise ValueError("no valid fields")
    db.x(f"UPDATE customers SET {', '.join(k + '=?' for k in sets)}, updated_at=? WHERE id=?",
         (*sets.values(), db.now_iso(), args["customer_id"]))
    index_profile(args["customer_id"])
    return {"customer_id": args["customer_id"], "updated": sorted(sets), "summary": f"updated {sorted(sets)}"}


@register("store_case_file", agents={"records"}, checks=[check_case_scope],
          description="Save the case file to the drive and index it in the vector DB.", params={"case_id": "str"})
def store_case_file(args, ctx, decision_id):
    c = db.q1("SELECT * FROM cases WHERE id=?", (args["case_id"],))
    if not c:
        raise ValueError("case not found")
    meta = drive.upload("cases", f"{c['id']}.json", _public_case(c))
    vectorstore.store().upsert("cases", [c["id"]], [case_doc(c)],
                               [{"case_id": c["id"], "customer_id": c["customer_id"], "status": c["status"]}])
    return {"case_id": c["id"], "file": f"cases/{meta['name']}", "summary": f"stored cases/{meta['name']} and indexed"}


def index_profile(customer_id: str):
    p = db.q1("SELECT * FROM customers WHERE id=?", (customer_id,))
    if not p:
        return
    drive.upload("profiles", f"{p['id']}.json", p)
    vectorstore.store().upsert("profiles", [p["id"]], [profile_doc(p)], [{"customer_id": p["id"]}])


def index_all_profiles():
    for p in db.q("SELECT id FROM customers"):
        index_profile(p["id"])
    for c in db.q("SELECT * FROM cases"):
        vectorstore.store().upsert("cases", [c["id"]], [case_doc(c)],
                                   [{"case_id": c["id"], "customer_id": c["customer_id"], "status": c["status"]}])
        drive.upload("cases", f"{c['id']}.json", _public_case(c))


# ---------------------------------------------------------------- retrieval
@register("search_cases", agents={"records"}, checks=[check_case_scope],
          description="Semantic search over case files (scoped to the run's customer).",
          params={"query": "str", "customer_id": "str"})
def search_cases(args, ctx, decision_id):
    hits = vectorstore.store().query("cases", args.get("query", ""), k=5, where=_scope_where(ctx, args))
    for h in hits:
        h["text"] = guardrails.redact(h["text"]) if config.control_enabled("output_filter") else h["text"]
    return {"results": hits, "summary": f"{len(hits)} case(s): " + ", ".join(h["id"] for h in hits)}


@register("search_profiles", agents={"records"}, checks=[check_case_scope],
          description="Semantic search over customer profiles (scoped to the run's customer).",
          params={"query": "str", "customer_id": "str"})
def search_profiles(args, ctx, decision_id):
    hits = vectorstore.store().query("profiles", args.get("query", ""), k=3, where=_scope_where(ctx, args))
    for h in hits:
        h["text"] = guardrails.redact(h["text"]) if config.control_enabled("output_filter") else h["text"]
    return {"results": hits, "summary": " | ".join(h["text"][:160] for h in hits) or "no profiles"}


@register("search_policies", agents={"records"},
          description="Semantic search over the active refund policy.", params={"query": "str"})
def search_policies(args, ctx, decision_id):
    hits = policy.search(args.get("query", ""), k=int(args.get("k", 3)))
    return {"results": hits, "summary": (hits[0]["text"][:300] if hits else "no policy text found")}


def check_drive_scope(args, ctx):
    if ctx.scope_customer is not None:
        return ("case_scope", "drive search across all files is limited to supervisors")
    return None


@register("drive_search", agents={"records"}, checks=[check_drive_scope],
          description="Search files in the mock cloud drive.", params={"folder": "str", "text": "str"})
def drive_search(args, ctx, decision_id):
    res = drive.search(args.get("folder", "cases"), args.get("text", ""), args.get("name", ""))
    return {"files": res, "summary": f"{len(res)} file(s)"}
