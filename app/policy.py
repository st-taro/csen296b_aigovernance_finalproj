"""Refund policy: parsing uploaded policy documents and the deterministic
policy engine.

The policy engine is the independent control for refund decisions. The LLM
proposes a decision; this engine (outside the LLM) decides what is allowed.
"""
import io
import json
import re
from datetime import datetime, timedelta

from app import config, db, vectorstore

REASONS = {
    "damaged": "Damaged item",
    "not_delivered": "Item not delivered",
    "wrong_item": "Wrong item received",
    "duplicate_charge": "Duplicate charge",
    "other": "Other",
}

DEFAULT_RULES = {
    "single_refund_limit": 100.0,
    "weekly_refund_limit": 500.0,
    "purchase_window_days": 30,
    "eligible_reasons": ["damaged", "not_delivered", "wrong_item", "duplicate_charge"],
    "one_refund_per_order": True,
    "require_order_match": True,
}


# --------------------------------------------------------------------------
# Document text extraction
# --------------------------------------------------------------------------
def extract_text(filename: str, data: bytes) -> str:
    name = (filename or "").lower()
    if name.endswith(".pdf"):
        try:
            from pypdf import PdfReader
        except ImportError as e:
            raise ValueError("PDF upload needs the 'pypdf' package (pip install pypdf)") from e
        reader = PdfReader(io.BytesIO(data))
        return "\n\n".join((p.extract_text() or "") for p in reader.pages)
    if name.endswith(".docx"):
        try:
            import docx
        except ImportError as e:
            raise ValueError("DOCX upload needs the 'python-docx' package (pip install python-docx)") from e
        d = docx.Document(io.BytesIO(data))
        return "\n\n".join(p.text for p in d.paragraphs)
    return data.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Rule parsing
# --------------------------------------------------------------------------
_RULE_LINE = re.compile(r"^\s*([a-z_]+)\s*:\s*(.*?)\s*$", re.M)
_LIMIT_KEYS = ("single_refund_limit", "weekly_refund_limit")
# Strict formats (policy_validation): plain ASCII dollar amounts and day counts.
# This rejects nan, inf, 1e309, "$1,000", Unicode digits and negative numbers.
_MONEY = re.compile(r"^\$?([0-9]{1,7})(\.[0-9]{1,2})?$")
_DAYS = re.compile(r"^[0-9]{1,5}$")
_BOOLS = {"true": True, "yes": True, "1": True, "false": False, "no": False, "0": False}


class PolicyRejected(ValueError):
    """An uploaded policy failed strict validation (policy_validation)."""

    def __init__(self, errors: list):
        super().__init__("policy rejected: " + "; ".join(errors))
        self.errors = errors


def _strict_value(key: str, val: str):
    """Parse one rule strictly. Raises ValueError with a readable message."""
    if key in _LIMIT_KEYS:
        if not _MONEY.match(val):
            raise ValueError(f"{key} must be a plain dollar amount such as 100 or 99.50, got {val!r}")
        amount = float(val.lstrip("$"))
        if amount <= 0:
            raise ValueError(f"{key} must be greater than 0, got {val!r}")
        return amount
    if key == "purchase_window_days":
        if not _DAYS.match(val):
            raise ValueError(f"purchase_window_days must be a whole number of days, got {val!r}")
        days = int(val)
        if not 1 <= days <= config.MAX_PURCHASE_WINDOW_DAYS:
            raise ValueError(f"purchase_window_days must be between 1 and {config.MAX_PURCHASE_WINDOW_DAYS}, got {days}")
        return days
    if key == "eligible_reasons":
        items = [r.strip() for r in val.split(",") if r.strip()]
        if not items:
            raise ValueError("eligible_reasons must list at least one reason")
        bad = [r for r in items if r not in REASONS or r == "other"]
        if bad:
            allowed = ", ".join(r for r in REASONS if r != "other")
            raise ValueError(f"eligible_reasons has unknown or non-eligible values {bad}; allowed: {allowed}")
        return items
    if val.lower() not in _BOOLS:
        raise ValueError(f"{key} must be true or false, got {val!r}")
    return _BOOLS[val.lower()]


def _legacy_value(key: str, val: str):
    """The original lenient parser (used when policy_validation is disabled)."""
    if key in _LIMIT_KEYS:
        return float(val.replace("$", ""))
    if key == "purchase_window_days":
        return int(val)
    if key == "eligible_reasons":
        return [r.strip() for r in val.split(",") if r.strip() in REASONS and r.strip() != "other"]
    return val.lower() in ("true", "yes", "1")


def _parse(text: str, strict: bool) -> tuple:
    """Returns (rules, warnings, errors). Errors are only produced in strict mode."""
    block = re.search(r"```policy-rules\s*(.*?)```", text or "", re.S)
    # Strict mode reads rules only from the fenced block, so prose such as
    # "single_refund_limit: anything" elsewhere in the document cannot set a rule.
    body = block.group(1) if block else ("" if strict else (text or ""))
    rules = dict(DEFAULT_RULES)
    warnings, errors = [], []
    for key, val in _RULE_LINE.findall(body):
        if key not in DEFAULT_RULES:
            if block:
                warnings.append(f"unknown rule '{key}' ignored")
            continue
        try:
            rules[key] = _strict_value(key, val) if strict else _legacy_value(key, val)
        except ValueError as e:
            if strict:
                errors.append(str(e))
            else:
                warnings.append(f"Could not parse {key}: {val!r}; kept default")
    if not block:
        warnings.append("No ```policy-rules block found; defaults used for anything not stated.")
    # Clamp to hard limits (the uploader cannot grant the agent more authority)
    for key, hard in (("single_refund_limit", config.HARD_SINGLE_LIMIT), ("weekly_refund_limit", config.HARD_WEEKLY_LIMIT)):
        if rules[key] > hard:
            warnings.append(f"{key} clamped to org hard limit ${hard:.0f}")
            rules[key] = hard
    if not strict:
        rules["purchase_window_days"] = max(1, min(int(rules["purchase_window_days"]), 365))
    # Proof of purchase and one-refund-per-order cannot be switched off by upload.
    for k in ("one_refund_per_order", "require_order_match"):
        if not rules[k]:
            warnings.append(f"{k} cannot be disabled by policy upload; kept true")
            rules[k] = True
    return rules, warnings, errors


def parse_rules(text: str, strict: bool = None) -> tuple:
    """Parse the `policy-rules` block out of a policy document. Returns
    (rules, warnings). Limits are clamped to the org's hard limits: an uploaded
    policy can lower them but never raise them.

    With policy_validation enabled (the default) values must be finite,
    positive, in range and in a plain format, eligible_reasons must be
    non-empty, and anything invalid raises PolicyRejected instead of being
    saved (RT 4.2, 4.6)."""
    strict = config.control_enabled("policy_validation") if strict is None else strict
    rules, warnings, errors = _parse(text, strict)
    if errors:
        raise PolicyRejected(errors)
    return rules, warnings


def strict_errors(text: str) -> list:
    """What strict validation would reject, whatever the control setting
    (used to log would_block in monitor mode)."""
    return _parse(text, True)[2]


# --------------------------------------------------------------------------
# Policy storage and indexing
# --------------------------------------------------------------------------
def add_policy(title: str, filename: str, content: str, uploaded_by: str, activate: bool = True) -> dict:
    rules, warnings = parse_rules(content)
    pid = db.x("INSERT INTO policies(title,filename,content,rules_json,uploaded_by,active,created_at) "
               "VALUES (?,?,?,?,?,?,?)",
               (title, filename, content, json.dumps(rules), uploaded_by, 0, db.now_iso()))
    chunks = vectorstore.chunk(content)
    vectorstore.store().upsert(
        "policies",
        [f"policy-{pid}-{i}" for i in range(len(chunks))],
        chunks,
        [{"policy_id": pid, "title": title, "chunk": i, "active": False} for i in range(len(chunks))],
    )
    if activate:
        activate_policy(pid)
    return {"id": pid, "title": title, "rules": rules, "warnings": warnings, "chunks": len(chunks)}


def activate_policy(pid: int) -> None:
    db.x("UPDATE policies SET active=0")
    db.x("UPDATE policies SET active=1 WHERE id=?", (pid,))
    # Re-flag chunks so retrieval only sees the active policy.
    for p in db.q("SELECT id,title,content FROM policies"):
        chunks = vectorstore.chunk(p["content"])
        vectorstore.store().upsert(
            "policies",
            [f"policy-{p['id']}-{i}" for i in range(len(chunks))],
            chunks,
            [{"policy_id": p["id"], "title": p["title"], "chunk": i, "active": p["id"] == pid}
             for i in range(len(chunks))],
        )


def active_policy() -> dict:
    p = db.q1("SELECT * FROM policies WHERE active=1")
    if not p:
        return {"id": None, "title": "(defaults)", "rules": dict(DEFAULT_RULES)}
    p["rules"] = json.loads(p["rules_json"])
    return p


def search(query: str, k: int = 4, active_only: bool = True) -> list:
    where = {"active": True} if active_only else None
    return vectorstore.store().query("policies", query, k=k, where=where)


def seed_default_policy() -> None:
    if db.q1("SELECT 1 AS one FROM policies"):
        return
    path = config.SEED_DIR / "policies" / "refund_policy_v1.md"
    add_policy("Customer Refund Policy v1", path.name, path.read_text(encoding="utf-8"), "system")


# --------------------------------------------------------------------------
# Deterministic policy engine
# --------------------------------------------------------------------------
def evaluate(case: dict, rules: dict = None) -> dict:
    """Evaluate a refund case against the active policy.

    Returns {"result": approve|deny|escalate, "rule": <rule id>, "reason": str,
             "checks": [ {rule, passed, detail} ... ]}
    Deny rules are checked first, then escalate rules.
    """
    rules = rules or active_policy()["rules"]
    checks = []

    def check(rule, passed, detail):
        checks.append({"rule": rule, "passed": bool(passed), "detail": detail})
        return passed

    order = db.q1("SELECT * FROM orders WHERE order_id=?", (case["order_id"],))
    amount = float(case["amount"])

    # --- deny rules
    if not check("proof_of_purchase", order and order["customer_id"] == case["customer_id"],
                 "Order ID matches the customer's record" if order and order["customer_id"] == case["customer_id"]
                 else "Order ID not found in this customer's record"):
        return _result("deny", "proof_of_purchase", "The order ID does not match your account.", checks)
    if not check("amount_le_order", amount <= float(order["amount"]) + 0.001,
                 f"Requested ${amount:.2f} vs order total ${order['amount']:.2f}"):
        return _result("deny", "amount_le_order",
                       f"The requested amount (${amount:.2f}) is more than the order total (${order['amount']:.2f}).",
                       checks)
    if not check("positive_amount", amount > 0, f"Requested ${amount:.2f}"):
        return _result("deny", "positive_amount", "The refund amount must be greater than zero.", checks)
    order_date = datetime.fromisoformat(order["order_date"])
    age = (db.now() - order_date).days
    window = int(rules["purchase_window_days"])
    if not check("purchase_window", age <= window, f"Order placed {age} days ago (window {window} days)"):
        return _result("deny", "purchase_window",
                       f"The order was placed {age} days ago, outside the {window}-day refund window.", checks)
    prior = db.q1("SELECT case_id FROM refunds WHERE order_id=?", (case["order_id"],))
    if not check("one_refund_per_order", not prior,
                 f"Earlier refund on this order: {prior['case_id']}" if prior else "No earlier refund on this order"):
        return _result("deny", "one_refund_per_order", "This order has already been refunded.", checks)

    # --- escalate rules
    if not check("eligible_reason", case["reason"] in rules["eligible_reasons"],
                 f"Reason '{case['reason']}'"):
        return _result("escalate", "eligible_reason",
                       "The reason given needs review by a supervisor.", checks)
    single = float(rules["single_refund_limit"])
    if not check("single_refund_limit", amount <= single, f"${amount:.2f} vs limit ${single:.2f}"):
        return _result("escalate", "single_refund_limit",
                       f"Refunds over ${single:.0f} need supervisor approval.", checks)
    weekly = float(rules["weekly_refund_limit"])
    used = db.weekly_autonomous_total()
    if not check("weekly_refund_limit", used + amount <= weekly,
                 f"Week-to-date ${used:.2f} + ${amount:.2f} vs limit ${weekly:.2f}"):
        return _result("escalate", "weekly_refund_limit",
                       "This week's automatic refund budget has been reached; a supervisor will review.", checks)
    return _result("approve", "all_rules_passed",
                   f"Eligible reason ({REASONS[case['reason']]}), within {window} days, "
                   f"and within the ${single:.0f} refund limit.", checks)


def _result(result, rule, reason, checks):
    return {"result": result, "rule": rule, "reason": reason, "checks": checks}
