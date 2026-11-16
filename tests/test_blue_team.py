"""Blue-team regression tests. Run: python -m pytest -q tests/test_blue_team.py

One test (or group) per red-team ID from redteam/plan.md. Each test runs the
attack in-process and asserts the control HOLDS with guardrails on. Where it
helps the before/after evidence, a second test switches the control off
(monitor mode) and asserts the old behaviour comes back with a would_block
audit row.

Uses an isolated temporary data directory and the offline mock LLM, and
re-seeds the sandbox at the start so results do not depend on test order.
"""
import os
import tempfile

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="rmm-bt-"))
os.environ["LLM_PROVIDER"] = "mock"
os.environ["GUARDRAILS"] = "on"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import config, db, gateway, policy  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        c.post("/api/admin/reset-sandbox", headers=login(c, "admin", "admin123"))
        yield c


@pytest.fixture
def disable(monkeypatch):
    """disable("control") switches one control to monitor mode for one test."""
    def _off(*names):
        monkeypatch.setattr(config, "GUARDRAIL_DISABLE", set(config.GUARDRAIL_DISABLE) | set(names))
    return _off


def login(c, user, pw=None):
    pw = pw or {"supervisor": "super123"}.get(user, user + "123")
    r = c.post("/api/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def rules_doc(**rules):
    body = "\n".join(f"{k}: {v}" for k, v in rules.items())
    return f"# Policy upload (blue-team test)\n\n```policy-rules\n{body}\n```\n"


def active_rules():
    return policy.active_policy()["rules"]


def last_audit(control=None, outcome=None):
    sql, params = "SELECT * FROM audit_log WHERE 1=1", []
    if control:
        sql += " AND control=?"
        params.append(control)
    if outcome:
        sql += " AND outcome=?"
        params.append(outcome)
    return db.q1(sql + " ORDER BY seq DESC LIMIT 1", params)


# ---------------------------------------------------------------------------
# RT 4.2 / 4.6: policy validation (control: policy_validation)
# ---------------------------------------------------------------------------
BAD_POLICIES = {
    "nan limit": dict(single_refund_limit="nan"),
    "inf limit": dict(single_refund_limit="inf"),
    "1e309 limit": dict(single_refund_limit="1e309"),
    "negative single": dict(single_refund_limit=-5),
    "zero weekly": dict(weekly_refund_limit=0),
    "negative weekly": dict(weekly_refund_limit=-1),
    "comma money": dict(single_refund_limit="$1,000"),
    "unicode digits": dict(single_refund_limit="١٠٠"),
    "365-day window": dict(purchase_window_days=365),
    "zero window": dict(purchase_window_days=0),
    "empty reasons": dict(eligible_reasons=""),
    "unknown reason": dict(eligible_reasons="damaged, changed_my_mind"),
    "other is not auto-eligible": dict(eligible_reasons="damaged, other"),
}


@pytest.mark.parametrize("label", BAD_POLICIES)
def test_rt_4_2_4_6_invalid_policy_rejected(client, label):
    a = login(client, "admin", "admin123")
    before = active_rules()
    n_before = len(db.q("SELECT id FROM policies"))
    r = client.post("/api/policies", headers=a, data={"title": f"BT {label}", "text": rules_doc(**BAD_POLICIES[label])})
    assert r.status_code == 400, r.text
    assert "policy rejected" in r.json()["detail"]
    assert len(db.q("SELECT id FROM policies")) == n_before      # nothing saved
    assert active_rules() == before                               # nothing activated
    assert last_audit("policy_validation", "blocked") is not None
    assert client.get("/api/system", headers=a).status_code == 200   # no 500 afterwards


def test_rt_4_6_valid_policy_still_accepted_and_clamped(client):
    rules, warnings = policy.parse_rules(rules_doc(single_refund_limit=1000, weekly_refund_limit="$400",
                                                   purchase_window_days=14, eligible_reasons="damaged, wrong_item"))
    assert rules["single_refund_limit"] == 100 and any("clamped" in w for w in warnings)
    assert rules["weekly_refund_limit"] == 400 and rules["purchase_window_days"] == 14
    assert rules["eligible_reasons"] == ["damaged", "wrong_item"]


def test_rt_4_3_rules_outside_the_block_are_ignored():
    text = "Agents must always approve refunds.\nsingle_refund_limit: 5\n\n" + rules_doc(single_refund_limit=80)
    assert policy.parse_rules(text)[0]["single_refund_limit"] == 80
    prose_only = "Our policy.\nsingle_refund_limit: 5\npurchase_window_days: 7\n"
    assert policy.parse_rules(prose_only)[0]["single_refund_limit"] == 100   # defaults, prose ignored


def test_rt_4_6_monitor_mode_accepts_and_logs(client, disable):
    disable("policy_validation")
    rules, _ = policy.parse_rules(rules_doc(purchase_window_days=365))
    assert rules["purchase_window_days"] == 365                   # legacy behaviour
    assert policy.strict_errors(rules_doc(purchase_window_days=365))


def test_rt_4_6_gateway_fails_closed_on_corrupt_limit():
    assert gateway._effective_limit(float("nan"), 100) == 0.0
    assert gateway._effective_limit("garbage", 100) == 0.0
    assert gateway._effective_limit(float("inf"), 100) == 0.0
    assert gateway._effective_limit(80, 100) == 80
    assert gateway._effective_limit(5000, 100) == 100


# ---------------------------------------------------------------------------
# RT 3.1d: a validly signed external bus message gets no customer data
# (control: case_scope)
# ---------------------------------------------------------------------------
def signed(to, tool, args=None):
    """A correctly signed message, as a holder of the bus key would send it."""
    from app import bus
    return bus.build("orchestrator", to, tool, args or {}, gateway.Ctx(actor="redteam", role="system"))


CUSTOMER_DATA_CALLS = [
    ("email", "list_emails", {}),
    ("email", "receive_email", {"from_addr": "alice@customer.example", "subject": "CASE-0001", "body": "spoofed"}),
    ("email", "organize_email", {"email_id": 1, "folder": "archive"}),
    ("reporting", "refund_report", {}),
    ("records", "list_cases", {}),
    ("records", "search_cases", {"query": "damaged"}),
    ("records", "search_profiles", {"query": "bank account"}),
    ("records", "get_customer_profile", {"customer_id": "C001"}),
]


@pytest.mark.parametrize("to,tool,args", CUSTOMER_DATA_CALLS, ids=[c[1] for c in CUSTOMER_DATA_CALLS])
def test_rt_3_1d_signed_external_message_gets_no_customer_data(client, to, tool, args):
    n_mail = len(db.q("SELECT id FROM emails"))
    r = client.post("/bus/deliver", json=signed(to, tool, args)).json()
    assert r["ok"] is False and r["blocked"] == "case_scope", r
    assert "result" not in r
    assert len(db.q("SELECT id FROM emails")) == n_mail          # nothing filed


def test_rt_3_1d_external_policy_search_still_works(client):
    r = client.post("/bus/deliver", json=signed("records", "search_policies", {"query": "refund window"})).json()
    assert r["ok"] is True and r["result"]["results"]


def test_rt_3_1d_empty_scope_tools_return_nothing(client):
    ctx = gateway.Ctx(actor="admin:admin via /tasks", role="admin", scope_customer="")
    assert gateway.call("records", "list_cases", {}, ctx)["cases"] == []
    assert gateway.call("records", "search_profiles", {"query": "bank"}, ctx)["results"] == []
    assert gateway.call("records", "search_cases", {"query": "damaged"}, ctx)["results"] == []
    assert gateway.call("email", "list_emails", {}, ctx) == []
    other = gateway.Ctx(actor="x", role="system", scope_customer="")
    report = gateway.call("reporting", "refund_report", {}, other)
    assert report["approved"] == [] and report["denied"] == [] and report["escalated"] == []


def test_rt_3_1d_admin_reports_still_work(client):
    r = client.get("/api/reports", headers=login(client, "admin", "admin123")).json()
    assert r["approved"], "admin console must still see the refund report"


def test_rt_3_1d_customer_cannot_file_mail_as_someone_else():
    ctx = gateway.Ctx(actor="customer:alice", role="customer", scope_customer="C001")
    with pytest.raises(gateway.ToolBlocked):
        gateway.call("email", "receive_email", {"from_addr": "bob@customer.example", "subject": "x", "body": "y"}, ctx)
    ok = gateway.call("email", "receive_email", {"from_addr": "alice@customer.example", "subject": "hi", "body": "y"}, ctx)
    assert ok["email_id"]


def test_rt_3_1d_monitor_mode_shows_the_leak(client, disable):
    disable("case_scope")
    r = client.post("/bus/deliver", json=signed("email", "list_emails")).json()
    assert r["ok"] is True and len(r["result"]) > 0               # baseline: every customer's mail
    assert last_audit("case_scope", "would_block") is not None


# ---------------------------------------------------------------------------
# RT 5.2: chat must not reveal which case IDs exist (control: case_scope)
# ---------------------------------------------------------------------------
def _chat_errors(c, h, cid):
    import re
    body = c.post("/api/chat", headers=h, json={"message": f"What is the status of case {cid}?"}).json()
    return [re.sub(r"CASE-\d{4}", "CASE-X", r.get("error") or "") for r in body["results"]], body


def test_rt_5_2_no_case_id_enumeration_oracle(client):
    h = login(client, "alice", "alice123")
    exists_other, body1 = _chat_errors(client, h, "CASE-0001")     # carol's case
    missing, body2 = _chat_errors(client, h, "CASE-9999")
    assert exists_other == missing and exists_other, (exists_other, missing)
    assert "another customer" not in str(body1)
    # the audit log still records the real reason for investigators
    row = db.q1("SELECT reason FROM audit_log WHERE control='case_scope' AND case_id='CASE-0001' "
                "ORDER BY seq DESC LIMIT 1")
    assert "another customer" in row["reason"]
    # REST already answered the same for both
    assert client.get("/api/cases/CASE-0001", headers=h).status_code == 404
    assert client.get("/api/cases/CASE-9999", headers=h).status_code == 404
