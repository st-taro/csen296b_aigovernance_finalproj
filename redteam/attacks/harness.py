"""Shared harness for the live-LLM red-team runs (sandbox only).

Observe-and-record: each attack function returns a finding describing what the
system did. Nothing here changes app code or guardrails.

An attack module registers attacks with @attack(...) and each function takes a
Harness `h` and returns finding(...). The harness adds the evidence the
Appendix F assurance dimensions need: request/response data the attack chose to
keep, audit rows since the attack started, and the raw model calls made during it.
"""
import os
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "redteam", "tests"))
import rt_suite  # noqa: E402  (reuses its HTTP / audit helpers; its main() is guarded)

# Outcomes. These describe what was observed, not a pass/fail judgement.
HELD = "HELD"                              # a control blocked it or the case escalated
FILTER_MISSED_BUT_HELD = "FILTER_MISSED_BUT_HELD"  # input filter did not flag, a later control held
EXPLOITED = "EXPLOITED"                    # the harmful action actually happened
LEAK = "LEAK"                              # data or hidden instructions were disclosed
DEGRADED = "DEGRADED"                      # availability / integrity damage (crashes, broken pages, DoS)
INFO = "INFO"                              # reconnaissance / informational
SKIPPED = "SKIPPED"                        # could not run (missing prerequisite)
ERROR = "ERROR"

REGISTRY = []

# Worst-first. With --repeat, one exploited run among many held ones must not be averaged away.
SEVERITY = [EXPLOITED, LEAK, DEGRADED, FILTER_MISSED_BUT_HELD, ERROR, INFO, SKIPPED, HELD]


def attack(id, section, title, pdf_text="", expected="", owasp="", maestro="", disruptive=False, reset=False):
    """Register an attack. `pdf_text` is the attack as written in Red_Team_Attacks.pdf and
    `expected` is what the PDF says should happen."""
    def deco(fn):
        REGISTRY.append({"id": id, "section": section, "title": title, "pdf_text": pdf_text,
                         "expected": expected, "owasp": owasp, "maestro": maestro,
                         "disruptive": disruptive, "reset": reset, "fn": fn})
        return fn
    return deco


def finding(outcome, observed, evidence=None, control="", decision_ids=None):
    return {"outcome": outcome, "observed": observed, "control": control,
            "decision_ids": decision_ids or [], "evidence": evidence or {}}


class Harness:
    """Per-run handle passed to every attack function."""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        rt_suite.BASE = self.base_url
        self.system = {}

    # -- thin wrappers over rt_suite so attacks don't import it directly ------
    def call(self, method, path, user=None, **kw):
        return rt_suite.call(method, path, user, **kw)

    def audit_rows(self, **kw):
        return rt_suite.audit_rows(**kw)

    def head_seq(self):
        return rt_suite.head_seq()

    def refund_for(self, case_id):
        return rt_suite.refund_for(case_id)

    def blocked_controls(self, rows):
        return rt_suite.blocked_controls(rows)

    def reset(self):
        rt_suite.call("POST", "/api/admin/reset-sandbox", "admin")
        rt_suite._tokens.clear()

    def llm_calls_since(self, ts):
        code, calls = self.call("GET", "/api/llm-calls", "supervisor")
        return [c for c in calls if c.get("ts", 0) >= ts] if isinstance(calls, list) else []

    def decision_ids(self, rows):
        return sorted({r["decision_id"] for r in rows if r.get("decision_id")})

    # -- preflight --------------------------------------------------------------
    def preflight(self, allow_mock=False):
        code, info = self.call("GET", "/api/system")
        if code != 200 or not isinstance(info, dict):
            raise SystemExit(f"cannot reach {self.base_url}/api/system (HTTP {code}); is the server running?")
        self.system = info
        if not info.get("guardrails"):
            raise SystemExit("server has guardrails OFF; these runs are for guardrails ON. Restart with GUARDRAILS=on.")
        if info.get("guardrail_disable"):
            raise SystemExit(f"server has individual controls disabled: {info['guardrail_disable']}. "
                             "Clear GUARDRAIL_DISABLE so results reflect all guardrails ON.")
        if info.get("llm_provider") == "mock" and not allow_mock:
            raise SystemExit("server is using the mock LLM. Set LLM_PROVIDER in .env for a live run, "
                             "or pass --allow-mock for a dry run.")
        return info


def run_attack(h, a, repeat=1):
    runs = []
    for i in range(repeat):
        started = time.time()
        seq = None
        try:
            if a.get("reset"):
                h.reset()   # money/state attacks start from a freshly seeded sandbox
            seq = h.head_seq()
            res = a["fn"](h)
        except Exception as e:  # keep going; record the failure
            res = finding(ERROR, f"{type(e).__name__}: {e}")
        res["llm_calls"] = h.llm_calls_since(started)
        if len(res["llm_calls"]) >= 100:
            res["llm_calls_note"] = "the server keeps only its last 100 model calls, so this list is truncated"
        res["audit_since"] = h.audit_rows(since_seq=seq) if seq is not None else []
        res["elapsed_s"] = round(time.time() - started, 2)
        runs.append(res)
    outcomes = [r["outcome"] for r in runs]
    return {"id": a["id"], "section": a["section"], "title": a["title"], "pdf_text": a["pdf_text"],
            "expected": a["expected"], "owasp": a["owasp"], "maestro": a["maestro"],
            "outcome": min(outcomes, key=SEVERITY.index), "outcome_counts": {o: outcomes.count(o) for o in set(outcomes)},
            "runs": runs}


GROUPS = {  # report roll-up, from section 9 of the PDF
    "1": "Model alignment robustness", "2": "Implementation guardrails",
    "3": "System infrastructure", "4": "Implementation guardrails",
    "5": "Implementation guardrails / RAG security", "6": "Implementation guardrails",
    "7": "Runtime / human and agentic interaction", "8": "Runtime / human and agentic interaction",
}


def write_report(out_dir, system, results):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# Live red-team run, {ts}", "",
             f"- LLM: `{system.get('llm_provider')}` / `{system.get('llm_model')}`",
             f"- Guardrails: `{system.get('guardrails')}` (disabled controls: {system.get('guardrail_disable') or 'none'})",
             f"- Attacks run: {len(results)}", "",
             "| ID | Attack | PDF expected | Observed | Outcome | Control |", "|---|---|---|---|---|---|"]
    for r in results:
        last = r["runs"][-1]
        obs = (last["observed"] or "").replace("\n", " ").replace("|", "/")[:160]
        exp = (r["expected"] or "").replace("\n", " ").replace("|", "/")[:100]
        counts = ", ".join(f"{k} x{v}" for k, v in sorted(r["outcome_counts"].items()))
        lines.append(f"| {r['id']} | {r['title']} | {exp} | {obs} | {counts} | {last.get('control') or ''} |")
    gaps = [r for r in results if r["outcome"] in (EXPLOITED, LEAK, DEGRADED, FILTER_MISSED_BUT_HELD)]
    lines += ["", "## Gaps to look at when building guardrails", ""]
    if not gaps:
        lines.append("None observed in this run.")
    for r in gaps:
        lines.append(f"- **{r['id']} {r['title']}**: {r['outcome']}. {r['runs'][-1]['observed']}")
    by_group = {}
    for r in results:
        by_group.setdefault(GROUPS.get(r["section"], "Other"), []).append(r)
    lines += ["", "## By assessment area (PDF section 9)", ""]
    for g, rs in by_group.items():
        lines.append(f"- {g}: " + ", ".join(f"{r['id']}={r['outcome']}" for r in rs))
    with open(os.path.join(out_dir, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
