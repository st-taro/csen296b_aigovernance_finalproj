"""Pluggable LLM layer.

Every LLM call in the app goes through `complete_json(purpose, system, prompt,
payload)`. Real providers get `system` + `prompt`; the offline mock model uses
the structured `payload` to produce a deterministic answer.

Providers (LLM_PROVIDER):
  mock       offline, deterministic, no key. "Naive" by default: it follows
             instructions embedded in customer text, like a hijacked model.
  anthropic  Claude via the official `anthropic` SDK.
  openai     any OpenAI-compatible /chat/completions endpoint (OpenAI, Ollama,
             LM Studio) via plain HTTP.
"""
import json
import os
import re
import time

from app import config

# Every call is recorded here (bounded) for observability / evidence.
CALL_LOG = []


class LLMError(RuntimeError):
    pass


def _extract_json(text: str):
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1)
    start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=-1)
    if start < 0:
        raise ValueError("no JSON object in model output")
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unterminated JSON in model output")


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------
class AnthropicProvider:
    name = "anthropic"

    def __init__(self):
        try:
            import anthropic
        except ImportError as e:
            raise LLMError("LLM_PROVIDER=anthropic needs `pip install anthropic`") from e
        self.anthropic = anthropic
        self.client = anthropic.Anthropic(timeout=config.LLM_TIMEOUT)
        self.model = config.LLM_MODEL or "claude-opus-5-5"
        self.use_fallbacks = True

    def complete(self, system: str, prompt: str, max_tokens: int = 4000) -> str:
        kwargs = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            # Sent via extra_body so older SDK versions without the typed param still work.
            extra_body={"output_config": {"effort": os.environ.get("LLM_EFFORT", "low")}},
        )
        if self.use_fallbacks:
            # Server-side refusal fallback (routes a refused request to another model).
            kwargs["extra_headers"] = {"anthropic-beta": "server-side-fallback-2026-07-01"}
            kwargs["extra_body"] = {**kwargs["extra_body"], "fallbacks": "default"}
        try:
            resp = self.client.messages.create(**kwargs)
        except self.anthropic.BadRequestError:
            if not self.use_fallbacks:
                raise
            # Older model / account without the fallback beta: retry without it.
            self.use_fallbacks = False
            kwargs.pop("extra_headers", None)
            kwargs["extra_body"].pop("fallbacks", None)
            resp = self.client.messages.create(**kwargs)
        if resp.stop_reason == "refusal":
            raise LLMError("model refused the request")
        return "".join(b.text for b in resp.content if b.type == "text")


class OpenAICompatProvider:
    name = "openai"

    def __init__(self):
        import requests
        self.requests = requests
        self.base = config.LLM_BASE_URL.rstrip("/")
        self.model = config.LLM_MODEL or self._first_model() or "gpt-4o-mini"

    def _first_model(self):
        """Local servers (LM Studio, Ollama): use the first loaded model if LLM_MODEL is unset."""
        try:
            headers = {"Authorization": f"Bearer {config.LLM_API_KEY}"} if config.LLM_API_KEY else {}
            r = self.requests.get(f"{self.base}/models", headers=headers, timeout=10)
            models = [m["id"] for m in r.json().get("data", []) if "embed" not in m["id"].lower()]
            return models[0] if models else None
        except Exception:
            return None

    def complete(self, system: str, prompt: str, max_tokens: int = 4000) -> str:
        headers = {"Content-Type": "application/json"}
        if config.LLM_API_KEY:
            headers["Authorization"] = f"Bearer {config.LLM_API_KEY}"
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": 0,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": prompt}]}
        r = self.requests.post(f"{self.base}/chat/completions", json=body, headers=headers,
                               timeout=config.LLM_TIMEOUT)
        if r.status_code >= 400:
            raise LLMError(f"LLM HTTP {r.status_code}: {r.text[:300]}")
        return r.json()["choices"][0]["message"]["content"]


class MockProvider:
    """Deterministic stand-in for an LLM. Uses the structured payload."""
    name = "mock"

    def complete(self, system, prompt, max_tokens=4000):  # pragma: no cover
        return "{}"

    def complete_json(self, purpose: str, payload: dict) -> dict:
        fn = getattr(self, f"_{purpose}", None)
        return fn(payload) if fn else {}

    # -- orchestrator -------------------------------------------------------
    def _plan(self, p):
        msg = p["message"]
        low = msg.lower()
        steps = []
        case_ids = re.findall(r"case-\d{4}", low)
        orders = re.findall(r"ord-\d{4}", low)
        naive = config.LLM_MOCK_NAIVE

        if naive and re.search(r"(export|dump|list|show|reveal).{0,30}(all|every|other).{0,15}(customer|record|account|profile)", low):
            steps.append({"task": "Export all customer records as requested", "intent": "export_all_records", "args": {}})
        if naive and re.search(r"(grant|give|elevate|change).{0,40}(permission|access|admin|privilege|limit)", low):
            steps.append({"task": "Change agent permissions as requested", "intent": "change_permissions",
                          "args": {"request": msg[:200]}})
        m_amt = re.search(r"\$\s?(\d+(?:\.\d{1,2})?)", msg)
        if naive and re.search(r"(issue|send|give|transfer).{0,30}refund|refund me", low) and m_amt and not orders:
            steps.append({"task": "Issue the refund the user asked for", "intent": "issue_refund_direct",
                          "args": {"amount": float(m_amt.group(1)),
                                   "case_id": case_ids[0].upper() if case_ids else None}})
        if orders and re.search(r"refund|return|damaged|broken|never (arrived|came)|wrong|charged twice", low):
            reason = ("damaged" if re.search(r"damag|broken|crack", low) else
                      "not_delivered" if re.search(r"never|not deliver|didn.?t (arrive|come)|missing", low) else
                      "wrong_item" if "wrong" in low else
                      "duplicate_charge" if re.search(r"twice|duplicate|double", low) else "other")
            steps.append({"task": f"Create a refund case for {orders[0].upper()}", "intent": "submit_refund",
                          "args": {"order_id": orders[0].upper(),
                                   "amount": float(m_amt.group(1)) if m_amt else None,
                                   "reason": reason, "description": msg}})
        for cid in case_ids:
            if re.search(r"process|decide|run|re-?evaluate", low) and p["role"] != "customer":
                steps.append({"task": f"Process {cid.upper()}", "intent": "process_case", "args": {"case_id": cid.upper()}})
            else:
                steps.append({"task": f"Look up status of {cid.upper()}", "intent": "case_status",
                              "args": {"case_id": cid.upper()}})
        if re.search(r"my cases|my requests|my refunds", low):
            steps.append({"task": "List the customer's cases", "intent": "list_my_cases", "args": {}})
        if re.search(r"(bank|balance|profile|account details|my info)", low) and not steps:
            target = re.search(r"\bc\d{3}\b", low)
            steps.append({"task": "Retrieve customer profile", "intent": "customer_profile",
                          "args": {"customer_id": target.group(0).upper() if target else None}})
        if re.search(r"report|approved|denied|weekly total|how much.*(refund|week)", low):
            steps.append({"task": "Build the refund report", "intent": "refund_report", "args": {}})
        if re.search(r"policy|rule|window|limit|eligible|how (long|many|much)", low) and not any(
                s["intent"] == "refund_report" for s in steps):
            steps.append({"task": "Search the refund policy", "intent": "search_policy", "args": {"query": msg}})
        if re.search(r"search cases|similar cases|find cases", low):
            steps.append({"task": "Search case files", "intent": "search_cases", "args": {"query": msg}})
        if not steps:
            steps.append({"task": "Answer the question from policy context", "intent": "search_policy",
                          "args": {"query": msg}})
        return {"steps": steps, "reasoning": "keyword planner (mock)"}

    def _route(self, p):
        table = {
            "submit_refund": "intake", "assign_case": "intake",
            "case_status": "records", "list_my_cases": "records", "customer_profile": "records",
            "search_policy": "records", "search_cases": "records", "export_all_records": "records",
            "issue_refund_direct": "refunds", "process_case": "refunds", "decide_refund": "refunds",
            "refund_report": "reporting", "weekly_total": "reporting",
            "send_email": "email", "read_email": "email",
            "change_permissions": "records",
        }
        return {"agent": table.get(p["intent"], "records"), "why": "intent table (mock)"}

    def _aggregate(self, p):
        parts = []
        for r in p["results"]:
            if r.get("error"):
                parts.append(f"- {r['task']}: could not be completed ({r['error']}).")
            else:
                parts.append(f"- {r['task']}: {r.get('summary') or 'done'}")
        return {"answer": "Here is what I found:\n" + "\n".join(parts)}

    # -- refunds agent ------------------------------------------------------
    def _refund_recommendation(self, p):
        case = p["case"]
        desc = case.get("description", "")
        low = desc.lower()
        if config.LLM_MOCK_NAIVE:
            hijack = re.search(r"(ignore|disregard|override|new instruction|system|you are now|approve)", low)
            amt = re.search(r"\$\s?(\d+(?:\.\d{1,2})?)", desc)
            if hijack and re.search(r"approve|refund|issue", low):
                amount = float(amt.group(1)) if amt else float(case["amount"])
                return {"decision": "approve", "amount": amount,
                        "reason": "Customer instructions indicate this refund is pre-approved.",
                        "rule": "customer_instruction"}
        # Otherwise mirror a reasonable reading of the policy.
        ev = p.get("policy_hint") or {}
        decision = ev.get("result", "escalate")
        return {"decision": decision, "amount": float(case["amount"]),
                "reason": ev.get("reason", "Needs review."), "rule": ev.get("rule", "unknown")}

    # -- email agent --------------------------------------------------------
    def _email_draft(self, p):
        kind, case = p["kind"], p["case"]
        name = p.get("customer_name", "Customer")
        out = {}
        if kind == "ack":
            out = {"subject": f"[{case['id']}] We received your refund request",
                   "body": (f"Hi {name},\n\nThanks for contacting Refund Me Maybe. We received your refund request "
                            f"for order {case['order_id']} (${float(case['amount']):.2f}). Your case ID is {case['id']}. "
                            "We'll email you again once a decision is made.\n\n- Refund Me Maybe Support")}
        else:
            decision = p["decision"]
            verb = {"approved": "has been approved", "denied": "has been denied",
                    "escalated": "has been sent to a supervisor for review",
                    "returned": "needs more information"}.get(decision, f"is {decision}")
            extra = (f" A refund of ${float(p.get('amount') or case['amount']):.2f} has been added to your account balance."
                     if decision == "approved" else "")
            out = {"subject": f"[{case['id']}] Update on your refund request",
                   "body": (f"Hi {name},\n\nYour refund request for order {case['order_id']} {verb}.{extra}\n\n"
                            f"Reason: {p.get('reason', '')}\n\n- Refund Me Maybe Support")}
        if config.LLM_MOCK_NAIVE:
            m = re.search(r"(?:send|forward|cc|copy)[^.\n]{0,40}?([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})",
                          case.get("description", ""), re.I)
            if m:
                out["to"] = m.group(1)
        return out

    def _email_triage(self, p):
        body = (p["subject"] + " " + p["body"]).lower()
        cid = re.search(r"case-\d{4}", body)
        folder = "case-correspondence" if cid else "general"
        if p.get("injection_flagged"):
            folder = "suspicious"
        intent = ("status" if "status" in body else "complaint" if re.search(r"angry|unacceptable|complain", body)
                  else "refund_request" if "refund" in body else "other")
        return {"folder": folder, "case_id": cid.group(0).upper() if cid else None, "intent": intent,
                "summary": p["body"][:160]}

    def _answer(self, p):
        ctx = p.get("context") or []
        if not ctx:
            return {"answer": "I couldn't find anything relevant in the policy documents."}
        best = ctx[0]["text"]
        return {"answer": "From the active refund policy:\n\n" + best[:600]}


_provider = None


def provider():
    global _provider
    if _provider is None:
        if config.LLM_PROVIDER == "anthropic":
            _provider = AnthropicProvider()
        elif config.LLM_PROVIDER in ("openai", "ollama", "lmstudio"):
            _provider = OpenAICompatProvider()
        else:
            _provider = MockProvider()
    return _provider


def complete_json(purpose: str, system: str, prompt: str, payload: dict, default: dict = None) -> dict:
    """Call the model and parse a JSON object from its reply. Never raises:
    on failure returns `default` (plus an `_error` key) so callers fall back to
    deterministic behaviour."""
    p = provider()
    started = time.time()
    entry = {"purpose": purpose, "provider": p.name, "ts": started}
    try:
        if isinstance(p, MockProvider):
            out = p.complete_json(purpose, payload)
        else:
            text = p.complete(system, prompt + "\n\nRespond with a single JSON object only.")
            entry["raw"] = text[:2000]
            out = _extract_json(text)
            if not isinstance(out, dict):
                out = {"value": out}
        entry["ok"] = True
    except Exception as e:  # network errors, refusals, bad JSON
        out = dict(default or {})
        out["_error"] = f"{type(e).__name__}: {e}"[:300]
        entry["ok"] = False
        entry["error"] = out["_error"]
    entry["ms"] = int((time.time() - started) * 1000)
    entry["output"] = out
    CALL_LOG.append(entry)
    del CALL_LOG[:-200]
    return out
