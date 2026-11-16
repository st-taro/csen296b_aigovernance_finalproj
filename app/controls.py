"""Enforce-or-monitor helper for blue-team controls that live outside the
tool gateway (API boundary checks, policy upload, recon, sandbox reset).

Same contract as the gateway: with the control enabled, a violation is
blocked and audited as `blocked`; with it disabled (GUARDRAILS=off or listed
in GUARDRAIL_DISABLE) the violation is audited as `would_block` and the
action goes ahead. That keeps the before/after (config B / config C)
comparison working for every new control.
"""
from app import audit, config


def violation(control: str, reason: str, actor: str = "system", **kw):
    """Record a violation of `control`. Returns (blocked, decision_id)."""
    if config.control_enabled(control):
        return True, audit.record(actor, "blocked", control=control, reason=reason, **kw)
    return False, audit.record(actor, "would_block", control=control,
                               reason=f"[guardrail disabled] {reason}", **kw)
