"""Central configuration, read from environment variables (see .env.example).

Everything here is read once at startup. Agents cannot change these values at
runtime: there is no API that writes them (ASI03 control: an agent cannot raise
its own limits or permissions).
"""
import os
import secrets
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    """Tiny .env loader so we don't need python-dotenv. Existing env vars win."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


ROOT = Path(__file__).resolve().parent.parent
_load_dotenv(ROOT / ".env")


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


# --- Paths -----------------------------------------------------------------
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data" / "runtime"))
SEED_DIR = ROOT / "data" / "seed"
DB_PATH = DATA_DIR / "app.db"
CHROMA_DIR = DATA_DIR / "chroma"
DRIVE_DIR = DATA_DIR / "drive"
LOG_DIR = ROOT / "logs"

# --- LLM -------------------------------------------------------------------
# mock      : deterministic offline model (no key needed). Good for CI and demos.
# anthropic : Claude via the official anthropic SDK (needs ANTHROPIC_API_KEY)
# openai    : any OpenAI-compatible /chat/completions endpoint: OpenAI, Ollama
#             (LLM_BASE_URL=http://localhost:11434/v1), LM Studio
#             (LLM_BASE_URL=http://localhost:1234/v1)
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "mock").lower()
LLM_MODEL = os.environ.get("LLM_MODEL", "")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")
LLM_API_KEY = os.environ.get("LLM_API_KEY", os.environ.get("OPENAI_API_KEY", ""))
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "120"))
# The mock model is "naive" by default: it obeys instructions embedded in
# customer text, the way a jailbroken model would. This lets the red team show
# that the independent controls (gateway, policy engine) still hold even when
# the model is fully hijacked.
LLM_MOCK_NAIVE = _bool("LLM_MOCK_NAIVE", True)

# --- Guardrails ------------------------------------------------------------
# GUARDRAILS=off turns every control below into monitor-only mode ("would_block"
# is logged but the action executes). SANDBOX USE ONLY: it exists so the team
# can produce "functional but insecure" vs "retest with guardrails" benchmark
# evidence (spec Appendix H).
GUARDRAILS = _bool("GUARDRAILS", True)
# Fine-grained switches: comma-separated list of controls to disable.
# Names: input_filter, output_filter, capability, kill_switch, case_scope,
#        email_recipient, single_limit, weekly_limit, order_checks,
#        supervisor_lock, policy_engine, rate_limit, bus_signature
GUARDRAIL_DISABLE = {
    s.strip() for s in os.environ.get("GUARDRAIL_DISABLE", "").split(",") if s.strip()
}


def control_enabled(name: str) -> bool:
    return GUARDRAILS and name not in GUARDRAIL_DISABLE


# --- Organization policy hard limits ---------------------------------------
# These come from the project spec and are enforced by the gateway. An uploaded
# policy document may LOWER them but can never raise them.
HARD_SINGLE_LIMIT = float(os.environ.get("HARD_SINGLE_LIMIT", "100"))
HARD_WEEKLY_LIMIT = float(os.environ.get("HARD_WEEKLY_LIMIT", "500"))

# Max tool calls in one orchestration run (LLM06 Unbounded Consumption)
MAX_TOOL_CALLS_PER_RUN = int(os.environ.get("MAX_TOOL_CALLS_PER_RUN", "30"))
MAX_PLAN_STEPS = int(os.environ.get("MAX_PLAN_STEPS", "8"))
MAX_INPUT_CHARS = int(os.environ.get("MAX_INPUT_CHARS", "4000"))

# HMAC master key for inter-agent bus messages (ASI07). Each sender signs with
# its own key derived from this one (see app/bus.py). If BUS_SECRET is unset or
# still a placeholder from the repo, a random per-process secret is used
# instead: a publicly known key would let anyone sign messages to
# /bus/deliver. Set a real value in .env to sign test messages from outside.
_PLACEHOLDER_BUS_SECRETS = {"", "sandbox-bus-secret-change-me", "change-me-for-your-sandbox"}
_bus_secret = os.environ.get("BUS_SECRET", "").strip()
BUS_SECRET_IS_EPHEMERAL = _bus_secret in _PLACEHOLDER_BUS_SECRETS
BUS_SECRET = secrets.token_hex(32) if BUS_SECRET_IS_EPHEMERAL else _bus_secret
# Bus messages older than this (or this far in the future) are rejected, which
# bounds replays even across restarts, when the in-memory replay cache is empty.
BUS_MAX_AGE_SECONDS = int(os.environ.get("BUS_MAX_AGE_SECONDS", "60"))

# --- Sessions and login (ASI03) ---------------------------------------------
# Sessions expire this long after sign-in.
SESSION_TTL_MINUTES = int(os.environ.get("SESSION_TTL_MINUTES", "480"))
# After this many failed logins for one username within LOGIN_LOCKOUT_MINUTES,
# further attempts are refused until the window passes. 0 disables lockout.
LOGIN_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", "15"))

SUPPORT_EMAIL = "support@refundmemaybe.example"
APP_NAME = "Refund Me Maybe"


def summary() -> dict:
    """Non-secret configuration snapshot shown in the UI and evidence files."""
    return {
        "app": APP_NAME,
        "llm_provider": LLM_PROVIDER,
        "llm_model": LLM_MODEL or "(provider default)",
        "llm_mock_naive": LLM_MOCK_NAIVE if LLM_PROVIDER == "mock" else None,
        "guardrails": GUARDRAILS,
        "guardrail_disable": sorted(GUARDRAIL_DISABLE),
        "hard_single_limit": HARD_SINGLE_LIMIT,
        "hard_weekly_limit": HARD_WEEKLY_LIMIT,
        "max_tool_calls_per_run": MAX_TOOL_CALLS_PER_RUN,
        "session_ttl_minutes": SESSION_TTL_MINUTES,
        "login_max_failures": LOGIN_MAX_FAILURES,
    }
