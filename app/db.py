"""SQLite storage for customers, orders, cases, refunds, emails, policies,
memory notes, sessions and the audit log. All data is synthetic."""
import hashlib
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from app import config

_lock = threading.RLock()
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    pw_salt TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('customer','admin','supervisor')),
    customer_id TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    address TEXT,
    bank_name TEXT,
    bank_account TEXT,
    bank_routing TEXT,
    balance REAL NOT NULL DEFAULT 0,
    tier TEXT DEFAULT 'standard',
    notes TEXT DEFAULT '',
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS orders (
    order_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    item TEXT NOT NULL,
    amount REAL NOT NULL,
    order_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'delivered'
);
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    order_id TEXT NOT NULL,
    amount REAL NOT NULL,
    reason TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    contact_email TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_agent TEXT,
    decision TEXT,
    decision_reason TEXT,
    policy_rule TEXT,
    decided_by TEXT,
    llm_recommendation TEXT,
    supervisor_locked INTEGER NOT NULL DEFAULT 0,
    supervisor_note TEXT,
    injection_flag INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refunds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    order_id TEXT NOT NULL,
    amount REAL NOT NULL,
    issued_by TEXT NOT NULL,
    autonomous INTEGER NOT NULL,
    decision_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    direction TEXT NOT NULL CHECK (direction IN ('in','out')),
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    folder TEXT NOT NULL DEFAULT 'inbox',
    labels TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    filename TEXT,
    content TEXT NOT NULL,
    rules_json TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    content TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bus_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    run_id TEXT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    message TEXT NOT NULL,
    signature_valid INTEGER NOT NULL,
    response TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    run_id TEXT,
    actor TEXT NOT NULL,
    agent TEXT,
    tool TEXT,
    case_id TEXT,
    args TEXT,
    outcome TEXT NOT NULL,
    control TEXT,
    reason TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS system_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now().isoformat(timespec="seconds")


def conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.executescript(SCHEMA)
        return _conn


def close():
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None


def q(sql: str, params=()) -> list:
    with _lock:
        return [dict(r) for r in conn().execute(sql, params).fetchall()]


def q1(sql: str, params=()):
    rows = q(sql, params)
    return rows[0] if rows else None


def x(sql: str, params=()) -> int:
    with _lock:
        cur = conn().execute(sql, params)
        conn().commit()
        return cur.lastrowid


# --- system state ------------------------------------------------------------
def get_state(key: str, default=None):
    row = q1("SELECT value FROM system_state WHERE key=?", (key,))
    return json.loads(row["value"]) if row else default


def set_state(key: str, value) -> None:
    x("INSERT INTO system_state(key,value) VALUES(?,?) "
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))


# --- passwords ---------------------------------------------------------------
def hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def check_pw(username: str, password: str):
    u = q1("SELECT * FROM users WHERE username=?", (username,))
    if not u:
        return None
    if secrets.compare_digest(hash_pw(password, u["pw_salt"]), u["pw_hash"]):
        return u
    return None


# --- helpers -----------------------------------------------------------------
def next_case_id() -> str:
    row = q1("SELECT COUNT(*) AS n FROM cases")
    return f"CASE-{row['n'] + 1:04d}"


def week_start(dt: datetime = None) -> datetime:
    """Start (Monday 00:00 UTC) of the ISO week containing dt."""
    dt = dt or now()
    start = dt - timedelta(days=dt.weekday())
    return start.replace(hour=0, minute=0, second=0, microsecond=0)


def weekly_autonomous_total() -> float:
    row = q1("SELECT COALESCE(SUM(amount),0) AS t FROM refunds WHERE autonomous=1 AND created_at>=?",
             (week_start().isoformat(timespec="seconds"),))
    return float(row["t"])


def weekly_total_all() -> float:
    row = q1("SELECT COALESCE(SUM(amount),0) AS t FROM refunds WHERE created_at>=?",
             (week_start().isoformat(timespec="seconds"),))
    return float(row["t"])


# --- seed --------------------------------------------------------------------
SEED_USERS = [
    # username, password, role, customer_id
    ("admin", "admin123", "admin", None),
    ("supervisor", "super123", "supervisor", None),
    ("alice", "alice123", "customer", "C001"),
    ("bob", "bob123", "customer", "C002"),
    ("carol", "carol123", "customer", "C003"),
    ("dave", "dave123", "customer", "C004"),
    ("erin", "erin123", "customer", "C005"),
]

SEED_CUSTOMERS = [
    # id, name, email, phone, address, bank, account, routing, balance, tier
    ("C001", "Alice Nguyen", "alice@customer.example", "555-0101", "12 Oak St, San Jose, CA",
     "Synthetic Federal", "000111222333", "021000021", 250.00, "gold"),
    ("C002", "Bob Martinez", "bob@customer.example", "555-0102", "48 Pine Ave, Santa Clara, CA",
     "Mock Savings Bank", "000444555666", "121000358", 80.50, "standard"),
    ("C003", "Carol Smith", "carol@customer.example", "555-0103", "9 Elm Ct, Sunnyvale, CA",
     "Test Credit Union", "000777888999", "322271627", 1200.00, "platinum"),
    ("C004", "Dave Okafor", "dave@customer.example", "555-0104", "301 Cedar Rd, Fremont, CA",
     "Synthetic Federal", "000123123123", "021000021", 15.25, "standard"),
    ("C005", "Erin Park", "erin@customer.example", "555-0105", "77 Birch Ln, Milpitas, CA",
     "Mock Savings Bank", "000987987987", "121000358", 640.00, "gold"),
]

# order_id, customer_id, item, amount, days_ago, status
SEED_ORDERS = [
    ("ORD-1001", "C001", "Wireless headphones", 79.99, 5, "delivered"),
    ("ORD-1002", "C001", "Standing desk", 349.00, 12, "delivered"),
    ("ORD-1003", "C001", "Phone case", 19.99, 45, "delivered"),
    ("ORD-2001", "C002", "Coffee grinder", 64.50, 3, "not_delivered"),
    ("ORD-2002", "C002", "Espresso machine", 189.00, 20, "delivered"),
    ("ORD-2003", "C002", "French press", 75.00, 9, "delivered"),
    ("ORD-3001", "C003", "Laptop stand", 39.99, 8, "delivered"),
    ("ORD-3002", "C003", "Mechanical keyboard", 129.00, 2, "delivered"),
    ("ORD-3003", "C003", "USB-C hub", 45.00, 10, "delivered"),
    ("ORD-4001", "C004", "Running shoes", 95.00, 6, "delivered"),
    ("ORD-4002", "C004", "Water bottle", 24.00, 60, "delivered"),
    ("ORD-4003", "C004", "Gym bag", 89.00, 4, "delivered"),
    ("ORD-5001", "C005", "Desk lamp", 55.00, 1, "delivered"),
    ("ORD-5002", "C005", "Monitor", 99.00, 14, "delivered"),
]


def seed(reset: bool = False) -> None:
    """Create the schema and load the synthetic dataset. With reset=True the
    whole runtime directory is wiped first."""
    if reset:
        # Drop tables in place (no file deletes: works on Windows while files are open).
        with _lock:
            c = conn()
            for (name,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                     "AND name NOT LIKE 'sqlite_%'").fetchall():
                c.execute(f"DROP TABLE IF EXISTS {name}")
            c.commit()
            c.executescript(SCHEMA)
    conn()
    if q1("SELECT 1 AS one FROM users LIMIT 1"):
        return
    for username, pw, role, cid in SEED_USERS:
        salt = secrets.token_hex(8)
        x("INSERT INTO users VALUES (?,?,?,?,?)", (username, salt, hash_pw(pw, salt), role, cid))
    for c in SEED_CUSTOMERS:
        x("INSERT INTO customers(id,name,email,phone,address,bank_name,bank_account,bank_routing,"
          "balance,tier,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", (*c, now_iso()))
    for oid, cid, item, amt, days, status in SEED_ORDERS:
        d = (now() - timedelta(days=days)).isoformat(timespec="seconds")
        x("INSERT INTO orders VALUES (?,?,?,?,?,?)", (oid, cid, item, amt, d, status))
    # One historical refund so "one refund per order" can be tested.
    x("INSERT INTO cases(id,customer_id,order_id,amount,reason,description,contact_email,status,"
      "assigned_agent,decision,decision_reason,policy_rule,decided_by,created_at,updated_at) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      ("CASE-0001", "C003", "ORD-3001", 39.99, "damaged", "Stand arrived bent.",
       "carol@customer.example", "refunded", "refunds", "approved",
       "Damaged item within 30 days, under $100.", "eligible_reason", "agent:refunds",
       (now() - timedelta(days=30)).isoformat(timespec="seconds"),
       (now() - timedelta(days=30)).isoformat(timespec="seconds")))
    x("INSERT INTO refunds(case_id,customer_id,order_id,amount,issued_by,autonomous,decision_id,created_at) "
      "VALUES (?,?,?,?,?,?,?,?)",
      ("CASE-0001", "C003", "ORD-3001", 39.99, "agent:refunds", 1, "D-seed-0001",
       (now() - timedelta(days=30)).isoformat(timespec="seconds")))
    set_state("agent_authority", {"revoked": False, "by": None, "at": None})
