"""VulnForge SQLite database layer — hooks, findings, tasks, audit_trials, event_log."""

import sqlite3
import json
import hashlib
import os
import time
from pathlib import Path

DB_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DB_DIR / "vulnforge.db"

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS hooks (
    hook_id       TEXT PRIMARY KEY,
    file_path     TEXT NOT NULL,
    func_name     TEXT NOT NULL,
    hook_type     TEXT NOT NULL,          -- 'dangerous_call','route_entry','input_source','auth_bypass_pattern',...
    language      TEXT NOT NULL DEFAULT 'unknown',
    severity      TEXT NOT NULL DEFAULT 'info',  -- 'info','low','medium','high','critical'
    line_start    INTEGER,
    line_end      INTEGER,
    snippet       TEXT,                   -- code snippet around the hook point
    metadata      TEXT DEFAULT '{}',      -- JSON blob: {framework, route_path, http_method, params, ...}
    status        TEXT NOT NULL DEFAULT 'pending', -- 'pending','analyzing','verified','false_positive','dismissed'
    confidence    REAL NOT NULL DEFAULT 0.0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id     TEXT PRIMARY KEY,
    hook_id        TEXT,
    agent_id       TEXT NOT NULL DEFAULT 'unknown',
    severity       TEXT NOT NULL DEFAULT 'info',
    title          TEXT NOT NULL,
    description    TEXT,
    poc_code       TEXT,
    cwe_id         TEXT,
    cvss_score     REAL,
    verdict        TEXT NOT NULL DEFAULT 'unverified',  -- 'unverified','true_positive','false_positive','needs_review'
    confidence     REAL NOT NULL DEFAULT 0.0,         -- LLM's own confidence (0-1)
    final_score    REAL NOT NULL DEFAULT 0.0,         -- composite score from multi-layer defense (0-100)
    raw_response   TEXT,                  -- full LLM response for audit trail
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (hook_id) REFERENCES hooks(hook_id)
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id        TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL,
    hook_id        TEXT,
    finding_id     TEXT,
    task_type      TEXT NOT NULL,         -- 'analyze_hook','verify_finding','cross_check','courtroom_defend',...
    status         TEXT NOT NULL DEFAULT 'queued', -- 'queued','running','completed','failed'
    priority       INTEGER NOT NULL DEFAULT 0,
    context_window_id TEXT,
    result_summary TEXT,
    token_used     INTEGER DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    started_at     TEXT,
    completed_at   TEXT,
    FOREIGN KEY (hook_id) REFERENCES hooks(hook_id),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS audit_trials (
    trial_id        TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL,
    round_number    INTEGER NOT NULL DEFAULT 1,
    prosecutor_view TEXT,
    defender_view   TEXT,
    judge_summary   TEXT,
    jury_verdict    TEXT,                 -- 'valid','invalid','partially_valid'
    jury_score      REAL DEFAULT 0.0,
    jury_reasoning  TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS token_usage (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name        TEXT NOT NULL,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    timestamp         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vulnerability_patterns (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type      TEXT NOT NULL,          -- 'sql_injection','xss','command_injection','path_traversal','auth_bypass',...
    cwe_id            TEXT NOT NULL,          -- 'CWE-89','CWE-79','CWE-78','CWE-22','CWE-862',...
    code_signature    TEXT NOT NULL,          -- regex pattern for code-level matching
    vulnerable_snippet TEXT NOT NULL,         -- example vulnerable code
    fix_snippet       TEXT,                   -- recommended fix code
    detection_rule    TEXT,                   -- AST-level or composite detection pattern
    source_project    TEXT,                   -- which project this pattern was discovered from
    discovered_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS event_log (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL DEFAULT (datetime('now')),
    agent_id     TEXT,
    action       TEXT NOT NULL,           -- 'hook_created','finding_reported','task_started','verdict_reached',...
    entity_type  TEXT,                    -- 'hook','finding','task','trial'
    entity_id    TEXT,
    detail       TEXT,
    hash_chain   TEXT                    -- SHA-256 linking to previous event
);

CREATE INDEX IF NOT EXISTS idx_hooks_status ON hooks(status);
CREATE INDEX IF NOT EXISTS idx_hooks_type ON hooks(hook_type);
CREATE INDEX IF NOT EXISTS idx_hooks_file ON hooks(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(agent_id);
CREATE INDEX IF NOT EXISTS idx_event_log_entity ON event_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_vuln_patterns_cwe ON vulnerability_patterns(cwe_id);
CREATE INDEX IF NOT EXISTS idx_vuln_patterns_type ON vulnerability_patterns(pattern_type);
"""


def _hash_event(prev_hash: str, action: str, entity_id: str, timestamp: str) -> str:
    payload = f"{prev_hash}|{action}|{entity_id}|{timestamp}"
    return hashlib.sha256(payload.encode()).hexdigest()


class Database:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_event_hash = "0" * 64

    def init_schema(self) -> "Database":
        with sqlite3.connect(str(self.path)) as conn:
            conn.executescript(SCHEMA_SQL)
        return self

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def log_event(self, action: str, agent_id: str = "system",
                  entity_type: str | None = None, entity_id: str | None = None,
                  detail: str | None = None) -> int:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._last_event_hash = _hash_event(self._last_event_hash, action, entity_id or "", ts)
        with self.connect() as conn:
            cur = conn.execute(
                """INSERT INTO event_log (timestamp, agent_id, action, entity_type, entity_id, detail, hash_chain)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ts, agent_id, action, entity_type, entity_id, detail, self._last_event_hash)
            )
            return cur.lastrowid

    # -- hooks CRUD --
    def insert_hook(self, **kwargs) -> str:
        hook_id = kwargs.pop("hook_id", None) or hashlib.sha256(
            f"{kwargs.get('file_path')}:{kwargs.get('func_name')}:{kwargs.get('line_start')}".encode()
        ).hexdigest()[:16]
        kwargs["hook_id"] = hook_id
        kwargs.setdefault("metadata", "{}")
        if isinstance(kwargs.get("metadata"), dict):
            kwargs["metadata"] = json.dumps(kwargs["metadata"], ensure_ascii=False)
        columns = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?"] * len(kwargs))
        with self.connect() as conn:
            conn.execute(f"INSERT OR REPLACE INTO hooks ({columns}) VALUES ({placeholders})", list(kwargs.values()))
        self.log_event("hook_created", entity_type="hook", entity_id=hook_id)
        return hook_id

    def list_hooks(self, status: str | None = None, hook_type: str | None = None) -> list[dict]:
        query = "SELECT * FROM hooks WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if hook_type:
            query += " AND hook_type = ?"
            params.append(hook_type)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_hook_status(self, hook_id: str, status: str, confidence: float | None = None):
        with self.connect() as conn:
            if confidence is not None:
                conn.execute("UPDATE hooks SET status=?, confidence=?, updated_at=datetime('now') WHERE hook_id=?",
                             (status, confidence, hook_id))
            else:
                conn.execute("UPDATE hooks SET status=?, updated_at=datetime('now') WHERE hook_id=?",
                             (status, hook_id))

    # -- findings CRUD --
    def insert_finding(self, **kwargs) -> str:
        finding_id = kwargs.pop("finding_id", None) or f"FIND-{hashlib.sha256(str(kwargs).encode()).hexdigest()[:12]}"
        kwargs["finding_id"] = finding_id
        columns = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?"] * len(kwargs))
        with self.connect() as conn:
            conn.execute(f"INSERT OR REPLACE INTO findings ({columns}) VALUES ({placeholders})", list(kwargs.values()))
        self.log_event("finding_reported", entity_type="finding", entity_id=finding_id)
        return finding_id

    def list_findings(self, verdict: str | None = None) -> list[dict]:
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # -- tasks CRUD --
    def create_task(self, **kwargs) -> str:
        task_id = kwargs.pop("task_id", None) or f"TASK-{int(time.time()*1000)}-{hashlib.sha256(str(kwargs).encode()).hexdigest()[:6]}"
        kwargs["task_id"] = task_id
        columns = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?"] * len(kwargs))
        with self.connect() as conn:
            conn.execute(f"INSERT OR REPLACE INTO tasks ({columns}) VALUES ({placeholders})", list(kwargs.values()))
        self.log_event("task_started", entity_type="task", entity_id=task_id)
        return task_id

    def update_task(self, task_id: str, **kwargs):
        if not kwargs:
            return
        set_clause = ", ".join(f"{k}=?" for k in kwargs)
        with self.connect() as conn:
            conn.execute(f"UPDATE tasks SET {set_clause} WHERE task_id=?", list(kwargs.values()) + [task_id])

    def list_tasks(self, status: str | None = None) -> list[dict]:
        query = "SELECT * FROM tasks WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # -- audit_trials CRUD --
    def insert_trial(self, **kwargs) -> str:
        trial_id = kwargs.pop("trial_id", None) or f"TRIAL-{kwargs['finding_id']}-R{kwargs.get('round_number',1)}"
        kwargs["trial_id"] = trial_id
        columns = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?"] * len(kwargs))
        with self.connect() as conn:
            conn.execute(f"INSERT OR REPLACE INTO audit_trials ({columns}) VALUES ({placeholders})", list(kwargs.values()))
        self.log_event("verdict_reached", entity_type="trial", entity_id=trial_id)
        return trial_id

    # -- stats --
    def stats(self) -> dict:
        with self.connect() as conn:
            return {
                "hooks_total": conn.execute("SELECT COUNT(*) FROM hooks").fetchone()[0],
                "hooks_pending": conn.execute("SELECT COUNT(*) FROM hooks WHERE status='pending'").fetchone()[0],
                "findings_total": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                "findings_true_positive": conn.execute("SELECT COUNT(*) FROM findings WHERE verdict='true_positive'").fetchone()[0],
                "tasks_queued": conn.execute("SELECT COUNT(*) FROM tasks WHERE status='queued'").fetchone()[0],
                "tasks_running": conn.execute("SELECT COUNT(*) FROM tasks WHERE status='running'").fetchone()[0],
                "events_logged": conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0],
            }


    # -- token usage --
    def insert_token_usage(self, agent_name: str, prompt_tokens: int,
                           completion_tokens: int) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO token_usage (agent_name, prompt_tokens, completion_tokens)"
                " VALUES (?, ?, ?)",
                (agent_name, prompt_tokens, completion_tokens),
            )
        return cur.lastrowid

    def get_total_usage(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT agent_name, SUM(prompt_tokens) AS total_prompt,"
                " SUM(completion_tokens) AS total_completion"
                " FROM token_usage GROUP BY agent_name"
                " ORDER BY total_prompt DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_hook_count(self) -> int:
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM hooks").fetchone()[0]

    def get_finding_count(self) -> int:
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    # -- vulnerability_patterns CRUD --
    def insert_pattern(self, **kwargs) -> int:
        """Insert a vulnerability pattern. Returns the auto-increment id."""
        columns = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?"] * len(kwargs))
        with self.connect() as conn:
            cur = conn.execute(
                f"INSERT INTO vulnerability_patterns ({columns}) VALUES ({placeholders})",
                list(kwargs.values()),
            )
        self.log_event("pattern_inserted", entity_type="vulnerability_pattern",
                       entity_id=str(cur.lastrowid))
        return cur.lastrowid

    def list_patterns(self, pattern_type: str | None = None,
                      cwe_id: str | None = None) -> list[dict]:
        """List vulnerability patterns, optionally filtered."""
        query = "SELECT * FROM vulnerability_patterns WHERE 1=1"
        params = []
        if pattern_type:
            query += " AND pattern_type = ?"
            params.append(pattern_type)
        if cwe_id:
            query += " AND cwe_id = ?"
            params.append(cwe_id)
        query += " ORDER BY discovered_at DESC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_pattern_count(self) -> int:
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM vulnerability_patterns").fetchone()[0]

_db: Database | None = None


def get_db(path: Path | None = None) -> Database:
    global _db
    if _db is None:
        _db = Database(path)
        _db.init_schema()
    return _db
