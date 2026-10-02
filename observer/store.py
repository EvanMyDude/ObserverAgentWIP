"""SQLite storage. One file, owner-only permissions, schema versioned via user_version."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 3
# Statements that bring a database from version N-1 to N. Fresh databases get SCHEMA directly.
MIGRATIONS = {
    2: ["ALTER TABLE sessions ADD COLUMN surface TEXT"],
    3: ["CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"],
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    kind TEXT NOT NULL,              -- transcript | spool
    size INTEGER NOT NULL DEFAULT 0,
    mtime REAL NOT NULL DEFAULT 0,
    offset INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    cwd TEXT,
    entrypoint TEXT,
    version TEXT,
    git_branch TEXT,
    permission_mode TEXT,
    surface TEXT,                    -- cli | cowork
    first_ts TEXT,
    last_ts TEXT,
    internal INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tool_calls (
    tool_use_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    agent_id TEXT,                   -- NULL for the main thread
    agent_type TEXT,                 -- subagent type, from meta.json or attributionAgent
    skill TEXT,                      -- attributionSkill: the skill active at the time
    ts TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    input_json TEXT,
    input_key TEXT,                  -- stable key used to join hook events
    result_ts TEXT,
    outcome TEXT NOT NULL DEFAULT 'pending',   -- ok | error | rejected | denied | pending
    error_class TEXT,
    result_excerpt TEXT
);
CREATE INDEX IF NOT EXISTS tool_calls_session ON tool_calls(session_id, ts);
CREATE INDEX IF NOT EXISTS tool_calls_ts ON tool_calls(ts);
CREATE TABLE IF NOT EXISTS messages (
    uuid TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    agent_id TEXT,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,              -- human | assistant | interrupt | command | compaction | api_error
    skill TEXT,
    text TEXT
);
CREATE INDEX IF NOT EXISTS messages_session ON messages(session_id, ts);
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    session_id TEXT,
    agent_id TEXT,
    ts TEXT,
    model TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_creation_tokens INTEGER
);
CREATE TABLE IF NOT EXISTS skill_paths (
    skill TEXT PRIMARY KEY,
    path TEXT
);
CREATE TABLE IF NOT EXISTS hook_events (
    id TEXT PRIMARY KEY,             -- hash of the raw line
    ts TEXT NOT NULL,
    event TEXT NOT NULL,
    session_id TEXT,
    cwd TEXT,
    tool_name TEXT,
    input_key TEXT,
    payload_json TEXT
);
CREATE INDEX IF NOT EXISTS hook_events_session ON hook_events(session_id, ts);
CREATE TABLE IF NOT EXISTS frictions (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    session_id TEXT,
    project TEXT,
    agent_key TEXT,                  -- main | skill:<name> | agent:<type>
    kind TEXT NOT NULL,
    subkind TEXT,
    fingerprint TEXT NOT NULL,
    tool_name TEXT,
    detail TEXT,
    evidence_ref TEXT,               -- tool_use_id, message uuid, or hook event id
    cost_seconds REAL NOT NULL DEFAULT 0,
    meta_json TEXT
);
CREATE INDEX IF NOT EXISTS frictions_ts ON frictions(ts);
CREATE INDEX IF NOT EXISTS frictions_fp ON frictions(kind, fingerprint);
CREATE TABLE IF NOT EXISTS recommendations (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    rationale TEXT,
    patch_json TEXT,
    verify TEXT,
    risk TEXT,
    confidence REAL,
    impact_minutes_week REAL,
    evidence_json TEXT,
    fingerprints_json TEXT,          -- friction (kind, fingerprint) pairs this targets
    source TEXT,                     -- rule | judge
    status TEXT NOT NULL DEFAULT 'open',
    status_reason TEXT,
    first_seen TEXT,
    last_seen TEXT,
    applied_at TEXT,
    baseline_per_day REAL,
    after_per_day REAL,
    dismissed_at TEXT,
    dismissed_evidence INTEGER
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT NOT NULL,
    finished TEXT,
    window_start TEXT,
    window_end TEXT,
    stats_json TEXT,
    judge_status TEXT,
    report_path TEXT
);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    new = not path.exists()
    conn = sqlite3.connect(str(path))
    if new:
        os.chmod(path, 0o600)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 0:
        conn.executescript(SCHEMA)
    else:
        for step in range(version + 1, SCHEMA_VERSION + 1):
            for statement in MIGRATIONS.get(step, []):
                conn.execute(statement)
    if version < SCHEMA_VERSION:
        conn.execute("PRAGMA user_version=%d" % SCHEMA_VERSION)
        conn.commit()
    return conn


def dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def loads(text, default=None):
    if text is None:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default
