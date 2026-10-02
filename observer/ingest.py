"""Incremental, idempotent ingestion of Claude Code transcripts and the hook spool.

Each file is read from the byte offset where the previous run stopped, and only complete lines
are consumed, so a session that is still being written is picked up on the next run. Rows are
keyed by IDs from the source (tool_use_id, record uuid, request id), so re-reading is harmless.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path

from . import classify
from .config import Config
from .redact import excerpt
from .store import dumps

_SKILL_BASE_RE = re.compile(r"Base directory for this skill: (\S+)")
_COMMAND_NAME_RE = re.compile(r"<command-name>\s*/?([^<\s]+)\s*</command-name>")
_SYSTEM_REMINDER_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)
_NON_HUMAN_PREFIXES = (
    "<local-command-stdout>",
    "<local-command-stderr>",
    "<local-command-caveat>",
    "Caveat: The messages below",
    "<task-notification>",
    "<agent-message",
    "<bash-input>",
    "<bash-stdout>",
    "<bash-stderr>",
)
EXCERPT_CHARS = 1200
TEXT_CHARS = 2000


def _trim_input(value, limit: int = 600):
    """Keep tool inputs valid JSON while bounding size and redacting secrets in every string."""
    if isinstance(value, str):
        return excerpt(value, limit)
    if isinstance(value, dict):
        return {k: _trim_input(v, limit) for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        return [_trim_input(v, limit) for v in value[:40]]
    return value


def norm_ts(value) -> str | None:
    """Normalize timestamps to UTC `YYYY-MM-DDTHH:MM:SS.mmmZ` so string order is time order."""
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    parsed = parsed.astimezone(datetime.timezone.utc)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (parsed.microsecond // 1000)


def _read_new_lines(conn: sqlite3.Connection, path: Path, kind: str):
    """Yield complete new lines since the stored offset; commit the new offset after the caller is done."""
    try:
        stat = path.stat()
    except OSError:
        return [], None
    row = conn.execute("SELECT size, mtime, offset FROM files WHERE path=?", (str(path),)).fetchone()
    offset = row["offset"] if row else 0
    if row and row["size"] == stat.st_size and row["mtime"] == stat.st_mtime:
        return [], None
    if stat.st_size < offset:
        offset = 0  # rewritten or truncated: re-read; primary keys keep this idempotent
    with path.open("rb") as fh:
        fh.seek(offset)
        data = fh.read()
    end = data.rfind(b"\n")
    if end < 0:
        return [], (stat, offset)
    chunk = data[: end + 1]
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    return lines, (stat, offset + len(chunk))


def _save_offset(conn, path: Path, kind: str, marker) -> None:
    if marker is None:
        return
    stat, offset = marker
    # Only mark the file unchanged once everything up to its end has been consumed.
    size = stat.st_size if offset == stat.st_size else -1
    conn.execute(
        "INSERT INTO files(path, kind, size, mtime, offset) VALUES(?,?,?,?,?) "
        "ON CONFLICT(path) DO UPDATE SET size=excluded.size, mtime=excluded.mtime, offset=excluded.offset",
        (str(path), kind, size, stat.st_mtime, offset),
    )


class TranscriptIngestor:
    def __init__(self, conn: sqlite3.Connection, cfg: Config):
        self.conn = conn
        self.cfg = cfg
        self.stats = Counter()
        self.unknown_types = Counter()
        self.home = str(cfg.home)

    # ------------------------------------------------------------ discovery

    def transcript_files(self) -> list:
        files = []
        for root in self.cfg.roots():
            if not root.is_dir():
                continue
            files.extend(sorted(root.glob("*/*.jsonl")))
            files.extend(sorted(root.glob("*/*/subagents/agent-*.jsonl")))
        return files

    def run(self) -> Counter:
        for path in self.transcript_files():
            self.ingest_file(path)
        self.stats["unknown_record_types"] = sum(self.unknown_types.values())
        return self.stats

    # ------------------------------------------------------------ per file

    def ingest_file(self, path: Path) -> None:
        lines, marker = _read_new_lines(self.conn, path, "transcript")
        self.stats["files_seen"] += 1
        if not lines and marker is None:
            return
        agent_id = agent_type = None
        if path.parent.name == "subagents":
            agent_id = path.stem[len("agent-"):] if path.stem.startswith("agent-") else path.stem
            meta = path.with_suffix(".meta.json")
            if meta.exists():
                try:
                    agent_type = json.loads(meta.read_text(encoding="utf-8")).get("agentType")
                except (OSError, ValueError):
                    pass
        self.stats["files_read"] += 1
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                self.stats["parse_errors"] += 1
                continue
            if not isinstance(record, dict):
                self.stats["parse_errors"] += 1
                continue
            self.stats["records"] += 1
            try:
                self.ingest_record(record, agent_id, agent_type)
            except Exception:  # one odd record must not stop the run
                self.stats["record_errors"] += 1
        _save_offset(self.conn, path, "transcript", marker)
        self.conn.commit()

    # ------------------------------------------------------------ per record

    def ingest_record(self, rec: dict, agent_id, agent_type) -> None:
        rtype = rec.get("type")
        session_id = rec.get("sessionId")
        ts = norm_ts(rec.get("timestamp"))
        if session_id and ts:
            self._touch_session(rec, session_id, ts)
        if rtype == "assistant":
            self._assistant(rec, session_id, ts, agent_id, agent_type or rec.get("attributionAgent"))
        elif rtype == "user":
            self._user(rec, session_id, ts, agent_id)
        elif rtype == "system":
            if rec.get("subtype") == "compact_boundary" and ts:
                self._message(rec.get("uuid"), session_id, agent_id, ts, "compaction", None, "compact boundary")
            elif rec.get("level") == "error" and ts:
                self._message(rec.get("uuid"), session_id, agent_id, ts, "api_error", None, str(rec.get("content", ""))[:TEXT_CHARS])
        elif rtype in ("attachment", "queue-operation", "last-prompt", "summary", "file-history-snapshot", "atis-latch"):
            pass
        else:
            self.unknown_types[str(rtype)] += 1

    def _touch_session(self, rec: dict, session_id: str, ts: str) -> None:
        cwd = rec.get("cwd")
        internal = 1 if cwd and (cwd == self.home or cwd.startswith(self.home + "/")) else 0
        self.conn.execute(
            """INSERT INTO sessions(session_id, cwd, entrypoint, version, git_branch, permission_mode, first_ts, last_ts, internal)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(session_id) DO UPDATE SET
                 cwd=COALESCE(sessions.cwd, excluded.cwd),
                 entrypoint=COALESCE(sessions.entrypoint, excluded.entrypoint),
                 version=COALESCE(excluded.version, sessions.version),
                 git_branch=COALESCE(excluded.git_branch, sessions.git_branch),
                 permission_mode=COALESCE(excluded.permission_mode, sessions.permission_mode),
                 first_ts=MIN(sessions.first_ts, excluded.first_ts),
                 last_ts=MAX(sessions.last_ts, excluded.last_ts),
                 internal=MAX(sessions.internal, excluded.internal)""",
            (session_id, cwd, rec.get("entrypoint"), rec.get("version"), rec.get("gitBranch"),
             rec.get("permissionMode"), ts, ts, internal),
        )

    def _message(self, uuid, session_id, agent_id, ts, kind, skill, text) -> None:
        if not uuid or not session_id:
            return
        self.conn.execute(
            "INSERT OR IGNORE INTO messages(uuid, session_id, agent_id, ts, kind, skill, text) VALUES(?,?,?,?,?,?,?)",
            (uuid, session_id, agent_id, ts, kind, skill, text),
        )
        self.stats["messages"] += 1

    def _assistant(self, rec, session_id, ts, agent_id, agent_type) -> None:
        msg = rec.get("message") or {}
        skill = rec.get("attributionSkill")
        content = msg.get("content")
        if rec.get("isApiErrorMessage") and ts:
            self._message(rec.get("uuid"), session_id, agent_id, ts, "api_error", skill, classify.result_text(content)[:TEXT_CHARS])
            return
        request_id = rec.get("requestId") or msg.get("id")
        usage = msg.get("usage") or {}
        if request_id and usage:
            self.conn.execute(
                "INSERT OR IGNORE INTO requests(request_id, session_id, agent_id, ts, model, input_tokens, output_tokens, "
                "cache_read_tokens, cache_creation_tokens) VALUES(?,?,?,?,?,?,?,?,?)",
                (request_id, session_id, agent_id, ts, msg.get("model"), usage.get("input_tokens"),
                 usage.get("output_tokens"), usage.get("cache_read_input_tokens"), usage.get("cache_creation_input_tokens")),
            )
        if not isinstance(content, list) or not ts:
            return
        for index, block in enumerate(content):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and block.get("id"):
                name = str(block.get("name", ""))
                tool_input = block.get("input")
                self.conn.execute(
                    "INSERT OR IGNORE INTO tool_calls(tool_use_id, session_id, agent_id, agent_type, skill, ts, tool_name, "
                    "input_json, input_key) VALUES(?,?,?,?,?,?,?,?,?)",
                    (block["id"], session_id, agent_id, agent_type, skill, ts, name,
                     dumps(_trim_input(tool_input)), classify.input_key(name, tool_input)),
                )
                self.stats["tool_calls"] += 1
            elif block.get("type") == "text" and block.get("text"):
                self._message("%s:%d" % (rec.get("uuid"), index), session_id, agent_id, ts, "assistant", skill,
                              excerpt(block["text"], TEXT_CHARS))

    def _user(self, rec, session_id, ts, agent_id) -> None:
        content = (rec.get("message") or {}).get("content")
        if rec.get("isMeta"):
            match = _SKILL_BASE_RE.search(classify.result_text(content))
            if match:
                path = match.group(1)
                self.conn.execute("INSERT OR REPLACE INTO skill_paths(skill, path) VALUES(?,?)",
                                  (path.rstrip("/").rsplit("/", 1)[-1], path))
            return
        if rec.get("isCompactSummary"):
            if ts:
                self._message(rec.get("uuid"), session_id, agent_id, ts, "compaction", None, "compaction summary")
            return
        if isinstance(content, list):
            texts = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_result":
                    self._tool_result(block, rec, ts)
                elif block.get("type") == "text":
                    texts.append(str(block.get("text", "")))
            if texts and ts:
                self._human_text(rec, session_id, ts, agent_id, "\n".join(texts))
        elif isinstance(content, str) and ts:
            self._human_text(rec, session_id, ts, agent_id, content)

    def _tool_result(self, block: dict, rec: dict, ts) -> None:
        tool_use_id = block.get("tool_use_id")
        if not tool_use_id:
            return
        row = self.conn.execute("SELECT tool_name, input_json FROM tool_calls WHERE tool_use_id=?", (tool_use_id,)).fetchone()
        if row is None:
            self.stats["orphan_results"] += 1
            return
        text = classify.result_text(block.get("content"))
        try:
            tool_input = json.loads(row["input_json"]) if row["input_json"] else {}
        except ValueError:
            tool_input = {}
        outcome, error_class = classify.classify_result(row["tool_name"], tool_input, text, block.get("is_error"))
        keep_excerpt = outcome != "ok"
        self.conn.execute(
            "UPDATE tool_calls SET result_ts=?, outcome=?, error_class=?, result_excerpt=? WHERE tool_use_id=?",
            (ts, outcome, error_class, excerpt(text, EXCERPT_CHARS) if keep_excerpt else None, tool_use_id),
        )
        self.stats["tool_results"] += 1

    def _human_text(self, rec, session_id, ts, agent_id, text) -> None:
        if agent_id:
            return  # inside a subagent transcript, "user" text is the parent agent delegating, not you
        origin = rec.get("origin")
        if isinstance(origin, dict) and origin.get("kind") not in (None, "human"):
            return
        stripped = _SYSTEM_REMINDER_RE.sub("", text).strip()
        if not stripped:
            return
        uuid = rec.get("uuid")
        if stripped.startswith(classify.INTERRUPT_MARK):
            self._message(uuid, session_id, agent_id, ts, "interrupt", None, stripped[:200])
            return
        command = _COMMAND_NAME_RE.search(stripped)
        if command:
            self._message(uuid, session_id, agent_id, ts, "command", None, command.group(1))
            return
        if stripped.startswith(_NON_HUMAN_PREFIXES):
            return
        self._message(uuid, session_id, agent_id, ts, "human", None, excerpt(stripped, TEXT_CHARS))


def ingest_spool(conn: sqlite3.Connection, cfg: Config) -> Counter:
    stats = Counter()
    if not cfg.spool_dir.is_dir():
        return stats
    for path in sorted(cfg.spool_dir.glob("*.jsonl")):
        lines, marker = _read_new_lines(conn, path, "spool")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                stats["parse_errors"] += 1
                continue
            name = event.get("hook_event_name")
            ts = norm_ts(event.get("ts"))
            if not name or not ts:
                stats["parse_errors"] += 1
                continue
            tool_name = event.get("tool_name")
            key = classify.input_key(tool_name, event.get("tool_input")) if tool_name else None
            conn.execute(
                "INSERT OR IGNORE INTO hook_events(id, ts, event, session_id, cwd, tool_name, input_key, payload_json) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (hashlib.sha1(line.encode("utf-8")).hexdigest(), ts, name, event.get("session_id"), event.get("cwd"),
                 tool_name, key, dumps(event)),
            )
            stats["hook_events"] += 1
        _save_offset(conn, path, "spool", marker)
        conn.commit()
    return stats
