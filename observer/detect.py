"""Turn ingested records into friction events. Deterministic and idempotent: each run deletes and
rebuilds frictions inside the lookback window, so detector changes apply retroactively."""
from __future__ import annotations

import bisect
import datetime
import hashlib
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict

from . import classify
from .config import Config
from .ingest import norm_ts
from .store import dumps, loads

MAX_RECOVERY_SECONDS = 600
MAX_PROMPT_WAIT_SECONDS = 300
LOOP_WINDOW = 10
LOOP_THRESHOLD = 3
# Frictions that count against an agent in the scorecard. Permission prompts and API failures are
# excluded because they are not the agent's doing.
AGENT_FAULT_KINDS = ("tool_error", "rejected", "denied", "retry_loop", "interrupt", "correction", "capability_gap")
COWORK_PREFIX = "cowork/"
_STOP_WORDS = {"your", "the", "my", "this", "a", "an", "any", "to", "that", "these", "those", "their", "our"}


def parse_ts(value: str) -> datetime.datetime:
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)


def iso(dt: datetime.datetime) -> str:
    return norm_ts(dt.astimezone(datetime.timezone.utc).isoformat())


def seconds_between(a: str, b: str) -> float:
    return (parse_ts(b) - parse_ts(a)).total_seconds()


def lookback_start(cfg: Config, now: datetime.datetime) -> str:
    # Covers the recommendation window plus the verification period that follows an applied change.
    return iso(now - datetime.timedelta(days=cfg.window_days + cfg.verify_after_days + 1))


def agent_key(agent_type, skill) -> str:
    if agent_type:
        return "agent:%s" % agent_type
    if skill:
        return "skill:%s" % skill
    return "main"


def _fid(*parts) -> str:
    return "f" + hashlib.sha1("\x00".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:12]


def _rule_for(tool_name: str, tool_input) -> str:
    rule = classify.synth_rule(tool_name, tool_input)
    if rule:
        return rule
    if tool_name == "Bash":
        prog = classify.first_program((tool_input or {}).get("command", "") if isinstance(tool_input, dict) else "")
        return "Bash(%s *)" % prog if prog else "Bash"
    return tool_name


def _error_fingerprint(call: sqlite3.Row, tool_input: dict) -> str:
    cls = call["error_class"]
    tool = call["tool_name"]
    if cls == "command_not_found":
        prog = classify.missing_program(call["result_excerpt"] or "") or classify.first_program(tool_input.get("command", ""))
        return "missing:%s" % prog
    if cls == "outside_workdir":
        path = str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path") or "")
        if not path:  # Bash and other tools: the blocked path is named in the error or the command
            path = _first_abs_path(call["result_excerpt"] or "") or _first_abs_path(str(tool_input.get("command", "")))
        return "dir:%s" % _dir_bucket(path)
    if tool.startswith("mcp__"):
        return "mcp:%s:%s" % (tool.split("__")[1] if "__" in tool else tool, cls)
    if tool == "Bash":
        return "bash:%s:%s" % (classify.first_program(tool_input.get("command", "")), cls)
    return "%s:%s" % (tool, cls)


_ABS_PATH_RE = re.compile(r"(?:^|(?<=[\s'\"`(=]))((?:/|~/)[^\s'\"`;|&<>()]+)")


def _first_abs_path(text: str) -> str:
    """First absolute or home-relative path with at least two components (skips `/add-dir`, `/dev/null`)."""
    for match in _ABS_PATH_RE.finditer(text or ""):
        path = match.group(1).rstrip(".,:")
        if path.startswith("/dev/") or len([p for p in path.split("/") if p]) < 2:
            continue
        return path
    return ""


def _dir_bucket(path: str) -> str:
    """Group paths by their first four components (/Users/name/Documents/Project)."""
    path = os.path.expanduser(path) if path else ""
    if not path:
        return ""
    parts = [p for p in path.split("/") if p]
    if len(parts) <= 1:
        return "/" + "/".join(parts)
    # Drop the file name when the path looks like a file.
    if "." in parts[-1] and len(parts) > 1:
        parts = parts[:-1]
    return "/" + "/".join(parts[:4])


_GAP_OBJECT_RE = re.compile(
    r"\b(?:access(?: to)?|permission to|connect to|reach|read|open|use|run|install)\s+"
    r"(?:(?:the|your|my|this|any|a|an)\s+)?([^.,;:!?\n]+)",
    re.I,
)
_GAP_TAIL_STOP_RE = re.compile(
    r"\b(?:from|in|on|at|so|because|since|but|and|or|without|here|right now|directly|via|through|with|for now)\b", re.I
)


def _gap_key(sentence: str) -> str:
    """Reduce a "cannot access X" statement to X, so differently worded statements cluster."""
    match = _GAP_OBJECT_RE.search(sentence)
    tail = match.group(1) if match else sentence
    tail = _GAP_TAIL_STOP_RE.split(tail, 1)[0]
    words = [w for w in re.findall(r"[a-z0-9][a-z0-9._-]*", tail.lower()) if w not in _STOP_WORDS]
    return " ".join(words[:3]) or "unspecified"


def _norm_sentence(text: str) -> str:
    text = re.sub(r"\s+", " ", text.strip().lower())
    text = re.sub(r"^(?:please|pls|also|and|but|so)\s+", "", text)
    return text.rstrip(" .!?;:")


def _sentences(text: str) -> list:
    out = []
    for line in text.splitlines():
        line = line.strip(" -*\t>")
        if not line or "```" in line:
            continue
        for part in re.split(r"(?<=[.!?])\s+", line):
            words = part.split()
            if 4 <= len(words) <= 40:
                alpha = sum(ch.isalpha() for ch in part)
                if alpha / max(len(part), 1) >= 0.6:
                    out.append(part.strip())
    return out


class Detector:
    def __init__(self, conn: sqlite3.Connection, cfg: Config, now: datetime.datetime):
        self.conn = conn
        self.cfg = cfg
        self.now = now
        self.start = lookback_start(cfg, now)
        self.rows = []
        self.stats = Counter()
        self.sessions = {
            r["session_id"]: r for r in conn.execute("SELECT session_id, cwd, internal, surface FROM sessions")
        }
        self.skill_timeline = defaultdict(list)  # session_id -> sorted [(ts, agent_key)]

    def project(self, session_id) -> str:
        row = self.sessions.get(session_id)
        return (row["cwd"] if row and row["cwd"] else "") or "(unknown)"

    def internal(self, session_id) -> bool:
        row = self.sessions.get(session_id)
        return bool(row and row["internal"])

    def emit(self, fid, ts, session_id, akey, kind, subkind, fingerprint, tool_name, detail, ref, cost, meta=None):
        row = self.sessions.get(session_id)
        if row is not None and row["surface"] == "cowork" and not akey.startswith(COWORK_PREFIX):
            akey = COWORK_PREFIX + akey  # Cowork agents are scored and fixed separately from Claude Code
        self.rows.append((fid, ts, session_id, self.project(session_id), akey, kind, subkind, fingerprint, tool_name,
                          detail, ref, float(cost or 0), dumps(meta) if meta else None))
        self.stats[kind] += 1

    def default_cost(self, kind: str) -> float:
        return float(self.cfg.cost_seconds.get(kind, 30))

    # ------------------------------------------------------------ run

    def run(self) -> Counter:
        self.conn.execute("DELETE FROM frictions WHERE ts >= ?", (self.start,))
        self.detect_tool_calls()
        self.detect_messages()
        self.detect_hook_events()
        self.detect_repeated_instructions()
        self.conn.executemany(
            "INSERT OR REPLACE INTO frictions(id, ts, session_id, project, agent_key, kind, subkind, fingerprint, "
            "tool_name, detail, evidence_ref, cost_seconds, meta_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            self.rows,
        )
        self.conn.commit()
        return self.stats

    # ------------------------------------------------------------ transcripts: tool calls

    def detect_tool_calls(self) -> None:
        calls = self.conn.execute(
            "SELECT * FROM tool_calls WHERE ts >= ? ORDER BY session_id, COALESCE(agent_id, ''), ts", (self.start,)
        ).fetchall()
        groups = defaultdict(list)
        for call in calls:
            if self.internal(call["session_id"]):
                continue
            groups[(call["session_id"], call["agent_id"])].append(call)
            if call["agent_id"] is None:
                self.skill_timeline[call["session_id"]].append((call["ts"], agent_key(call["agent_type"], call["skill"])))
        for timeline in self.skill_timeline.values():
            timeline.sort()
        for (session_id, _agent_id), seq in groups.items():
            self._scan_sequence(session_id, seq)

    def _scan_sequence(self, session_id: str, seq: list) -> None:
        recent_errors = defaultdict(list)  # fingerprint -> indices of recent errors
        looping = set()
        for i, call in enumerate(seq):
            akey = agent_key(call["agent_type"], call["skill"])
            tool_input = loads(call["input_json"], {}) or {}
            if not isinstance(tool_input, dict):
                tool_input = {}
            for fp in [fp for fp, idx in recent_errors.items() if idx and idx[-1] < i - LOOP_WINDOW + 1]:
                looping.discard(fp)
            outcome = call["outcome"]
            if outcome == "error":
                cls = call["error_class"]
                if cls in classify.BENIGN_ERROR_CLASSES:
                    continue
                fp = _error_fingerprint(call, tool_input)
                cost = self._recovery_seconds(seq, i)
                detail = "%s -> %s" % (classify.summarize_input(call["tool_name"], tool_input, 160),
                                       (call["result_excerpt"] or "")[:240])
                self.emit(_fid("tool_error", call["tool_use_id"]), call["ts"], session_id, akey, "tool_error", cls, fp,
                          call["tool_name"], detail, call["tool_use_id"], cost)
                idx = [j for j in recent_errors[fp] if j > i - LOOP_WINDOW] + [i]
                recent_errors[fp] = idx
                if len(idx) >= LOOP_THRESHOLD and fp not in looping:
                    looping.add(fp)
                    first = seq[idx[0]]
                    self.emit(_fid("retry_loop", call["tool_use_id"]), call["ts"], session_id, akey, "retry_loop", cls,
                              fp, call["tool_name"], "%d identical failures within %d calls: %s" % (len(idx), LOOP_WINDOW, detail),
                              call["tool_use_id"], max(seconds_between(first["ts"], call["ts"]), 0))
            elif outcome in ("rejected", "denied"):
                rule = _rule_for(call["tool_name"], tool_input)
                detail = "%s | %s" % (classify.summarize_input(call["tool_name"], tool_input, 160),
                                      (call["result_excerpt"] or "")[:200])
                self.emit(_fid(outcome, call["tool_use_id"]), call["ts"], session_id, akey, outcome,
                          "user" if outcome == "rejected" else "rule_or_classifier", rule, call["tool_name"], detail,
                          call["tool_use_id"], self.default_cost(outcome), {"rule": rule})

    def _recovery_seconds(self, seq: list, i: int) -> float:
        """Time from a failed call to the agent's next successful call, as a measure of what it cost."""
        start = seq[i]["ts"]
        for later in seq[i + 1:]:
            if later["outcome"] == "ok":
                return min(max(seconds_between(start, later["ts"]), 0), MAX_RECOVERY_SECONDS)
        return self.default_cost("tool_error")

    def agent_at(self, session_id: str, ts: str) -> str:
        timeline = self.skill_timeline.get(session_id) or []
        pos = bisect.bisect_right(timeline, (ts, "￿")) - 1
        return timeline[pos][1] if pos >= 0 else "main"

    # ------------------------------------------------------------ transcripts: messages

    def detect_messages(self) -> None:
        rows = self.conn.execute(
            "SELECT * FROM messages WHERE ts >= ? ORDER BY session_id, ts", (self.start,)
        ).fetchall()
        previous = {}
        seen_activity = set(
            r["session_id"] for r in self.conn.execute("SELECT DISTINCT session_id FROM tool_calls WHERE ts >= ?", (self.start,))
        )
        for msg in rows:
            session_id = msg["session_id"]
            if self.internal(session_id):
                continue
            kind = msg["kind"]
            akey = agent_key(None, msg["skill"]) if msg["kind"] == "assistant" and msg["agent_id"] is None else self.agent_at(session_id, msg["ts"])
            prev = previous.get(session_id)
            if kind == "interrupt":
                self.emit(_fid("interrupt", msg["uuid"]), msg["ts"], session_id, akey, "interrupt", None,
                          "interrupt:%s" % akey, None, msg["text"], msg["uuid"], self.default_cost("interrupt"))
            elif kind == "human":
                after_interrupt = prev is not None and prev["kind"] == "interrupt"
                has_prior_work = prev is not None and prev["kind"] in ("assistant", "interrupt", "human") and session_id in seen_activity
                if after_interrupt or (has_prior_work and classify.looks_like_correction(msg["text"])):
                    self.emit(_fid("correction", msg["uuid"]), msg["ts"], session_id, akey, "correction",
                              "after_interrupt" if after_interrupt else "lexical", "correction:%s" % akey, None,
                              (msg["text"] or "")[:400], msg["uuid"], self.default_cost("correction"))
            elif kind == "assistant" and msg["agent_id"] is None:
                sentence = classify.capability_gap_sentence(msg["text"] or "")
                if sentence:
                    self.emit(_fid("capability_gap", msg["uuid"]), msg["ts"], session_id, akey, "capability_gap", None,
                              "gap:%s" % _gap_key(sentence), None, sentence[:300], msg["uuid"],
                              self.default_cost("capability_gap"))
            elif kind == "api_error":
                self.emit(_fid("api_failure", msg["uuid"]), msg["ts"], session_id, akey, "api_failure", "transcript",
                          "api:%s" % re.sub(r"\W+", " ", (msg["text"] or "")[:48]).strip().lower(), None,
                          (msg["text"] or "")[:300], msg["uuid"], self.default_cost("api_failure"))
            elif kind == "compaction":
                self.emit(_fid("compaction", msg["uuid"]), msg["ts"], session_id, akey, "compaction", None,
                          "compaction:%s" % self.project(session_id), None, None, msg["uuid"], self.default_cost("compaction"))
            if kind in ("human", "interrupt") or (kind == "assistant" and msg["agent_id"] is None):
                previous[session_id] = msg

    # ------------------------------------------------------------ hooks

    def detect_hook_events(self) -> None:
        events = self.conn.execute("SELECT * FROM hook_events WHERE ts >= ? ORDER BY ts", (self.start,)).fetchall()
        for event in events:
            session_id = event["session_id"]
            if session_id and self.internal(session_id):
                continue
            payload = loads(event["payload_json"], {}) or {}
            name = event["event"]
            if name == "PermissionRequest":
                self._permission_request(event, payload)
            elif name == "PermissionDenied":
                tool_use_id = payload.get("tool_use_id")
                if tool_use_id:
                    row = self.conn.execute("SELECT outcome FROM tool_calls WHERE tool_use_id=?", (tool_use_id,)).fetchone()
                    if row is not None and row["outcome"] == "denied":
                        continue  # already counted from the transcript
                rule = _rule_for(event["tool_name"] or "", payload.get("tool_input"))
                self.emit(_fid("denied", event["id"]), event["ts"], session_id, self.agent_at(session_id, event["ts"]),
                          "denied", "classifier", rule, event["tool_name"],
                          "%s | %s" % (classify.summarize_input(event["tool_name"] or "", payload.get("tool_input"), 160),
                                       str(payload.get("reason", ""))[:200]),
                          event["id"], self.default_cost("denied"), {"rule": rule, "reason": payload.get("reason")})
            elif name == "StopFailure":
                error = str(payload.get("error", ""))
                self.emit(_fid("api_failure", event["id"]), event["ts"], session_id, self.agent_at(session_id, event["ts"]),
                          "api_failure", "stop_failure", "api:%s" % re.sub(r"\W+", " ", error[:48]).strip().lower(), None,
                          (error + " " + json.dumps(payload.get("error_details", ""))[:200]).strip(), event["id"],
                          self.default_cost("api_failure"))

    def _permission_request(self, event, payload) -> None:
        tool_name = event["tool_name"] or ""
        suggested = classify.rules_from_suggestions(payload.get("permission_suggestions"))
        rule = suggested[0] if suggested else _rule_for(tool_name, payload.get("tool_input"))
        match = None
        if event["session_id"] and event["input_key"]:
            candidates = self.conn.execute(
                "SELECT tool_use_id, ts, result_ts, outcome FROM tool_calls WHERE session_id=? AND tool_name=? AND input_key=?",
                (event["session_id"], tool_name, event["input_key"]),
            ).fetchall()
            near = [(abs(seconds_between(c["ts"], event["ts"])), c) for c in candidates]
            near = [pair for pair in near if pair[0] <= 600]
            if near:
                match = min(near, key=lambda pair: pair[0])[1]
        if match is None or match["outcome"] == "pending":
            subkind, cost = "unknown", self.default_cost("permission_prompt")
        elif match["outcome"] in ("rejected", "denied"):
            subkind, cost = "rejected", self.default_cost("permission_prompt")
        else:
            subkind = "approved"
            wait = seconds_between(event["ts"], match["result_ts"]) if match["result_ts"] else None
            cost = min(max(wait, 0), MAX_PROMPT_WAIT_SECONDS) if wait is not None else self.default_cost("permission_prompt")
        self.emit(_fid("permission_prompt", event["id"]), event["ts"], event["session_id"],
                  self.agent_at(event["session_id"], event["ts"]), "permission_prompt", subkind, rule, tool_name,
                  classify.summarize_input(tool_name, payload.get("tool_input"), 200), event["id"], cost,
                  {"rule": rule, "suggested": bool(suggested), "cwd": event["cwd"],
                   "tool_use_id": match["tool_use_id"] if match else None})

    # ------------------------------------------------------------ cross-session

    def detect_repeated_instructions(self) -> None:
        window_start = iso(self.now - datetime.timedelta(days=self.cfg.window_days))
        rows = self.conn.execute(
            "SELECT uuid, session_id, ts, text FROM messages WHERE kind='human' AND ts >= ? ORDER BY ts", (window_start,)
        ).fetchall()
        by_sentence = defaultdict(list)
        for msg in rows:
            if self.internal(msg["session_id"]):
                continue
            for sentence in set(_sentences(msg["text"] or "")):
                by_sentence[_norm_sentence(sentence)].append((msg, sentence))
        for norm, hits in by_sentence.items():
            sessions = {m["session_id"] for m, _ in hits}
            if len(sessions) < self.cfg.repeated_instruction_min_sessions:
                continue
            fp = "instr:" + hashlib.sha1(norm.encode("utf-8")).hexdigest()[:12]
            for msg, sentence in hits:
                self.emit(_fid("repeated_instruction", msg["uuid"], fp), msg["ts"], msg["session_id"], "main",
                          "repeated_instruction", None, fp, None, sentence, msg["uuid"], 15)


def detect(conn: sqlite3.Connection, cfg: Config, now: datetime.datetime) -> Counter:
    return Detector(conn, cfg, now).run()
