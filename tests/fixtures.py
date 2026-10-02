"""Builders for transcript and hook records, shaped like Claude Code 2.1.287 output."""
from __future__ import annotations

import datetime
import itertools
import json
import os
import sys
from pathlib import Path

NOW = datetime.datetime(2026, 10, 2, 12, 0, 0, tzinfo=datetime.timezone.utc)
_counter = itertools.count(1)


def ts(days_ago: float = 0, seconds: float = 0) -> str:
    moment = NOW - datetime.timedelta(days=days_ago) + datetime.timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


def _uid(prefix: str = "u") -> str:
    return "%s-%06d" % (prefix, next(_counter))


class Session:
    """Accumulates records for one session file and writes them as JSONL."""

    def __init__(self, root: Path, cwd: str, session_id: str | None = None, days_ago: float = 1.0):
        self.root = root
        self.cwd = cwd
        self.session_id = session_id or _uid("sess")
        self.clock = 0.0
        self.days_ago = days_ago
        self.records = []
        self.skill = None

    def now(self, step: float = 2.0) -> str:
        self.clock += step
        return ts(self.days_ago, self.clock)

    def _base(self, rtype: str, **extra) -> dict:
        rec = {"type": rtype, "uuid": _uid(), "parentUuid": None, "isSidechain": False, "timestamp": self.now(),
               "sessionId": self.session_id, "cwd": self.cwd, "entrypoint": "cli", "version": "2.1.287",
               "gitBranch": "main", "userType": "external"}
        rec.update(extra)
        return rec

    def prompt(self, text: str):
        rec = self._base("user", message={"role": "user", "content": text}, origin={"kind": "human"},
                         promptSource="cli", turnOrigin="human", permissionMode="default")
        self.records.append(rec)
        return rec

    def say(self, text: str):
        rec = self._base("assistant", message={"model": "claude-opus-5-5", "id": _uid("msg"), "role": "assistant",
                                               "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                                               "usage": {"input_tokens": 10, "output_tokens": 5}},
                         requestId=_uid("req"), attributionSkill=self.skill)
        self.records.append(rec)
        return rec

    def tool(self, name: str, tool_input: dict, result: str, is_error: bool = False, gap: float = 2.0) -> str:
        tool_id = "toolu_" + _uid("t")
        use = self._base("assistant", message={"model": "claude-opus-5-5", "id": _uid("msg"), "role": "assistant",
                                               "content": [{"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}],
                                               "stop_reason": "tool_use", "usage": {"input_tokens": 10, "output_tokens": 5}},
                         requestId=_uid("req"), attributionSkill=self.skill)
        self.records.append(use)
        self.clock += gap
        res = self._base("user", message={"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tool_id, "content": result, "is_error": is_error}]},
            toolUseResult=("Error: " + result) if is_error else {"stdout": result}, sourceToolAssistantUUID=use["uuid"])
        self.records.append(res)
        return tool_id

    def interrupt(self):
        rec = self._base("user", message={"role": "user", "content": [{"type": "text", "text": "[Request interrupted by user]"}]})
        self.records.append(rec)
        return rec

    def skill_load(self, name: str, path: str):
        self.skill = name
        rec = self._base("user", isMeta=True, message={"role": "user", "content": [
            {"type": "text", "text": "Base directory for this skill: %s\n\n# %s" % (path, name)}]})
        self.records.append(rec)

    def write(self) -> Path:
        directory = self.root / self.cwd.strip("/").replace("/", "-")
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / ("%s.jsonl" % self.session_id)
        with path.open("w", encoding="utf-8") as fh:
            for rec in self.records:
                fh.write(json.dumps(rec) + "\n")
        return path

    def subagent(self, agent_type: str) -> "Subagent":
        return Subagent(self, agent_type)


class Subagent(Session):
    def __init__(self, parent: Session, agent_type: str):
        super().__init__(parent.root, parent.cwd, parent.session_id, parent.days_ago)
        self.clock = parent.clock
        self.agent_id = _uid("a")
        self.agent_type = agent_type

    def _base(self, rtype: str, **extra) -> dict:
        rec = super()._base(rtype, **extra)
        rec.update(isSidechain=True, agentId=self.agent_id, attributionAgent=self.agent_type)
        return rec

    def write(self) -> Path:
        directory = self.root / self.cwd.strip("/").replace("/", "-") / self.session_id / "subagents"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / ("agent-%s.jsonl" % self.agent_id)
        with path.open("w", encoding="utf-8") as fh:
            for rec in self.records:
                fh.write(json.dumps(rec) + "\n")
        (directory / ("agent-%s.meta.json" % self.agent_id)).write_text(json.dumps({"agentType": self.agent_type}))
        return path


def hook_event(spool: Path, session: Session, event: str, at: str, **fields) -> None:
    spool.mkdir(parents=True, exist_ok=True)
    record = {"ts": at, "hook_event_name": event, "session_id": session.session_id, "cwd": session.cwd}
    record.update(fields)
    with (spool / (at[:10] + ".jsonl")).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def isolated_env(tmp: Path) -> dict:
    """Environment that points HOME, the Claude config dir, and the observer home into a temp dir."""
    home = tmp / "home"
    (home / ".claude" / "projects").mkdir(parents=True, exist_ok=True)
    return {"HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"), "OBSERVER_HOME": str(home / ".observer")}


def write_fake_claude(path: Path, response: dict, log: Path) -> Path:
    """A stand-in `claude` binary that records argv, env, and stdin, then prints a canned response."""
    data = path.with_name(path.name + ".response.json")
    data.write_text(json.dumps(response))
    script = "\n".join([
        "#!%s" % sys.executable,
        "import json, os, sys",
        "stdin = sys.stdin.read()",
        "with open(%r, 'w') as fh:" % str(log),
        "    json.dump({'argv': sys.argv[1:], 'internal': os.environ.get('OBSERVER_INTERNAL'), 'stdin': stdin}, fh)",
        "with open(%r) as fh:" % str(data),
        "    response = json.load(fh)",
        "print(json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False, 'result': '',",
        "                  'structured_output': response}))",
        "",
    ])
    path.write_text(script)
    os.chmod(path, 0o755)
    return path
