#!/usr/bin/env python3
"""Claude Code hook entrypoint: append one JSON line per event to the observer spool.

Registered at user scope for PermissionRequest, PermissionDenied, Notification,
StopFailure and SessionEnd. It must never slow down or alter a session, so it:

* imports only the standard library (it runs as a plain script, not via the package);
* writes nothing to stdout, so it can never return a decision or inject context;
* always exits 0, logging its own failures to ~/.observer/logs/hook-errors.log.
"""
import datetime
import json
import os
import sys

MAX_STDIN = 1_000_000
MAX_FIELD = 2_000
KEEP = (
    "hook_event_name",
    "session_id",
    "cwd",
    "permission_mode",
    "transcript_path",
    "tool_name",
    "tool_use_id",
    "tool_input",
    "permission_suggestions",
    "reason",
    "notification_type",
    "message",
    "title",
    "error",
    "error_details",
    "is_interrupt",
    "duration_ms",
)


def _home():
    return os.path.expanduser(os.environ.get("OBSERVER_HOME", "~/.observer"))


def _clip(value):
    """Bound the size of every string inside the payload."""
    if isinstance(value, str):
        return value if len(value) <= MAX_FIELD else value[:MAX_FIELD] + "...[truncated]"
    if isinstance(value, dict):
        return {k: _clip(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip(v) for v in value[:50]]
    return value


def main():
    # The observer's own judge call runs with this set; never record it.
    if os.environ.get("OBSERVER_INTERNAL") == "1":
        return
    payload = json.loads(sys.stdin.read(MAX_STDIN) or "{}")
    now = datetime.datetime.now(datetime.timezone.utc)
    record = {"ts": now.isoformat(timespec="milliseconds").replace("+00:00", "Z")}
    for key in KEEP:
        if key in payload:
            record[key] = _clip(payload[key])
    spool = os.path.join(_home(), "spool")
    os.makedirs(spool, mode=0o700, exist_ok=True)
    path = os.path.join(spool, now.strftime("%Y-%m-%d") + ".jsonl")
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # never let a hook failure reach the session
        try:
            logs = os.path.join(_home(), "logs")
            os.makedirs(logs, mode=0o700, exist_ok=True)
            with open(os.path.join(logs, "hook-errors.log"), "a", encoding="utf-8") as fh:
                fh.write("%s %r\n" % (datetime.datetime.now().isoformat(), exc))
        except Exception:
            pass
    sys.exit(0)
