"""Close the loop: persist recommendations, detect when you applied one, and measure its effect."""
from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import sqlite3

from .config import Config
from .detect import iso, parse_ts
from .recommend import EXTRA_PATH
from .store import dumps, loads



def expire_unseen(conn: sqlite3.Connection, now_iso: str) -> int:
    """Open or blocked recommendations this run did not regenerate no longer have qualifying evidence."""
    cur = conn.execute(
        "UPDATE recommendations SET status='expired', status_reason='evidence no longer meets the thresholds' "
        "WHERE status IN ('open', 'blocked') AND last_seen < ?", (now_iso,)
    )
    conn.commit()
    return cur.rowcount


def upsert(conn: sqlite3.Connection, recs: list, now_iso: str) -> None:
    for rec in recs:
        row = conn.execute("SELECT * FROM recommendations WHERE id=?", (rec.id,)).fetchone()
        evidence = dict(rec.evidence, judge_note=rec.judge_note, demoted=rec.demoted, source=rec.source,
                        risk_reason=rec.risk_reason)
        if row is None:
            status = "blocked" if rec.blocked_reason else "open"
            conn.execute(
                "INSERT INTO recommendations(id, type, target, title, rationale, patch_json, verify, risk, confidence, "
                "impact_minutes_week, evidence_json, fingerprints_json, source, status, status_reason, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rec.id, rec.type, rec.target, rec.title, rec.rationale, dumps(rec.patch), rec.verify, rec.risk,
                 rec.confidence, rec.impact_minutes_week, dumps(evidence), dumps(rec.fingerprints), rec.source, status,
                 rec.blocked_reason or None, now_iso, now_iso),
            )
            continue
        status, reason = row["status"], row["status_reason"]
        if rec.blocked_reason:
            if status in ("open", "blocked"):
                status, reason = "blocked", rec.blocked_reason
        elif status in ("blocked", "expired"):
            status, reason = "open", None
        elif status == "dismissed" and rec.evidence.get("count", 0) >= 2 * max(row["dismissed_evidence"] or 0, 1):
            status, reason = "open", "reopened: evidence doubled since you dismissed it"
        conn.execute(
            "UPDATE recommendations SET title=?, rationale=?, patch_json=?, verify=?, risk=?, confidence=?, "
            "impact_minutes_week=?, evidence_json=?, fingerprints_json=?, source=?, status=?, status_reason=?, last_seen=? "
            "WHERE id=?",
            (rec.title, rec.rationale, dumps(rec.patch), rec.verify, rec.risk, rec.confidence, rec.impact_minutes_week,
             dumps(evidence), dumps(rec.fingerprints), rec.source, status, reason, now_iso, rec.id),
        )
    conn.commit()


# ------------------------------------------------------------------ applied detection


def _load_json(path: str):
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _settings_files(patch_file: str) -> list:
    files = [patch_file, "~/.claude/settings.json"]
    # A project rule counts as applied whether it went into settings.json or settings.local.json.
    match = re.match(r"^(.*)/\.claude/settings(?:\.local)?\.json$", patch_file)
    if match:
        files += [match.group(1) + "/.claude/settings.json", match.group(1) + "/.claude/settings.local.json"]
    return list(dict.fromkeys(files))


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"^[-*\s]+", "", text.strip().lower()))


def is_applied(patch: dict) -> bool:
    kind = patch.get("kind")
    if kind == "settings_merge":
        wanted = (patch.get("merge") or {}).get("permissions") or {}
        for file in _settings_files(str(patch.get("file", ""))):
            data = _load_json(file)
            perms = data.get("permissions") if isinstance(data, dict) else None
            if not isinstance(perms, dict):
                continue
            if all(isinstance(perms.get(key), list) and all(v in perms[key] for v in values)
                   for key, values in wanted.items()):
                return True
        return False
    if kind == "append":
        try:
            with open(os.path.expanduser(str(patch.get("file", ""))), encoding="utf-8") as fh:
                content = _norm(fh.read())
        except OSError:
            return False
        lines = [_norm(l) for l in str(patch.get("text", "")).splitlines() if _norm(l)]
        return bool(lines) and sum(1 for l in lines if l in content) * 2 >= len(lines)
    if kind == "command" and patch.get("program"):
        path = os.pathsep.join([os.environ.get("PATH", "")] + EXTRA_PATH)
        return shutil.which(str(patch["program"]), path=path) is not None
    return False


def _rate_per_day(conn, fingerprints: list, start: str, end: str) -> float:
    if not fingerprints:
        return 0.0
    days = max((parse_ts(end) - parse_ts(start)).total_seconds() / 86400.0, 1.0)
    total = 0
    for kind, fp in fingerprints:
        total += conn.execute(
            "SELECT COUNT(*) FROM frictions WHERE kind=? AND fingerprint=? AND ts >= ? AND ts < ?", (kind, fp, start, end)
        ).fetchone()[0]
    return total / days


def mark_applied(conn, rec_id: str, now: datetime.datetime, cfg: Config) -> None:
    row = conn.execute("SELECT fingerprints_json FROM recommendations WHERE id=?", (rec_id,)).fetchone()
    fps = [tuple(x) for x in loads(row["fingerprints_json"], [])] if row else []
    now_iso = iso(now)
    baseline = _rate_per_day(conn, fps, iso(now - datetime.timedelta(days=cfg.window_days)), now_iso)
    conn.execute("UPDATE recommendations SET status='applied', status_reason=NULL, applied_at=?, baseline_per_day=? WHERE id=?",
                 (now_iso, baseline, rec_id))


def update_outcomes(conn: sqlite3.Connection, cfg: Config, now: datetime.datetime) -> dict:
    changes = {"applied": [], "verified": [], "not_effective": []}
    for row in conn.execute("SELECT * FROM recommendations WHERE status IN ('open', 'dismissed')").fetchall():
        if is_applied(loads(row["patch_json"], {}) or {}):
            mark_applied(conn, row["id"], now, cfg)
            changes["applied"].append(row["id"])
    for row in conn.execute("SELECT * FROM recommendations WHERE status='applied'").fetchall():
        applied_at = row["applied_at"]
        if not applied_at or parse_ts(applied_at) > now - datetime.timedelta(days=cfg.verify_after_days):
            continue
        fps = [tuple(x) for x in loads(row["fingerprints_json"], [])]
        after = _rate_per_day(conn, fps, applied_at, iso(now))
        baseline = row["baseline_per_day"] or 0.0
        if baseline <= 0 and after == 0:
            status, reason = "verified", "no recurrence after applying (no baseline to compare)"
        elif baseline <= 0:
            status, reason = "not_effective", "friction appeared after applying"
        elif after <= baseline * (1 - cfg.verify_drop):
            status, reason = "verified", "friction fell from %.2f to %.2f per day" % (baseline, after)
        else:
            status, reason = "not_effective", "friction went from %.2f to %.2f per day" % (baseline, after)
        conn.execute("UPDATE recommendations SET status=?, status_reason=?, after_per_day=? WHERE id=?",
                     (status, reason, after, row["id"]))
        changes[status].append(row["id"])
    conn.commit()
    return changes


def dismiss(conn, rec_id: str, reason: str | None) -> bool:
    row = conn.execute("SELECT evidence_json FROM recommendations WHERE id=?", (rec_id,)).fetchone()
    if row is None:
        return False
    count = (loads(row["evidence_json"], {}) or {}).get("count", 0)
    conn.execute(
        "UPDATE recommendations SET status='dismissed', status_reason=?, dismissed_at=?, dismissed_evidence=? WHERE id=?",
        (reason or "dismissed by you", iso(datetime.datetime.now(datetime.timezone.utc)), count, rec_id),
    )
    conn.commit()
    return True


def mark_done(conn, rec_id: str, cfg: Config) -> bool:
    if conn.execute("SELECT 1 FROM recommendations WHERE id=?", (rec_id,)).fetchone() is None:
        return False
    mark_applied(conn, rec_id, datetime.datetime.now(datetime.timezone.utc), cfg)
    conn.commit()
    return True
