"""The daily run: ingest -> detect -> recommend -> judge -> gate -> outcomes -> report."""
from __future__ import annotations

import datetime
import subprocess
import sys
from collections import Counter

from . import judge, outcomes, policy, recommend, report
from .config import Config, ensure_home
from .detect import detect, iso
from .ingest import TranscriptIngestor, ingest_spool
from .install import hooks_installed
from .store import connect, dumps, loads


def prune(conn, cfg: Config, now: datetime.datetime) -> None:
    cutoff = iso(now - datetime.timedelta(days=cfg.retention_days))
    for table in ("tool_calls", "messages", "hook_events", "frictions", "requests"):
        conn.execute("DELETE FROM %s WHERE ts < ?" % table, (cutoff,))
    conn.commit()


def notify(title: str, message: str) -> None:
    if sys.platform != "darwin":
        return
    script = 'display notification "%s" with title "%s"' % (
        message.replace("\\", "").replace('"', "'")[:200], title.replace('"', "'"))
    try:
        subprocess.run(["osascript", "-e", script], timeout=10, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        pass


def run(cfg: Config, use_judge: bool = True, send_notification: bool = False, now: datetime.datetime | None = None) -> dict:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    now_iso = iso(now)
    ensure_home(cfg)
    conn = connect(cfg.db_path)
    run_id = conn.execute("INSERT INTO runs(started) VALUES(?)", (now_iso,)).lastrowid
    conn.commit()
    previous = conn.execute(
        "SELECT window_end FROM runs WHERE finished IS NOT NULL AND id < ? ORDER BY id DESC LIMIT 1", (run_id,)
    ).fetchone()
    since = previous["window_end"] if previous else iso(now - datetime.timedelta(days=1))

    ingestor = TranscriptIngestor(conn, cfg)
    ingest_stats = ingestor.run()
    spool_stats = ingest_spool(conn, cfg)
    prune(conn, cfg, now)
    new_sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE internal=0 AND first_ts >= ?", (since,)).fetchone()[0]

    detect_stats = detect(conn, cfg, now)
    clusters = recommend.build_clusters(conn, cfg, now)
    recs = recommend.candidates(conn, cfg, now, clusters)
    for rec in recs:
        policy.gate(rec)
    scorecard = recommend.scorecard(conn, cfg, now)

    judge_status, summary, attributions = "skipped (--no-llm)", "", {}
    if use_judge and cfg.judge_enabled:
        if not clusters:
            judge_status = "skipped (no friction to review)"
        else:
            window_start = iso(now - datetime.timedelta(days=cfg.window_days))
            history = [
                {"id": r["id"], "type": r["type"], "title": r["title"], "status": r["status"],
                 "status_reason": r["status_reason"]}
                for r in conn.execute(
                    "SELECT id, type, title, status, status_reason FROM recommendations WHERE status != 'open' "
                    "ORDER BY last_seen DESC LIMIT 30")
            ]
            pack = judge.build_pack(cfg, clusters, recs, scorecard,
                                    judge.corrections_with_context(conn, cfg, window_start), history)
            data, status = judge.call_judge(cfg, pack)
            if data is None:
                judge_status = "failed (%s); report uses deterministic rules only" % status
            else:
                new, attributions = judge.apply_judgment(data, recs, clusters, cfg)
                for rec in new:
                    policy.gate(rec)
                recs += new
                summary = data.get("summary", "")[:800]
                judge_status = "ok (%s, %d attributions, %d new recommendations)" % (cfg.judge_model, len(attributions), len(new))
    elif not cfg.judge_enabled:
        judge_status = "disabled in config"

    outcomes.upsert(conn, recs, now_iso)
    outcome_changes = outcomes.update_outcomes(conn, cfg, now)

    seen_ids = [r.id for r in recs]
    placeholders = ",".join("?" * len(seen_ids)) or "''"
    rec_rows = conn.execute("SELECT * FROM recommendations WHERE id IN (%s)" % placeholders, seen_ids).fetchall()
    outcome_rows = conn.execute(
        "SELECT * FROM recommendations WHERE status IN ('applied', 'verified', 'not_effective') ORDER BY applied_at DESC LIMIT 20"
    ).fetchall()
    hook_total = conn.execute("SELECT COUNT(*) FROM hook_events").fetchone()[0]
    notification_counts = Counter(
        (loads(r["payload_json"], {}) or {}).get("notification_type") or "other"
        for r in conn.execute("SELECT payload_json FROM hook_events WHERE event='Notification' AND ts >= ?",
                              (iso(now - datetime.timedelta(days=cfg.window_days)),))
    )
    ctx = {
        "now": now,
        "new_sessions": new_sessions,
        "summary": summary,
        "recommendations": rec_rows,
        "outcomes": outcome_rows,
        "scorecard": scorecard,
        "friction_by_kind": report.friction_by_kind(conn, iso(now - datetime.timedelta(days=cfg.window_days))),
        "attribution_counts": judge.judge_counts(attributions),
        "health": report.health_lines(ingest_stats, spool_stats, hook_total, judge_status, ingestor.unknown_types,
                                      hooks_installed(), notification_counts),
    }
    text = report.render(ctx, cfg)
    local_day = now.astimezone().strftime("%Y-%m-%d")
    path = cfg.reports_dir / ("%s.md" % local_day)
    path.write_text(text, encoding="utf-8")
    (cfg.reports_dir / "latest.md").write_text(text, encoding="utf-8")

    stats = {"ingest": dict(ingest_stats), "spool": dict(spool_stats), "detect": dict(detect_stats),
             "clusters": len(clusters), "recommendations": len(recs), "outcomes": outcome_changes, "since": since}
    conn.execute("UPDATE runs SET finished=?, window_start=?, window_end=?, stats_json=?, judge_status=?, report_path=? WHERE id=?",
                 (iso(datetime.datetime.now(datetime.timezone.utc)), since, now_iso, dumps(stats), judge_status, str(path), run_id))
    conn.commit()

    open_rows = [r for r in rec_rows if r["status"] == "open"]
    if send_notification and cfg.notify:
        top = max(open_rows, key=lambda r: (r["impact_minutes_week"] or 0) * (r["confidence"] or 0), default=None)
        notify("Observer: %d recommendations" % len(open_rows), top["title"] if top else "No recurring friction today.")
    conn.close()
    return {"report": str(path), "stats": stats, "judge": judge_status, "open": len(open_rows)}
