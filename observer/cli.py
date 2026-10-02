"""Command line interface: `python3 -m observer <command>`."""
from __future__ import annotations

import argparse
import json
import sys

from . import install, outcomes, pipeline
from .config import ensure_home, load_config
from .recommend import rank_score
from .report import render_patch
from .store import connect, loads


def _conn(cfg):
    ensure_home(cfg)
    return connect(cfg.db_path)


def cmd_run(cfg, args) -> int:
    result = pipeline.run(cfg, use_judge=not args.no_llm, send_notification=args.notify)
    print("Report: %s" % result["report"])
    print("Open recommendations: %d. Judge: %s" % (result["open"], result["judge"]))
    return 0


def cmd_list(cfg, args) -> int:
    conn = _conn(cfg)
    statuses = ("open", "blocked", "applied", "verified", "not_effective", "dismissed") if args.all else ("open",)
    rows = conn.execute(
        "SELECT * FROM recommendations WHERE status IN (%s)" % ",".join("?" * len(statuses)), statuses).fetchall()
    rows = sorted(rows, key=rank_score, reverse=True)
    if not rows:
        print("No recommendations%s." % ("" if args.all else " open"))
    for r in rows:
        print("%s  %-13s %-6s %5.0f min/wk  %s" % (r["id"], r["status"], r["risk"] or "?", r["impact_minutes_week"] or 0, r["title"]))
    return 0


def cmd_show(cfg, args) -> int:
    conn = _conn(cfg)
    r = conn.execute("SELECT * FROM recommendations WHERE id=?", (args.id,)).fetchone()
    if r is None:
        print("No recommendation %s." % args.id)
        return 1
    evidence = loads(r["evidence_json"], {}) or {}
    print("%s  %s\n" % (r["id"], r["title"]))
    print("Type: %s   Status: %s   Risk: %s (%s)   Source: %s" % (
        r["type"], r["status"], r["risk"], evidence.get("risk_reason", ""), r["source"]))
    if r["status_reason"]:
        print("Status reason: %s" % r["status_reason"])
    print("\n%s\n" % r["rationale"])
    print(render_patch(loads(r["patch_json"], {}) or {}))
    print("\nVerify: %s" % r["verify"])
    print("\nEvidence: %d events, %d sessions, %s to %s" % (
        evidence.get("count", 0), evidence.get("sessions", 0), evidence.get("first", ""), evidence.get("last", "")))
    for example in evidence.get("examples", []):
        print("  - %s  %s" % (example.get("ts", ""), example.get("detail", "")[:300]))
    if args.json:
        print(json.dumps(dict(r), indent=2, default=str))
    return 0


def cmd_done(cfg, args) -> int:
    ok = outcomes.mark_done(_conn(cfg), args.id, cfg)
    print("Marked %s as applied; its effect is measured after %d days." % (args.id, cfg.verify_after_days) if ok
          else "No recommendation %s." % args.id)
    return 0 if ok else 1


def cmd_dismiss(cfg, args) -> int:
    ok = outcomes.dismiss(_conn(cfg), args.id, args.reason)
    print("Dismissed %s; it returns only if its evidence doubles." % args.id if ok else "No recommendation %s." % args.id)
    return 0 if ok else 1


def cmd_report(cfg, args) -> int:
    path = cfg.reports_dir / "latest.md"
    if not path.exists():
        print("No report yet; run `observer run`.")
        return 1
    sys.stdout.write(path.read_text(encoding="utf-8"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="observer", description="Friction logger and daily advisor for local AI agents.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="ingest, detect, recommend, and write today's report")
    p.add_argument("--no-llm", action="store_true", help="skip the judge; deterministic rules only")
    p.add_argument("--notify", action="store_true", help="show a macOS notification with the top item")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("list", help="list open recommendations")
    p.add_argument("--all", action="store_true", help="include applied, verified, dismissed, and blocked")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="show one recommendation with its patch and evidence")
    p.add_argument("id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("done", help="mark a recommendation applied (for ones the observer cannot detect)")
    p.add_argument("id")
    p.set_defaults(func=cmd_done)

    p = sub.add_parser("dismiss", help="suppress a recommendation until its evidence doubles")
    p.add_argument("id")
    p.add_argument("--reason")
    p.set_defaults(func=cmd_dismiss)

    p = sub.add_parser("report", help="print the latest report")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("doctor", help="check transcripts, hooks, schedule, and the claude CLI")
    p.set_defaults(func=lambda cfg, args: install.doctor(cfg))

    p = sub.add_parser("install-hooks", help="add the observer hook to ~/.claude/settings.json")
    p.add_argument("--yes", action="store_true", help="write the change (default is a dry run)")
    p.set_defaults(func=lambda cfg, args: install.install_hooks(args.yes))

    p = sub.add_parser("uninstall-hooks", help="remove the observer hook")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=lambda cfg, args: install.uninstall_hooks(args.yes))

    p = sub.add_parser("install-schedule", help="write the launchd job (macOS) or print a cron line")
    p.add_argument("--hour", type=int, default=6)
    p.add_argument("--minute", type=int, default=0)
    p.add_argument("--load", action="store_true", help="load it into launchd now")
    p.set_defaults(func=lambda cfg, args: install.install_schedule(cfg, args.hour, args.minute, args.load))

    p = sub.add_parser("uninstall-schedule", help="unload and remove the launchd job")
    p.set_defaults(func=lambda cfg, args: install.uninstall_schedule())
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(load_config(), args)
