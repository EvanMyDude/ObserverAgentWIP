"""Render the daily Markdown report."""
from __future__ import annotations

import json
from collections import Counter

from .recommend import rank_score
from .store import loads

KIND_LABELS = {
    "tool_error": "Tool errors",
    "rejected": "Actions you rejected",
    "denied": "Denied by rules or the auto-mode classifier",
    "permission_prompt": "Permission prompts",
    "interrupt": "Interruptions",
    "correction": "Corrections",
    "retry_loop": "Retry loops",
    "capability_gap": "Agent said it lacked access",
    "api_failure": "API failures",
    "compaction": "Context compactions",
    "repeated_instruction": "Instructions you repeated across sessions",
}


def _code(text: str, lang: str = "") -> str:
    fence = "````" if "```" in text else "```"
    return "%s%s\n%s\n%s" % (fence, lang, text.rstrip(), fence)


def render_patch(patch: dict) -> str:
    kind = patch.get("kind")
    if kind == "settings_merge":
        return "Add to `%s` (merge into the existing arrays):\n\n%s" % (
            patch.get("file"), _code(json.dumps(patch.get("merge"), indent=2), "json"))
    if kind == "append":
        return "Append to `%s`:\n\n%s" % (patch.get("file"), _code(str(patch.get("text", "")), "markdown"))
    if kind == "command":
        return "Run:\n\n%s" % _code(str(patch.get("command", "")), "bash")
    steps = str(patch.get("steps") or "")
    if patch.get("permissions"):
        steps += "\n\n%s" % _code(json.dumps({"permissions": patch["permissions"]}, indent=2), "json")
    file = patch.get("file")
    return steps + ("\n\nFile: `%s`" % file if file else "")


def _indent(text: str, prefix: str = "   ") -> str:
    return "\n".join(prefix + line if line.strip() else line for line in text.splitlines())


def _rec_block(n: int, row, cfg) -> str:
    evidence = loads(row["evidence_json"], {}) or {}
    patch = loads(row["patch_json"], {}) or {}
    head = "%d. **%s**  \n   `%s` · %s · %s risk · about %.0f min/week · confidence %.0f%%" % (
        n, row["title"], row["id"], row["type"], row["risk"] or "?", row["impact_minutes_week"] or 0,
        100 * (row["confidence"] or 0))
    lines = [head, "", _indent(row["rationale"] or "")]
    if evidence.get("judge_note"):
        lines += ["", _indent("*%s*" % evidence["judge_note"])]
    if row["source"] == "judge":
        lines += ["", _indent("*Suggested by the LLM review; last proposed %s.*" % (row["last_seen"] or "")[:10])]
    lines += ["", _indent(render_patch(patch))]
    meta = "Evidence: %d events in %d sessions, last seen %s." % (
        evidence.get("count", 0), evidence.get("sessions", 0), (evidence.get("last") or "")[:10])
    examples = evidence.get("examples") or []
    if examples:
        meta += " Latest example: %s" % _inline(examples[0].get("detail", ""), cfg.excerpt_chars // 2)
    lines += ["", _indent(meta), _indent("Verify: %s" % (row["verify"] or "")),
              _indent("Done or not wanted: `observer done %s` / `observer dismiss %s`" % (row["id"], row["id"]))]
    return "\n".join(lines)


def _inline(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    if len(text) > limit:
        text = text[:limit] + "..."
    return "`%s`" % text.replace("`", "'") if text else ""


def render(ctx: dict, cfg) -> str:
    now = ctx["now"]
    rows = ctx["recommendations"]          # DB rows for recommendations seen in this run
    current = [r for r in rows if r["status"] == "open"]
    demoted = {r["id"] for r in current if (loads(r["evidence_json"], {}) or {}).get("demoted")}
    ranked = sorted(current, key=rank_score, reverse=True)
    do_today = [r for r in ranked if r["id"] not in demoted and (r["confidence"] or 0) >= 0.6][: cfg.max_do_today]
    consider = [r for r in ranked if r not in do_today]
    blocked = [r for r in rows if r["status"] == "blocked"]

    out = ["# Observer report: %s" % now.astimezone().strftime("%Y-%m-%d"), ""]
    new = ctx["new_sessions"]
    out.append("Generated %s. Recommendations use the last %d days; %d new session%s since the previous run." % (
        now.astimezone().strftime("%Y-%m-%d %H:%M %Z"), cfg.window_days, new, "" if new == 1 else "s"))
    out.append("")
    if ctx.get("summary"):
        out += ["> " + ctx["summary"].replace("\n", "\n> "), ""]

    out.append("## Do today")
    out.append("")
    if do_today:
        out += [_rec_block(i + 1, r, cfg) + "\n" for i, r in enumerate(do_today)]
    else:
        out += ["Nothing crossed the thresholds. Agents ran without recurring friction, or there is not enough history yet.", ""]

    if consider:
        out += ["## Consider", "", "Lower confidence, questioned by the judge, or beyond today's top %d." % cfg.max_do_today, ""]
        out += [_rec_block(i + 1, r, cfg) + "\n" for i, r in enumerate(consider[:10])]

    if blocked:
        out += ["## Blocked by policy", "", "Considered and refused by the deterministic gate. Apply by hand only if you disagree.", ""]
        for r in blocked[:10]:
            out.append("- **%s** (`%s`): %s" % (r["title"], r["id"], r["status_reason"]))
        out.append("")

    wins = ctx["outcomes"]
    if wins:
        out += ["## Applied changes", "", "| Change | Status | Applied | Effect |", "|---|---|---|---|"]
        for r in wins:
            out.append("| %s | %s | %s | %s |" % (r["title"].replace("|", "/"), r["status"], (r["applied_at"] or "")[:10],
                                                (r["status_reason"] or "measuring").replace("|", "/")))
        out.append("")

    score = ctx["scorecard"]
    if score:
        out += ["## Agent scorecard", "", "Problems are tool errors, rejections, denials, retry loops, interruptions, "
                "corrections, and missing-access statements, per 100 tool calls over %d days." % cfg.window_days, "",
                "| Agent | Tool calls | Sessions | Problems per 100 | Top problems | Flag |", "|---|---:|---:|---:|---|---|"]
        for r in score[:15]:
            top = ", ".join("%s %d" % (k.replace("_", " "), n) for k, n in r["top"][:3]) or "none"
            flag = "underperforming" if r["underperforming"] else ""
            rate = "%.1f" % r["rate"] if r["calls"] >= cfg.min_tool_calls_for_scorecard else "n/a (few calls)"
            out.append("| %s | %d | %d | %s | %s | %s |" % (r["agent"], r["calls"], r["sessions"], rate, top, flag))
        out.append("")

    kinds = ctx["friction_by_kind"]
    if kinds:
        out += ["## Friction seen (%d days)" % cfg.window_days, "", "| Kind | Events | Sessions | Est. minutes |", "|---|---:|---:|---:|"]
        for kind, (count, sessions, minutes) in sorted(kinds.items(), key=lambda kv: -kv[1][2]):
            out.append("| %s | %d | %d | %.0f |" % (KIND_LABELS.get(kind, kind), count, sessions, minutes))
        out.append("")
        if ctx.get("attribution_counts"):
            causes = ", ".join("%s %d" % (k.replace("_", " "), n) for k, n in ctx["attribution_counts"].most_common())
            out += ["Judge's cause attribution across clusters: %s." % causes, ""]

    out += ["## Pipeline health", ""]
    health = ctx["health"]
    for line in health:
        out.append("- " + line)
    out.append("")
    return "\n".join(out)


def friction_by_kind(conn, start: str) -> dict:
    out = {}
    for r in conn.execute(
        "SELECT kind, COUNT(*) n, COUNT(DISTINCT session_id) s, SUM(cost_seconds) c FROM frictions WHERE ts >= ? GROUP BY kind",
        (start,),
    ):
        out[r["kind"]] = (r["n"], r["s"], (r["c"] or 0) / 60.0)
    return out


def health_lines(ingest_stats: Counter, spool_stats: Counter, hook_total: int, judge_status: str, unknown: Counter,
                 hooks_installed: bool, notification_counts: Counter, totals: dict) -> list:
    # Ingestion is incremental, so "new" counts are zero whenever nothing changed since the last run.
    lines = [
        "Transcripts: %d files checked (%d Claude Code, %d Cowork); %d changed since the last run, adding %d records "
        "and %d tool calls (%d parse errors). Database: %d sessions, %d tool calls." % (
            ingest_stats.get("files_seen", 0), ingest_stats.get("files_cli", 0), ingest_stats.get("files_cowork", 0),
            ingest_stats.get("files_read", 0), ingest_stats.get("records", 0), ingest_stats.get("tool_calls", 0),
            ingest_stats.get("parse_errors", 0), totals.get("sessions", 0), totals.get("tool_calls", 0)),
    ]
    lines.append("Sessions started in the last 7 days: %d Claude Code, %d Cowork." % (
        totals.get("recent_cli", 0), totals.get("recent_cowork", 0)))
    if totals.get("unmatched_hook_sessions"):
        lines.append("%d sessions fired hooks this week but have no transcript the observer can find; they may be "
                     "stored somewhere transcript_roots does not cover." % totals["unmatched_hook_sessions"])
    if unknown:
        lines.append("Record types the parser does not recognize (usually new metadata, and harmless while tool calls "
                     "keep being added): %s." % ", ".join("%s %d" % kv for kv in unknown.most_common(5)))
    if hooks_installed or hook_total:
        lines.append("Hooks: %d new events this run, %d in the database." % (spool_stats.get("hook_events", 0), hook_total))
        if notification_counts:
            lines.append("Agents notified you: %s." % ", ".join("%s %d" % kv for kv in notification_counts.most_common()))
    else:
        lines.append("Hooks are not installed, so permission-prompt approvals are invisible. Run `observer install-hooks --yes`.")
    lines.append("Judge: %s." % judge_status)
    return lines
