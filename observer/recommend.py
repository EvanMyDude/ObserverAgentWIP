"""Cluster frictions and derive candidate recommendations with exact patches.

Every candidate follows the intervention ladder in the design spec: the lowest rung that addresses
the evidence. Numbers (counts, costs, impact) come from the database, never from the judge.
"""
from __future__ import annotations

import datetime
import hashlib
import os
import re
import shutil
import sqlite3
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import classify
from .config import Config
from .detect import AGENT_FAULT_KINDS, COWORK_PREFIX, iso
from .store import loads

RISK_WEIGHT = {"low": 1.0, "medium": 2.0, "high": 6.0}

# Program -> Homebrew formula where the names differ.
BREW_FORMULA = {
    "rg": "ripgrep", "fd": "fd", "pdftotext": "poppler", "pdfinfo": "poppler", "pdftoppm": "poppler",
    "convert": "imagemagick", "magick": "imagemagick", "psql": "libpq", "tesseract": "tesseract",
    "gs": "ghostscript", "http": "httpie", "ag": "the_silver_searcher", "7z": "p7zip", "gsed": "gnu-sed",
    "timeout": "coreutils", "gtimeout": "coreutils", "realpath": "coreutils", "sha256sum": "coreutils",
    "ffmpeg": "ffmpeg", "yq": "yq", "jq": "jq", "gh": "gh", "uv": "uv", "tree": "tree", "wget": "wget",
    "shellcheck": "shellcheck", "ocrmypdf": "ocrmypdf", "qpdf": "qpdf", "exiftool": "exiftool",
}
# Missing programs that indicate a naming mismatch rather than a missing install.
ALIASES = {"python": "python3", "pip": "pip3"}
# Where Homebrew and user installs live; launchd and some agent shells omit these from PATH.
EXTRA_PATH = ["/opt/homebrew/bin", "/usr/local/bin", os.path.expanduser("~/.local/bin")]


@dataclass
class Cluster:
    id: str
    kind: str
    subkind: str
    fingerprint: str
    friction_ids: list = field(default_factory=list)
    sessions: set = field(default_factory=set)
    projects: set = field(default_factory=set)
    agents: set = field(default_factory=set)
    tools: set = field(default_factory=set)
    cost_seconds: float = 0.0
    first: str = ""
    last: str = ""
    examples: list = field(default_factory=list)  # (friction id, ts, detail)
    metas: list = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.friction_ids)

    def to_pack(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "subkind": self.subkind, "fingerprint": self.fingerprint,
            "count": self.count, "sessions": len(self.sessions), "projects": sorted(self.projects)[:5],
            "agents": sorted(self.agents)[:5], "tools": sorted(t for t in self.tools if t)[:5],
            "cost_minutes": round(self.cost_seconds / 60, 1), "first": self.first, "last": self.last,
        }


@dataclass
class Rec:
    type: str
    target: str
    title: str
    rationale: str
    patch: dict
    verify: str
    confidence: float
    clusters: list
    source: str = "rule"
    risk: str = ""
    risk_reason: str = ""
    blocked_reason: str = ""
    judge_note: str = ""
    demoted: bool = False
    impact_minutes_week: float = 0.0
    evidence: dict = field(default_factory=dict)
    fingerprints: list = field(default_factory=list)

    @property
    def id(self) -> str:
        return "r" + hashlib.sha1(("%s|%s" % (self.type, self.target)).encode("utf-8")).hexdigest()[:8]

    def attach_evidence(self, clusters: list, window_days: int) -> None:
        ids, sessions, projects, examples = [], set(), set(), []
        cost, first, last = 0.0, "", ""
        for c in clusters:
            ids.extend(c.friction_ids)
            sessions |= c.sessions
            projects |= c.projects
            examples.extend(c.examples)
            cost += c.cost_seconds
            first = min(first, c.first) if first else c.first
            last = max(last, c.last)
        examples.sort(key=lambda e: e[1], reverse=True)
        self.clusters = [c.id for c in clusters]
        self.fingerprints = sorted({(c.kind, c.fingerprint) for c in clusters})
        self.impact_minutes_week = round(cost / 60.0 * 7.0 / max(window_days, 1), 1)
        self.evidence = {
            "count": len(ids), "sessions": len(sessions), "projects": sorted(projects), "first": first, "last": last,
            "cost_minutes": round(cost / 60.0, 1), "friction_ids": ids[:200],
            "examples": [{"id": e[0], "ts": e[1], "detail": e[2]} for e in examples[:3]],
            "clusters": self.clusters,
        }


def for_cowork(rec: Rec) -> None:
    """Rewrite a recommendation whose evidence comes only from Cowork. Cowork sessions run with their own
    configuration directory (an inference from where they store transcripts), so a patch to ~/.claude may not
    reach them. The original permission entries stay in the patch so the policy gate still rates them."""
    patch = rec.patch
    kind = patch.get("kind")
    if kind == "append":
        steps = "Add this to Cowork's instructions (global, or the project's):\n\n%s" % patch.get("text", "")
        rec.patch = {"kind": "manual", "steps": steps}
    elif kind == "settings_merge":
        steps = ("This came from Cowork sessions, which keep their own configuration, so it may not take effect in %s. "
                 "Apply the equivalent through Cowork's own approval prompts or settings." % patch.get("file"))
        rec.patch = {"kind": "manual", "steps": steps, "permissions": (patch.get("merge") or {}).get("permissions")}
    elif kind == "command":
        steps = ("Cowork sessions run in their own environment, so installing `%s` on your Mac may not reach them. Ask "
                 "Cowork to install it inside its session, or tell it what to use instead." % patch.get("program"))
        rec.patch = {"kind": "manual", "steps": steps}
    rec.target = "cowork:%s" % rec.target
    rec.title = "%s (Cowork)" % rec.title


def rank_score(row) -> float:
    """Estimated minutes saved per week, discounted by confidence and risk. One ranking for every view."""
    risk = row["risk"] or "medium"
    return (row["impact_minutes_week"] or 0) * (row["confidence"] or 0) / RISK_WEIGHT.get(risk, RISK_WEIGHT["high"])


def _cid(kind, subkind, fingerprint) -> str:
    return "c" + hashlib.sha1(("%s|%s|%s" % (kind, subkind, fingerprint)).encode("utf-8")).hexdigest()[:6]


def build_clusters(conn: sqlite3.Connection, cfg: Config, now: datetime.datetime) -> dict:
    start = iso(now - datetime.timedelta(days=cfg.window_days))
    clusters = {}
    for f in conn.execute("SELECT * FROM frictions WHERE ts >= ? ORDER BY ts", (start,)):
        key = (f["kind"], f["subkind"] or "", f["fingerprint"])
        c = clusters.get(key)
        if c is None:
            c = clusters[key] = Cluster(_cid(*key), f["kind"], f["subkind"] or "", f["fingerprint"], first=f["ts"])
        c.friction_ids.append(f["id"])
        c.sessions.add(f["session_id"])
        c.projects.add(f["project"])
        c.agents.add(f["agent_key"])
        c.tools.add(f["tool_name"])
        c.cost_seconds += f["cost_seconds"] or 0
        c.last = f["ts"]
        c.examples.append((f["id"], f["ts"], f["detail"] or ""))
        meta = loads(f["meta_json"])
        if meta:
            c.metas.append(meta)
    for c in clusters.values():
        c.examples = sorted(c.examples, key=lambda e: e[1], reverse=True)[:3]
    return clusters


# ------------------------------------------------------------------ targets


def _home_rel(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path == home or path.startswith(home + "/") else path


def settings_target(projects: set) -> str:
    real = sorted(p for p in projects if p and p != "(unknown)")
    if len(real) == 1:
        return _home_rel(os.path.join(real[0], ".claude", "settings.local.json"))
    return "~/.claude/settings.json"


def claude_md_target(projects: set) -> str:
    real = sorted(p for p in projects if p and p != "(unknown)")
    if len(real) == 1:
        return _home_rel(os.path.join(real[0], "CLAUDE.md"))
    return "~/.claude/CLAUDE.md"


def _display_sentence(sentence: str) -> str:
    """Drop conversational lead-ins ("Please", "Also") so the line reads as a standing instruction."""
    text = re.sub(r"^(?:(?:please|pls|also|and|but|so|ok|okay)[,\s]+)+", "", sentence.strip(), flags=re.I)
    return text[:1].upper() + text[1:] if text else sentence.strip()


def _project_label(projects) -> str:
    real = sorted(_home_rel(p) for p in projects if p and p != "(unknown)")
    if not real:
        return "unknown project"
    return real[0] if len(real) == 1 else "%d projects" % len(real)


# ------------------------------------------------------------------ candidate rules


class Recommender:
    def __init__(self, conn: sqlite3.Connection, cfg: Config, now: datetime.datetime, clusters: dict, scorecard_rows: list):
        self.conn = conn
        self.cfg = cfg
        self.now = now
        self.clusters = clusters
        self.scorecard_rows = scorecard_rows
        self.recs = []

    def by_kind(self, kind: str) -> list:
        return [c for c in self.clusters.values() if c.kind == kind]

    def add(self, rec: Rec, clusters: list) -> None:
        rec.attach_evidence(clusters, self.cfg.window_days)
        agents = set().union(*(c.agents for c in clusters)) if clusters else set()
        cowork = {a for a in agents if a and a.startswith(COWORK_PREFIX)}
        if agents and cowork == agents:
            for_cowork(rec)
        elif cowork and rec.patch.get("kind") in ("settings_merge", "append", "command"):
            rec.rationale += (" Some of this happened in Cowork, which runs with its own configuration, so make the "
                              "same change in Cowork too.")
        self.recs.append(rec)

    def recurring(self, count: int, sessions: int) -> bool:
        return count >= self.cfg.min_occurrences and sessions >= self.cfg.min_sessions

    def run(self) -> list:
        self.allow_rules()
        self.deny_rules()
        self.missing_programs()
        self.outside_workdir()
        self.repeated_instructions()
        self.environment()
        self.capability_gaps()
        self.underperforming_agents()
        return self.recs

    def allow_rules(self) -> None:
        by_rule = defaultdict(list)
        for c in self.by_kind("permission_prompt"):
            by_rule[c.fingerprint].append(c)
        for rule, clusters in by_rule.items():
            subs = Counter()
            sessions, projects = set(), set()
            for c in clusters:
                subs[c.subkind] += c.count
                sessions |= c.sessions
                projects |= c.projects
            approved, rejected = subs["approved"], subs["rejected"]
            if rejected or approved < self.cfg.min_occurrences or len(sessions) < self.cfg.min_sessions:
                continue
            target_file = settings_target(projects)
            suggested = any(m.get("suggested") for c in clusters for m in c.metas)
            self.add(Rec(
                type="allow_permission",
                target="%s::%s" % (target_file, rule),
                title="Allow `%s` without prompting" % rule,
                rationale="You were asked %d times across %d sessions and approved every time.%s" % (
                    approved, len(sessions), " Rule text is Claude Code's own suggestion." if suggested else ""),
                patch={"kind": "settings_merge", "file": target_file, "merge": {"permissions": {"allow": [rule]}}},
                verify="Permission prompts for `%s` drop to zero." % rule,
                confidence=min(0.95, 0.6 + 0.05 * approved),
                clusters=[],
            ), [c for c in clusters if c.subkind == "approved"])

    def deny_rules(self) -> None:
        approved_rules = {c.fingerprint for c in self.by_kind("permission_prompt") if c.subkind == "approved"}
        for c in self.by_kind("rejected"):
            if c.fingerprint in approved_rules or not self.recurring(c.count, len(c.sessions)):
                continue
            rule = c.fingerprint
            target_file = settings_target(c.projects)
            self.add(Rec(
                type="deny_permission",
                target="%s::%s" % (target_file, rule),
                title="Stop agents from proposing `%s`" % rule,
                rationale="Agents attempted this %d times in %d sessions and you rejected it every time. A deny rule "
                          "ends the back-and-forth; if you only want to be asked, use `ask` instead." % (c.count, len(c.sessions)),
                patch={"kind": "settings_merge", "file": target_file, "merge": {"permissions": {"deny": [rule]}}},
                verify="Rejections of `%s` drop to zero." % rule,
                confidence=0.7,
                clusters=[],
            ), [c])

    def missing_programs(self) -> None:
        by_prog = defaultdict(list)
        for c in self.by_kind("tool_error"):
            if c.subkind == "command_not_found" and c.fingerprint.startswith("missing:"):
                by_prog[c.fingerprint[len("missing:"):]].append(c)
        for prog, clusters in by_prog.items():
            count = sum(c.count for c in clusters)
            if not prog or count < self.cfg.missing_cli_min_occurrences:
                continue
            projects = set().union(*(c.projects for c in clusters))
            cowork_only = all(a.startswith(COWORK_PREFIX) for c in clusters for a in c.agents)
            if prog in ALIASES:
                target_file = claude_md_target(projects)
                text = "- This machine has `%s`, not `%s`; always call `%s`." % (ALIASES[prog], prog, ALIASES[prog])
                self.add(Rec(
                    type="add_context",
                    target="%s::alias:%s" % (target_file, prog),
                    title="Tell agents to use `%s` instead of `%s`" % (ALIASES[prog], prog),
                    rationale="`%s: command not found` %d times. This is a naming gap, not a missing install." % (prog, count),
                    patch={"kind": "append", "file": target_file, "text": text},
                    verify="`%s: command not found` errors drop to zero." % prog,
                    confidence=0.85,
                    clusters=[],
                ), clusters)
                continue
            # Your Mac's PATH says nothing about Cowork's environment, so skip this check for Cowork-only evidence.
            installed = None if cowork_only else shutil.which(
                prog, path=os.pathsep.join([os.environ.get("PATH", "")] + EXTRA_PATH))
            if installed:
                # Installed but not found by the agent: its shell has a different PATH than yours.
                self.add(Rec(
                    type="fix_environment",
                    target="path:%s" % prog,
                    title="Agents cannot find `%s`, but it is installed" % prog,
                    rationale="`%s: command not found` %d times, yet it exists at `%s`. The agents' shell PATH is "
                              "missing `%s`." % (prog, count, installed, os.path.dirname(installed)),
                    patch={"kind": "manual", "steps": "Add `%s` to PATH in the shell profile Claude Code loads (for "
                                                      "example ~/.zprofile), or set it in the `env` block of "
                                                      "~/.claude/settings.json." % os.path.dirname(installed)},
                    verify="`%s: command not found` errors stop." % prog,
                    confidence=0.7,
                    clusters=[],
                ), clusters)
                continue
            if sys.platform == "darwin":
                formula = BREW_FORMULA.get(prog, prog)
                command = "brew install %s" % formula
                note = "" if prog in BREW_FORMULA else " Check the formula name with `brew search %s` first." % prog
            else:
                command = "install %s with your package manager" % prog
                note = ""
            self.add(Rec(
                type="install_tool",
                target=prog,
                title="Install `%s`" % prog,
                rationale="Agents hit `%s: command not found` %d times in %d sessions.%s" % (
                    prog, count, len(set().union(*(c.sessions for c in clusters))), note),
                patch={"kind": "command", "command": command, "program": prog},
                verify="`%s` is on PATH and the error stops appearing." % prog,
                confidence=0.85,
                clusters=[],
            ), clusters)

    def outside_workdir(self) -> None:
        for c in self.by_kind("tool_error"):
            if c.subkind != "outside_workdir" or not c.fingerprint.startswith("dir:"):
                continue
            directory = c.fingerprint[len("dir:"):]
            if not directory or not self.recurring(c.count, len(c.sessions)):
                continue
            target_file = settings_target(c.projects)
            self.add(Rec(
                type="add_dir",
                target="%s::%s" % (target_file, directory),
                title="Give agents access to `%s`" % _home_rel(directory),
                rationale="Tools were blocked %d times in %d sessions because this directory is outside the working "
                          "directories." % (c.count, len(c.sessions)),
                patch={"kind": "settings_merge", "file": target_file,
                       "merge": {"permissions": {"additionalDirectories": [_home_rel(directory)]}}},
                verify="`outside_workdir` errors for this directory drop to zero.",
                confidence=0.75,
                clusters=[],
            ), [c])

    def repeated_instructions(self) -> None:
        groups = defaultdict(list)
        for c in self.by_kind("repeated_instruction"):
            groups[(frozenset(c.sessions), frozenset(c.projects))].append(c)
        for (sessions, projects), clusters in groups.items():
            clusters.sort(key=lambda c: c.first)
            lines = []
            for c in clusters[:8]:
                sentence = c.examples[0][2] if c.examples else c.fingerprint
                lines.append("- " + _display_sentence(sentence))
            target_file = claude_md_target(set(projects))
            key = hashlib.sha1("|".join(sorted(c.fingerprint for c in clusters)).encode("utf-8")).hexdigest()[:10]
            self.add(Rec(
                type="add_context",
                target="%s::instr:%s" % (target_file, key),
                title="Stop retyping %s into new sessions" % ("this instruction" if len(lines) == 1 else "these %d instructions" % len(lines)),
                rationale="You typed the same text into %d sessions (%s). Put it where every session reads it." % (
                    len(sessions), _project_label(projects)),
                patch={"kind": "append", "file": target_file, "text": "\n".join(lines)},
                verify="The text stops appearing in your prompts.",
                confidence=0.7,
                clusters=[],
            ), clusters)

    def environment(self) -> None:
        advice = {
            "mcp_error": "Run `claude mcp list` and check that server's status and authentication.",
            "auth": "Re-authenticate the tool (for example `gh auth status`, or reconnect the connector).",
            "network": "Check DNS, VPN, or proxy settings for the host involved.",
            "timeout": "Ask agents to run long commands in the background, or raise the tool timeout.",
            "rate_limit": "Space out the calls or raise the quota for this service.",
            "os_permission": "Check file ownership and macOS privacy permissions (Full Disk Access) for the terminal.",
        }
        for c in self.by_kind("tool_error"):
            if c.subkind not in classify.ENVIRONMENT_ERROR_CLASSES or not self.recurring(c.count, len(c.sessions)):
                continue
            self.add(Rec(
                type="fix_environment",
                target=c.fingerprint,
                title="Fix recurring %s failures (%s)" % (c.subkind.replace("_", " "), c.fingerprint.split(":")[1] if ":" in c.fingerprint else c.fingerprint),
                rationale="%d failures in %d sessions. Agents cannot fix this from inside a session." % (c.count, len(c.sessions)),
                patch={"kind": "manual", "steps": advice.get(c.subkind, "Investigate the failing tool.")},
                verify="Failures with this fingerprint stop.",
                confidence=0.5,
                clusters=[],
            ), [c])

    def capability_gaps(self) -> None:
        for c in self.by_kind("capability_gap"):
            if c.count < 2:
                continue
            subject = c.fingerprint[len("gap:"):]
            self.add(Rec(
                type="add_capability",
                target=c.fingerprint,
                title="Agents keep saying they cannot reach: %s" % subject,
                rationale="%d statements in %d sessions. Connect an MCP server, connector, or CLI for it, or tell agents "
                          "where the information lives." % (c.count, len(c.sessions)),
                patch={"kind": "manual", "steps": "Search for a connector with `/mcp` or the plugin directory, or add a "
                                                  "CLAUDE.md line explaining how to reach it."},
                verify="The statement stops appearing.",
                confidence=0.5,
                clusters=[],
            ), [c])

    def underperforming_agents(self) -> None:
        for row in self.scorecard_rows:
            if not row["underperforming"]:
                continue
            clusters = [c for c in self.clusters.values() if row["agent"] in c.agents and c.kind in AGENT_FAULT_KINDS]
            if not clusters:
                continue
            top = ", ".join("%s %d" % (k, n) for k, n in row["top"][:3])
            path = row["definition"]
            self.add(Rec(
                type="tune_agent",
                target=row["agent"],
                title="Tune `%s`: %.0f problems per 100 tool calls" % (row["agent"], row["rate"]),
                rationale="%.1fx the median agent across %d tool calls in %d sessions. Top problems: %s." % (
                    row["ratio"], row["calls"], row["sessions"], top),
                patch={"kind": "manual", "file": path,
                       "steps": "Review the examples and add guidance for the top problem to %s." % (path or "the agent's instructions")},
                verify="This agent's problem rate falls below twice the median.",
                confidence=0.5,
                clusters=[],
            ), clusters)


def scorecard(conn: sqlite3.Connection, cfg: Config, now: datetime.datetime) -> list:
    start = iso(now - datetime.timedelta(days=cfg.window_days))
    calls = defaultdict(int)
    sessions = defaultdict(set)
    for r in conn.execute(
        "SELECT t.agent_type, t.skill, t.session_id, s.surface FROM tool_calls t JOIN sessions s USING(session_id) "
        "WHERE t.ts >= ? AND s.internal = 0", (start,)
    ):
        key = "agent:%s" % r["agent_type"] if r["agent_type"] else ("skill:%s" % r["skill"] if r["skill"] else "main")
        if r["surface"] == "cowork":
            key = COWORK_PREFIX + key  # must match the agent_key detect.Detector.emit writes
        calls[key] += 1
        sessions[key].add(r["session_id"])
    faults = defaultdict(Counter)
    placeholders = ",".join("?" * len(AGENT_FAULT_KINDS))
    for r in conn.execute(
        "SELECT agent_key, kind, COUNT(*) n FROM frictions WHERE ts >= ? AND kind IN (%s) GROUP BY agent_key, kind" % placeholders,
        (start,) + AGENT_FAULT_KINDS,
    ):
        faults[r["agent_key"]][r["kind"]] += r["n"]
    paths = {r["skill"]: r["path"] for r in conn.execute("SELECT skill, path FROM skill_paths")}
    rows = []
    for key, n in calls.items():
        total = sum(faults[key].values())
        rows.append({
            "agent": key, "calls": n, "sessions": len(sessions[key]), "problems": total,
            "rate": 100.0 * total / n if n else 0.0, "top": faults[key].most_common(),
        })
    eligible = [r["rate"] for r in rows if r["calls"] >= cfg.min_tool_calls_for_scorecard]
    median = statistics.median(eligible) if eligible else 0.0
    for r in rows:
        r["ratio"] = r["rate"] / median if median else 0.0
        r["underperforming"] = bool(
            r["calls"] >= cfg.min_tool_calls_for_scorecard and len(eligible) >= 2
            and r["rate"] >= cfg.underperf_min_rate and median > 0 and r["rate"] >= cfg.underperf_ratio * median
        )
        base = r["agent"][len(COWORK_PREFIX):] if r["agent"].startswith(COWORK_PREFIX) else r["agent"]
        name = base.split(":", 1)[-1]
        if base.startswith("skill:") and name in paths:
            r["definition"] = os.path.join(paths[name], "SKILL.md")
        elif base.startswith("agent:"):
            r["definition"] = "~/.claude/agents/%s.md (or the project's .claude/agents/)" % name
        else:
            r["definition"] = ""
    # Agents with too few calls for a meaningful rate go last, so one bad call does not top the table.
    rows.sort(key=lambda r: (r["calls"] < cfg.min_tool_calls_for_scorecard, -r["rate"], -r["calls"]))
    return rows


def candidates(conn: sqlite3.Connection, cfg: Config, now: datetime.datetime, clusters: dict, scorecard_rows: list) -> list:
    return Recommender(conn, cfg, now, clusters, scorecard_rows).run()
