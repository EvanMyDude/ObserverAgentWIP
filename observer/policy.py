"""Deterministic policy gate. It runs after the rules and after the judge, and it has the final say.

The observer reads untrusted text and proposes permission changes; this gate is what keeps a
crafted tool output from turning into a recommendation that widens access. It sets `risk` on
every recommendation and `blocked_reason` on the ones it refuses.
"""
from __future__ import annotations

import os
import re

from . import classify

ALLOWED_TYPES = {
    "allow_permission", "deny_permission", "add_dir", "install_tool", "add_context", "tune_agent",
    "fix_environment", "add_capability", "create_skill", "tune_auto_mode",
}
ALLOWED_SETTINGS_KEYS = {"allow", "deny", "ask", "additionalDirectories"}
MAX_TEXT = 1200
_SUSPICIOUS_TEXT = re.compile(
    r"bypass|dangerously|skip[- ]?permissions?|--no-verify|disable(?:AllHooks| hooks?)|ignore (?:all |any )?(?:previous|prior|above) "
    r"(?:instructions|rules)|permission[- ]?mode|defaultMode|auto[- ]?approve|without (?:asking|approval|confirmation)|"
    r"curl [^\n]*\|\s*(?:ba)?sh|base64 -d|rm -rf|chmod 777|exfiltrat",
    re.I,
)
_INSTALL_RE = re.compile(r"^brew install [a-z0-9][a-z0-9@+._/-]*$")
_GENERIC_INSTALL_RE = re.compile(r"^install [A-Za-z0-9][A-Za-z0-9@+._-]* with your package manager$")
_CONTEXT_FILE_RE = re.compile(r"(?:^|/)(?:CLAUDE(?:\.local)?\.md|SKILL\.md|\.claude/rules/[\w.-]+\.md|\.claude/agents/[\w.-]+\.md)$")


def _risk_max(a: str, b: str) -> str:
    return a if classify.RISK_ORDER[a] >= classify.RISK_ORDER[b] else b


def _check_settings_merge(rec, patch) -> tuple:
    file = str(patch.get("file", ""))
    if not re.search(r"(?:^|/)\.claude/settings(?:\.local)?\.json$", file):
        return None, "settings patch must target a Claude Code settings.json"
    merge = patch.get("merge")
    if not isinstance(merge, dict) or set(merge) != {"permissions"} or not isinstance(merge["permissions"], dict):
        return None, "settings patch may only touch `permissions`"
    return _check_permissions(merge["permissions"])


def _check_permissions(perms) -> tuple:
    if not isinstance(perms, dict) or not perms or not set(perms) <= ALLOWED_SETTINGS_KEYS:
        return None, "settings patch may only add allow, deny, ask, or additionalDirectories entries"
    risk, reason = classify.LOW, "contraction"
    for key, values in perms.items():
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and v.strip() for v in values):
            return None, "malformed %s list" % key
        for value in values:
            if key == "allow":
                level, why = classify.rule_risk(value)
                if level == classify.HIGH:
                    return None, "`%s` is high risk: %s" % (value, why)
                if level == classify.MEDIUM and risk == classify.LOW:
                    risk, reason = level, why
                elif level == classify.LOW and reason == "contraction":
                    reason = why
            elif key in ("deny", "ask"):
                tool, content = classify.parse_rule(value)
                if tool is None:
                    return None, "unparseable rule `%s`" % value
                if not content and not tool.startswith("mcp__"):
                    return None, "`%s` would %s every use of %s" % (value, key, tool)
            elif key == "additionalDirectories":
                path = value.strip()
                expanded = os.path.expanduser(path)
                if classify.is_secret_path(path) or classify._broad_path(expanded) or expanded.rstrip("/") == os.path.expanduser("~"):
                    return None, "`%s` is too broad or holds secrets" % value
                if any(part == ".." for part in path.split("/")):
                    return None, "relative parent paths are not allowed"
                risk, reason = _risk_max(risk, classify.MEDIUM), "grants file read and write access to a new directory"
    return risk, reason


def gate(rec) -> None:
    """Set rec.risk and rec.risk_reason; set rec.blocked_reason when refused."""
    rec.blocked_reason = ""
    if rec.type not in ALLOWED_TYPES:
        rec.risk, rec.blocked_reason = classify.HIGH, "unknown recommendation type %r" % rec.type
        return
    if not rec.evidence or not rec.evidence.get("friction_ids"):
        rec.risk, rec.blocked_reason = classify.HIGH, "no evidence in the database supports it"
        return
    patch = rec.patch if isinstance(rec.patch, dict) else {}
    kind = patch.get("kind")
    risk, reason = None, ""
    if kind == "settings_merge":
        risk, reason = _check_settings_merge(rec, patch)
    elif kind == "append":
        file = str(patch.get("file", ""))
        text = str(patch.get("text", ""))
        if not _CONTEXT_FILE_RE.search(file):
            reason = "context can only be appended to CLAUDE.md, SKILL.md, or .claude/rules or agents files"
        elif not text.strip() or len(text) > MAX_TEXT:
            reason = "context text is empty or longer than %d characters" % MAX_TEXT
        elif _SUSPICIOUS_TEXT.search(text):
            reason = "context text mentions bypassing safeguards, secrets, or risky commands"
        else:
            risk, reason = classify.LOW, "adds instructions only"
    elif kind == "command":
        command = str(patch.get("command", ""))
        if _INSTALL_RE.match(command):
            risk, reason = classify.MEDIUM, "installs a package from Homebrew"
        elif _GENERIC_INSTALL_RE.match(command):
            risk, reason = classify.MEDIUM, "installs a package"
        else:
            reason = "only `brew install <formula>` commands are allowed"
    elif kind == "manual":
        text = " ".join(str(patch.get(k, "")) for k in ("steps", "text"))
        if _SUSPICIOUS_TEXT.search(text):
            reason = "instructions mention bypassing safeguards, secrets, or risky commands"
        elif patch.get("permissions") is not None:
            # A permission change rewritten as manual steps (Cowork) is rated exactly like the patch it replaced.
            risk, reason = _check_permissions(patch["permissions"])
        else:
            risk, reason = classify.LOW, "manual review; nothing is changed automatically"
    else:
        reason = "unknown patch kind %r" % kind
    if risk is None:
        rec.risk, rec.risk_reason, rec.blocked_reason = classify.HIGH, "", reason
        return
    rec.risk, rec.risk_reason = risk, reason
