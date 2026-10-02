"""Install and inspect the observer: user-scope hooks, the launchd schedule, and a health check."""
from __future__ import annotations

import datetime
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .config import Config

HOOK_EVENTS = ["PermissionRequest", "PermissionDenied", "Notification", "StopFailure", "SessionEnd"]
HOOK_SCRIPT = Path(__file__).resolve().parent / "hook.py"
HOOK_MARKER = "observer/hook.py"
REPO_ROOT = Path(__file__).resolve().parent.parent
LABEL = "dev.observer.daily"


def claude_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude")).expanduser()


def settings_path() -> Path:
    return claude_dir() / "settings.json"


def plist_path() -> Path:
    return Path("~/Library/LaunchAgents/%s.plist" % LABEL).expanduser()


def hook_command(python: str = sys.executable) -> str:
    return "%s %s" % (shlex.quote(python), shlex.quote(str(HOOK_SCRIPT)))


def _is_ours(handler) -> bool:
    return isinstance(handler, dict) and HOOK_MARKER in str(handler.get("command", ""))


def hooks_installed(path: Path | None = None) -> bool:
    try:
        data = json.loads((path or settings_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return HOOK_MARKER in json.dumps(data.get("hooks", {}) if isinstance(data, dict) else {})


def merge_hooks(settings: dict, command: str) -> list:
    """Add our handler to each event once. Returns the events that changed."""
    hooks = settings.setdefault("hooks", {})
    changed = []
    for event in HOOK_EVENTS:
        groups = hooks.setdefault(event, [])
        if any(_is_ours(h) for g in groups if isinstance(g, dict) for h in g.get("hooks", [])):
            continue
        groups.append({"matcher": "", "hooks": [{"type": "command", "command": command, "timeout": 10}]})
        changed.append(event)
    return changed


def remove_hooks(settings: dict) -> list:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return []
    changed = []
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            if not isinstance(group, dict):
                kept_groups.append(group)
                continue
            handlers = [h for h in group.get("hooks", []) if not _is_ours(h)]
            if len(handlers) != len(group.get("hooks", [])):
                changed.append(event)
            if handlers:
                kept_groups.append(dict(group, hooks=handlers))
        if kept_groups:
            hooks[event] = kept_groups
        else:
            del hooks[event]
    if not hooks:
        settings.pop("hooks", None)
    return sorted(set(changed))


def _read_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("%s does not contain a JSON object" % path)
    return data


def _write_settings(path: Path, data: dict) -> Path | None:
    backup = None
    if path.exists():
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = path.with_name("%s.observer-backup-%s" % (path.name, stamp))
        shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".observer-tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if backup is not None:
        shutil.copymode(backup, tmp)
    os.replace(tmp, path)
    return backup


def install_hooks(apply: bool) -> int:
    path = settings_path()
    try:
        data = _read_settings(path)
    except ValueError as exc:
        print("Cannot parse %s: %s. Fix it first; nothing was changed." % (path, exc))
        return 1
    command = hook_command()
    changed = merge_hooks(data, command)
    if not changed:
        print("Observer hooks are already installed in %s." % path)
        return 0
    print("Will add this handler to %s for: %s" % (path, ", ".join(changed)))
    print("  %s" % command)
    if not apply:
        print("Dry run. Re-run with --yes to write (a timestamped backup is made first).")
        return 0
    backup = _write_settings(path, data)
    print("Wrote %s%s." % (path, " (backup: %s)" % backup if backup else ""))
    print("New Claude Code sessions pick this up; running sessions keep their old hooks.")
    return 0


def uninstall_hooks(apply: bool) -> int:
    path = settings_path()
    try:
        data = _read_settings(path)
    except ValueError as exc:
        print("Cannot parse %s: %s" % (path, exc))
        return 1
    changed = remove_hooks(data)
    if not changed:
        print("No observer hooks found in %s." % path)
        return 0
    print("Will remove observer hooks from: %s" % ", ".join(changed))
    if not apply:
        print("Dry run. Re-run with --yes to write.")
        return 0
    backup = _write_settings(path, data)
    print("Wrote %s (backup: %s)." % (path, backup))
    return 0


def _launchd_plist(cfg: Config, hour: int, minute: int) -> dict:
    claude = shutil.which(cfg.claude_bin) or cfg.claude_bin
    path_dirs = [os.path.dirname(claude)] if os.path.isabs(claude) else []
    path_dirs += ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    env = {"PATH": ":".join(dict.fromkeys(path_dirs)), "PYTHONPATH": str(REPO_ROOT)}
    if os.environ.get("OBSERVER_HOME"):
        env["OBSERVER_HOME"] = os.environ["OBSERVER_HOME"]
    if os.environ.get("CLAUDE_CONFIG_DIR"):
        env["CLAUDE_CONFIG_DIR"] = os.environ["CLAUDE_CONFIG_DIR"]
    return {
        "Label": LABEL,
        "ProgramArguments": [sys.executable, "-m", "observer", "run", "--notify"],
        "WorkingDirectory": str(REPO_ROOT),
        "EnvironmentVariables": env,
        # launchd runs a calendar job missed during sleep once, on wake.
        "StartCalendarInterval": {"Hour": hour, "Minute": minute},
        "StandardOutPath": str(cfg.logs_dir / "launchd.out.log"),
        "StandardErrorPath": str(cfg.logs_dir / "launchd.err.log"),
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 10,
    }


def install_schedule(cfg: Config, hour: int, minute: int, load: bool) -> int:
    if sys.platform != "darwin":
        print("launchd is macOS only. On Linux, add this line with `crontab -e`:")
        print("  %d %d * * * cd %s && PYTHONPATH=%s %s -m observer run >> %s 2>&1" % (
            minute, hour, shlex.quote(str(REPO_ROOT)), shlex.quote(str(REPO_ROOT)), shlex.quote(sys.executable),
            shlex.quote(str(cfg.logs_dir / "cron.log"))))
        return 0
    cfg.logs_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = plist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        plistlib.dump(_launchd_plist(cfg, hour, minute), fh)
    print("Wrote %s (daily at %02d:%02d local time)." % (path, hour, minute))
    domain = "gui/%d" % os.getuid()
    commands = [["launchctl", "bootout", "%s/%s" % (domain, LABEL)], ["launchctl", "bootstrap", domain, str(path)]]
    if not load:
        print("Load it with:")
        for cmd in commands:
            print("  " + " ".join(shlex.quote(c) for c in cmd))
        return 0
    subprocess.run(commands[0], capture_output=True)  # fine if it was not loaded
    result = subprocess.run(commands[1], capture_output=True, text=True)
    if result.returncode != 0:
        print("launchctl bootstrap failed: %s" % (result.stderr.strip() or result.returncode))
        return 1
    print("Loaded. Run it now with: launchctl kickstart %s/%s" % (domain, LABEL))
    return 0


def uninstall_schedule() -> int:
    path = plist_path()
    if sys.platform == "darwin":
        subprocess.run(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), LABEL)], capture_output=True)
    if path.exists():
        path.unlink()
        print("Removed %s." % path)
    else:
        print("No schedule installed.")
    return 0


def doctor(cfg: Config) -> int:
    ok = True

    def line(good: bool, text: str):
        nonlocal ok
        ok = ok and good
        print("%s %s" % ("[ok]  " if good else "[warn]", text))

    line(sys.version_info >= (3, 9), "Python %s at %s" % (sys.version.split()[0], sys.executable))
    for root in cfg.roots():
        count = len(list(root.glob("*/*.jsonl"))) if root.is_dir() else 0
        line(count > 0, "Transcripts: %d session files under %s" % (count, root))
    claude = shutil.which(cfg.claude_bin)
    version = ""
    if claude:
        try:
            version = subprocess.run([claude, "--version"], capture_output=True, text=True, timeout=20).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            version = "version unknown"
    line(bool(claude), "claude CLI: %s %s" % (claude or "not found on PATH (the judge step will be skipped)", version))
    line(hooks_installed(), "Hooks in %s: %s" % (settings_path(), "installed" if hooks_installed() else
                                                  "not installed (run `observer install-hooks --yes`)"))
    if sys.platform == "darwin":
        line(plist_path().exists(), "Schedule: %s" % (plist_path() if plist_path().exists() else
                                                       "not installed (run `observer install-schedule --load`)"))
    spool_files = list(cfg.spool_dir.glob("*.jsonl")) if cfg.spool_dir.is_dir() else []
    print("[info] Spool: %d files in %s" % (len(spool_files), cfg.spool_dir))
    if cfg.db_path.exists():
        import sqlite3
        conn = sqlite3.connect(str(cfg.db_path))
        row = conn.execute("SELECT finished, judge_status FROM runs WHERE finished IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        print("[info] Last run: %s" % ("%s, judge %s" % row if row else "never completed"))
    else:
        print("[info] No database yet; run `observer run`.")
    support = Path("~/Library/Application Support/Claude").expanduser()
    if support.is_dir():
        found = {}
        for path in support.rglob("*.jsonl"):
            found.setdefault(str(path.parent), 0)
            found[str(path.parent)] += 1
            if len(found) > 20:
                break
        if found:
            print("[info] JSONL directories under %s (possible Desktop or Cowork transcripts; the format is not "
                  "verified, so inspect before adding a parent to transcript_roots):" % support)
            for directory, n in sorted(found.items(), key=lambda kv: -kv[1])[:10]:
                print("       %4d  %s" % (n, directory))
    return 0 if ok else 1
