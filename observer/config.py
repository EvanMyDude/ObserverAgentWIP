"""Configuration with defaults, overridable from ~/.observer/config.json."""
from __future__ import annotations

import glob
import json
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path


def observer_home() -> Path:
    return Path(os.environ.get("OBSERVER_HOME", "~/.observer")).expanduser()


def _default_costs() -> dict:
    # Seconds of human or agent time a friction event costs when it cannot be measured
    # from timestamps. Estimates; the report labels derived numbers as estimates.
    return {
        "tool_error": 30,
        "rejected": 45,
        "denied": 30,
        "permission_prompt": 20,
        "interrupt": 60,
        "correction": 90,
        "capability_gap": 120,
        "api_failure": 60,
        "compaction": 30,
        "retry_loop": 0,  # measured from the loop's own timestamps
    }


@dataclass
class Config:
    transcript_roots: list = field(
        default_factory=lambda: [os.path.join(os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude"), "projects")]
    )
    # Cowork runs Claude Code in its own environment and keeps one transcript tree per session here.
    cowork_transcript_globs: list = field(default_factory=lambda: [
        "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/local_*/.claude/projects"
    ])
    window_days: int = 14
    min_occurrences: int = 3
    min_sessions: int = 2
    missing_cli_min_occurrences: int = 2
    repeated_instruction_min_sessions: int = 3
    min_tool_calls_for_scorecard: int = 20
    underperf_ratio: float = 2.0
    underperf_min_rate: float = 10.0
    verify_after_days: int = 7
    verify_drop: float = 0.5
    max_do_today: int = 5
    excerpt_chars: int = 400
    judge_enabled: bool = True
    claude_bin: str = "claude"
    judge_model: str = "opus"
    judge_effort: str = "medium"
    judge_max_budget_usd: float = 2.0
    judge_timeout_s: int = 600
    judge_extra_args: list = field(default_factory=list)
    notify: bool = True
    retention_days: int = 120
    cost_seconds: dict = field(default_factory=_default_costs)

    @property
    def home(self) -> Path:
        return observer_home()

    @property
    def db_path(self) -> Path:
        return self.home / "observer.db"

    @property
    def spool_dir(self) -> Path:
        return self.home / "spool"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    def roots(self) -> list:
        """(directory, surface) pairs: "cli" covers the terminal and the Desktop Code tab; "cowork" covers
        Cowork sessions, which run with their own configuration directory."""
        out = [(Path(r).expanduser(), "cli") for r in self.transcript_roots]
        for pattern in self.cowork_transcript_globs:
            out += [(Path(p), "cowork") for p in sorted(glob.glob(os.path.expanduser(pattern)))]
        return out

    def to_dict(self) -> dict:
        return asdict(self)


def load_config(path: Path | None = None) -> Config:
    cfg = Config()
    path = path or observer_home() / "config.json"
    if not path.exists():
        return cfg
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("observer: ignoring unreadable config %s (%s)" % (path, exc), file=sys.stderr)
        return cfg
    known = {f.name for f in fields(Config)}
    for key, value in data.items():
        if key not in known:
            print("observer: unknown config key %r ignored" % key, file=sys.stderr)
            continue
        if key == "cost_seconds" and isinstance(value, dict):
            cfg.cost_seconds.update(value)
        else:
            setattr(cfg, key, value)
    return cfg


def ensure_home(cfg: Config) -> None:
    for d in (cfg.home, cfg.spool_dir, cfg.reports_dir, cfg.logs_dir):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
