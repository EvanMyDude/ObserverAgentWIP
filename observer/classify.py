"""Deterministic classification: tool results, shell commands, permission rules and their risk.

String patterns were taken from Claude Code 2.1.287 (transcripts and the CLI binary). The
transcript format is internal and can change, so every matcher degrades to a generic class
instead of failing.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
from urllib.parse import urlparse

# ---------------------------------------------------------------- tool results

REJECT_RE = re.compile(r"The user doesn't want to (?:proceed with this tool use|take this action right now)")
DENIED_RE = re.compile(
    r"^(?:<tool_use_error>)?\s*(?:Permission to use .{0,300}? has been denied|"
    r".{0,200}?was blocked by a deny rule|.{0,200}?denied by (?:the )?(?:auto[- ]?mode|classifier|policy))",
    re.I | re.S,
)
INTERRUPT_MARK = "[Request interrupted by user"

_ERROR_PATTERNS = [
    ("outside_workdir", r"outside (?:of )?(?:the |your )?(?:allowed )?working director"),
    ("command_not_found", r"command not found|: not found\b|is not recognized as an internal or external command"),
    ("rate_limit", r"\b429\b|rate[ _-]?limit|too many requests"),
    (
        "auth",
        r"\b401\b|\b403\b|unauthori[sz]ed|forbidden|authentication (?:failed|required|error)|"
        r"not (?:logged|signed) in|invalid (?:api[ _-]?key|token|credentials)|token (?:has )?expired|"
        r"login required|re-?authenticate",
    ),
    (
        "network",
        r"could not resolve host|name or service not known|nodename nor servname|getaddrinfo|"
        r"(?-i:\bE(?:CONNREFUSED|CONNRESET|TIMEDOUT|NOTFOUND|AI_AGAIN)\b)|network is unreachable|"
        r"connection (?:refused|reset|timed out)|certificate verify failed|SSL(?:Error| routines)",
    ),
    ("timeout", r"timed out|timeout"),
    ("edit_mismatch", r"String to replace not found|matches of the string to replace"),
    ("not_read_first", r"File has not been read yet|File must be read first|modified since (?:it was )?(?:last )?read"),
    ("file_too_large", r"exceeds (?:the )?maximum|too large to|file content \(\d+ tokens\)"),
    ("file_not_found", r"File does not exist|No such file or directory|(?-i:\bENOENT\b)|does not exist|cannot find the path"),
    ("os_permission", r"Permission denied|(?-i:\bE(?:ACCES|PERM)\b)|Operation not permitted"),
    ("input_invalid", r"InputValidationError|<tool_use_error>|Invalid (?:tool )?(?:input|parameters?)|Unknown (?:tool|parameter)"),
]
_ERROR_RES = [(name, re.compile(pattern, re.I)) for name, pattern in _ERROR_PATTERNS]

# Classes that are a normal part of agent work and never drive a recommendation on their own.
BENIGN_ERROR_CLASSES = {"no_match", "check_failure"}
# Classes that indicate a missing capability or access rather than a model mistake.
GAP_ERROR_CLASSES = {"command_not_found", "outside_workdir"}
ENVIRONMENT_ERROR_CLASSES = {"auth", "network", "timeout", "rate_limit", "mcp_error", "os_permission"}
MODEL_ERROR_CLASSES = {"edit_mismatch", "not_read_first", "file_not_found", "input_invalid", "file_too_large"}

_SEARCH_PROGRAMS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "git-grep"}
_CHECK_TOOLS = {"pytest", "py.test", "jest", "vitest", "mocha", "ava", "tox", "nox", "tsc", "eslint", "ruff", "mypy",
                "pyright", "flake8", "pylint", "shellcheck", "golangci-lint", "swiftlint", "rspec", "phpunit", "unittest"}
_CHECK_SCRIPTS = {"test", "tests", "lint", "typecheck", "type-check", "check", "verify"}
_CHECK_SUBCOMMANDS = {"go": {"test", "vet"}, "cargo": {"test", "check", "clippy"}, "make": {"test", "check", "lint"},
                      "swift": {"test"}, "dotnet": {"test"}, "mvn": {"test", "verify"}, "gradle": {"test", "check"}}
_MISSING_RES = [
    re.compile(r"command not found: ([\w.+-]+)"),
    re.compile(r"(?:^|\n)\s*(?:[\w./-]*sh:\s*)?(?:line \d+:\s*)?([\w.+-]+): command not found"),
    re.compile(r"(?:^|\n)[\w./-]*sh: \d+: ([\w.+-]+): not found"),
    re.compile(r"'([\w.+-]+)' is not recognized as an internal or external command"),
]
_GAP_TEXT_RE = re.compile(
    r"\bI (?:don't|do not|can't|cannot|am unable to|'m unable to|am not able to) "
    r"(?:have (?:access|permission)|access|connect to|reach|read|open|use|run|install|reach)\b[^.\n]{0,160}|"
    r"\b(?:no|without) (?:tool|access|integration|connector|MCP server) (?:to|for|that)\b[^.\n]{0,160}|"
    r"\bis(?:n't| not) available (?:in|to) (?:this|my|the current) (?:session|environment|sandbox)[^.\n]{0,120}",
    re.I,
)
_CORRECTION_RE = re.compile(
    r"^\s*(?:no\b|nope\b|wrong\b|stop\b|wait\b|don'?t\b|do not\b|not that\b|that'?s (?:not|wrong|incorrect)\b|"
    r"that is (?:not|wrong|incorrect)\b|i (?:said|told you|asked|meant)\b|why (?:did|would|are) you\b|"
    r"you (?:didn'?t|did not|forgot|missed|broke|ignored)\b|undo\b|revert\b|actually\b|instead\b|"
    r"please don'?t\b|never\b)",
    re.I,
)


def result_text(content) -> str:
    """Flatten tool_result content (string or list of blocks) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                elif block.get("type") == "image":
                    parts.append("[image]")
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return json.dumps(content)[:4000]


def classify_result(tool_name: str, tool_input, text: str, is_error) -> tuple:
    """Return (outcome, error_class) for a tool result.

    outcome is ok | error | rejected | denied; error_class is None for ok/rejected/denied.
    """
    text = text or ""
    head = text.lstrip()[:400]
    # Anchor at the start: tool output that merely quotes these phrases (a grep, a log) is not a rejection.
    if REJECT_RE.match(head):
        return "rejected", None
    if is_error and DENIED_RE.search(head):
        return "denied", None
    if not is_error:
        return "ok", None
    command = ""
    if tool_name == "Bash" and isinstance(tool_input, dict):
        command = str(tool_input.get("command", ""))
        # A failing test or lint run is normal iteration, whatever its output mentions (a 403 in an
        # assertion, a timeout in a test name). Only a missing tool or blocked directory still counts.
        if is_check_command(command):
            for name, regex in _ERROR_RES:
                if name in GAP_ERROR_CLASSES and regex.search(text):
                    return "error", name
            return "error", "check_failure"
    for name, regex in _ERROR_RES:
        if regex.search(text):
            return "error", name
    if tool_name == "Bash":
        body = re.sub(r"^\s*(?:Error: )?Exit code \d+\s*", "", text).strip()
        if first_program(command) in _SEARCH_PROGRAMS and re.match(r"^\s*(?:Error: )?Exit code 1\b", text) and not body:
            return "error", "no_match"
        return "error", "nonzero_exit"
    if tool_name.startswith("mcp__"):
        return "error", "mcp_error"
    return "error", "other"


def is_check_command(command: str) -> bool:
    """True when the first real command is a test, lint, or type-check run. Decided from the program and
    subcommand, never from words elsewhere in the command (`npm install -D eslint` is not a check)."""
    for segment in _scan(command or "")["segments"]:
        words = _words(segment)
        if not words or words[0] in ("cd", "pushd", "popd", "export", "set", "true", ":"):
            continue
        prog, args = words[0].rsplit("/", 1)[-1], words[1:]
        if prog in ("npx", "bunx", "pnpx", "uvx") and args:
            prog, args = args[0].rsplit("/", 1)[-1], args[1:]
        elif prog in ("uv", "poetry", "pipenv") and len(args) >= 2 and args[0] == "run":
            prog, args = args[1].rsplit("/", 1)[-1], args[2:]
        if prog in ("python", "python3") and len(args) >= 2 and args[0] == "-m":
            prog, args = args[1], args[2:]
        positional = [a for a in args if not a.startswith("-")]
        sub = positional[0] if positional else ""
        if prog in _CHECK_TOOLS:
            return True
        if prog in ("black", "prettier", "gofmt", "rustfmt") and any(a in ("--check", "-l", "--list-different") for a in args):
            return True
        if prog in ("npm", "pnpm", "yarn", "bun"):
            script = positional[1] if sub == "run" and len(positional) > 1 else sub
            return script in _CHECK_SCRIPTS or script.split(":", 1)[0] in _CHECK_SCRIPTS
        if prog in _CHECK_SUBCOMMANDS:
            return sub in _CHECK_SUBCOMMANDS[prog]
        if prog == "xcodebuild":
            return "test" in args
        return False
    return False


def missing_program(text: str) -> str | None:
    for regex in _MISSING_RES:
        match = regex.search(text or "")
        if match:
            return match.group(1)
    return None


def capability_gap_sentence(text: str) -> str | None:
    match = _GAP_TEXT_RE.search(text or "")
    return match.group(0).strip() if match else None


def looks_like_correction(text: str) -> bool:
    return bool(_CORRECTION_RE.match(text or ""))


# ---------------------------------------------------------------- shell parsing


def _scan(command: str) -> dict:
    """Quote-aware scan of a shell command into top-level segments and risky constructs."""
    segments, buf = [], []
    quote = None
    has_ops = has_subst = has_redirect = False
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            elif quote == '"' and c == "\\" and i + 1 < n:
                buf.append(command[i + 1])
                i += 1
            elif quote == '"' and (c == "`" or command.startswith("$(", i)):
                has_subst = True
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])
            i += 1
        elif c == "`" or command.startswith("$(", i) or command.startswith("<(", i) or command.startswith(">(", i):
            has_subst = True
            buf.append(c)
        elif c == ">":
            # `2>&1`, `>&2` and `>/dev/null` do not write files; anything else might.
            rest = command[i + 1 :].lstrip(">").lstrip()
            if not (rest.startswith("&") or rest.startswith("/dev/null")):
                has_redirect = True
            buf.append(c)
        elif c == "<":
            buf.append(c)
        elif c == "&" and buf and buf[-1] in "<>":
            buf.append(c)  # fd duplication such as 2>&1
        elif command.startswith("&>", i):
            has_redirect = True  # &>file
            buf.append(c)
        elif c in ";|&\n":
            has_ops = True
            segments.append("".join(buf))
            buf = []
            if c in "|&" and i + 1 < n and command[i + 1] == c:
                i += 1
        else:
            buf.append(c)
        i += 1
    segments.append("".join(buf))
    return {
        "segments": [s.strip() for s in segments if s.strip()],
        "compound": has_ops,
        "subst": has_subst,
        "redirect": has_redirect,
    }


def _words(segment: str) -> list:
    try:
        words = shlex.split(segment, posix=True)
    except ValueError:
        words = segment.split()
    while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        words = words[1:]  # leading env assignments
    return words


def first_program(command: str) -> str:
    """The program a command runs, skipping `cd x &&` prefixes and env assignments."""
    for segment in _scan(command or "")["segments"]:
        words = _words(segment)
        if not words or words[0] in ("cd", "pushd", "popd", "export", "set", "true", ":"):
            continue
        return words[0].rsplit("/", 1)[-1]
    return ""


# ---------------------------------------------------------------- risk tables

LOW, MEDIUM, HIGH = "low", "medium", "high"
RISK_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

_READ_ONLY = {
    "cd", "pushd", "popd", ":", "ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "ag", "ack", "pwd",
    "echo", "printf", "which", "whereis", "type", "file", "stat", "du", "df", "ps", "uname", "date",
    "whoami", "id", "hostname", "cut", "tr", "diff", "cmp", "comm", "jq", "realpath",
    "dirname", "basename", "readlink", "md5", "md5sum", "shasum", "sha256sum", "sha1sum", "test", "true",
    "false", "sw_vers", "mdfind", "mdls", "column", "nl", "seq", "less", "more", "lsof", "pgrep",
    "otool", "nm", "strings", "hexdump", "od", "wc", "sleep", "cal", "uptime", "locale",
}
_HIGH = {
    "curl", "wget", "http", "https", "httpie", "nc", "ncat", "netcat", "telnet", "ftp", "ssh", "scp", "sftp",
    "rsync", "rm", "rmdir", "dd", "mkfs", "shred", "truncate", "sudo", "su", "doas", "chmod", "chown", "chgrp",
    "kill", "pkill", "killall", "shutdown", "reboot", "halt", "launchctl", "crontab", "systemctl", "osascript",
    "security", "eval", "exec", "source", ".", "xargs", "npx", "bunx", "uvx", "pipx", "dlx", "claude",
    "diskutil", "csrutil", "spctl", "defaults", "networksetup", "scutil", "ifconfig", "route", "iptables",
    "pfctl", "socat", "nmap", "base64",
}
_INTERPRETERS = {
    "python", "python3", "python2", "node", "deno", "bun", "ruby", "perl", "php", "bash", "sh", "zsh", "fish",
    "dash", "ksh", "tclsh", "lua", "Rscript", "julia", "swift", "pwsh", "powershell", "osascript", "awk",
    "gawk", "env",
}
_SUBCOMMAND_TOOLS = {
    "git", "gh", "npm", "pnpm", "yarn", "bun", "cargo", "go", "brew", "pip", "pip3", "uv", "poetry", "docker",
    "kubectl", "terraform", "make", "swift", "xcrun", "dotnet", "mvn", "gradle", "bundle", "rails", "rake",
    "mix", "deno", "conda", "pod", "flutter", "aws", "gcloud", "az", "heroku", "vercel", "supabase",
}
# Rule-level risk: an allow rule matches every command with the prefix, so each entry is rated by
# the worst thing that prefix permits (`git branch *` includes `git branch -D`).
_SUBCOMMAND_RISK = {
    "git": {
        LOW: {"status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "describe", "shortlog",
              "grep", "cat-file", "merge-base", "rev-list", "name-rev", "whatchanged", "count-objects"},
        MEDIUM: {"add", "commit", "checkout", "switch", "restore", "merge", "rebase", "cherry-pick", "fetch",
                 "pull", "worktree", "mv", "rm", "init", "clone", "apply", "am", "revert", "submodule",
                 "branch", "tag", "stash", "remote", "reflog", "ls-remote", "notes", "bisect"},
        HIGH: {"push", "reset", "clean", "filter-branch", "filter-repo", "gc", "update-ref", "send-email",
               "config", "credential", "daemon", "archive"},
    },
    "_pkg": {
        LOW: {"test", "ls", "list", "view", "info", "outdated", "audit", "why", "explain", "show", "freeze",
              "search", "doctor", "version", "check", "lint", "typecheck", "tree"},
        MEDIUM: {"run", "install", "i", "ci", "add", "remove", "uninstall", "update", "upgrade", "build",
                 "sync", "lock", "fmt", "format", "clippy", "vet", "tidy", "start", "dev"},
        HIGH: {"publish", "exec", "dlx", "x", "link", "unpublish", "deprecate", "owner", "login", "logout",
               "token", "adduser", "config", "set", "cache", "self", "pack"},
    },
    "_infra": {  # these reach systems that hold credentials, so even reads start at medium
        LOW: {"version", "help"},
        MEDIUM: {"get", "describe", "logs", "ps", "images", "list", "plan", "validate", "inspect", "build",
                 "pull", "init", "fmt"},
        HIGH: {"run", "exec", "apply", "delete", "destroy", "push", "rm", "rmi", "prune", "cp", "scale",
               "rollout", "patch", "edit", "create", "deploy", "login", "secrets", "ssh"},
    },
}
_PKG_TOOLS = {"npm", "pnpm", "yarn", "bun", "cargo", "go", "brew", "pip", "pip3", "uv", "poetry", "bundle",
              "mix", "conda", "pod", "dotnet", "mvn", "gradle", "deno", "swift", "flutter"}
_INFRA_TOOLS = {"docker", "kubectl", "terraform", "aws", "gcloud", "az", "heroku", "vercel", "supabase", "xcrun"}
_CHECK_PROGRAMS = {"pytest", "jest", "vitest", "mocha", "tsc", "eslint", "ruff", "mypy", "pyright", "flake8",
                   "pylint", "shellcheck", "golangci-lint", "swiftlint", "rspec", "phpunit"}
_WRITE_LOCAL = {"mkdir", "touch", "cp", "mv", "ln", "tee", "patch", "prettier", "black", "gofmt", "rustfmt",
                "isort", "open", "unzip", "tar", "zip", "gzip", "gunzip", "uniq"}
# Programs that are read-only unless given certain flags. An allow rule ending in a wildcard permits
# those flags, so such a rule is rated by the flag's risk, not by the program's usual use.
_FLAG_RISK = {
    "find": (("-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"), HIGH,
             "find can run commands or delete files with -exec or -delete"),
    "fd": (("-x", "--exec", "-X", "--exec-batch"), HIGH, "fd can run commands with --exec"),
    "rg": (("--pre",), HIGH, "rg --pre runs a command for every file"),
    "sed": (("-i", "--in-place"), MEDIUM, "sed -i edits files in place"),
    "yq": (("-i", "--inplace"), MEDIUM, "yq -i edits files in place"),
    "sort": (("-o", "--output"), MEDIUM, "sort -o writes files"),
    "tree": (("-o",), MEDIUM, "tree -o writes files"),
    "xxd": (("-r", "-revert"), MEDIUM, "xxd -r writes files"),
}
_GH_READ_VERBS = {"view", "list", "status", "diff", "checks", "watch"}
_GH_HIGH_NOUNS = {"api", "secret", "variable", "ssh-key", "gpg-key", "codespace", "extension", "alias", "auth",
                  "config", "attestation", "cache"}

_SECRET_PATH_RE = re.compile(
    r"(?:^|/)(?:\.ssh|\.aws|\.gnupg|\.gcloud|\.kube|\.docker|\.netrc|\.pgpass|\.npmrc|\.pypirc|"
    r"Keychains|keychain|\.env(?:\.[\w.-]+)?|[\w.-]*\.pem|[\w.-]*\.key|id_(?:rsa|ed25519|ecdsa|dsa)[\w.]*|"
    r"credentials(?:\.json)?|secrets?(?:\.\w+)?|\.claude/settings[\w.]*\.json|\.git/config)(?:$|/)",
    re.I,
)


def is_secret_path(path: str) -> bool:
    return bool(_SECRET_PATH_RE.search(path or ""))


def _max_risk(*risks):
    return max(risks, key=lambda r: RISK_ORDER[r[0]])


def _drop_option_values(args: list, options: tuple) -> list:
    """Remove options that take a separate value (`-C path`) so the subcommand is found."""
    out, skip = [], False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in options:
            skip = True
            continue
        out.append(arg)
    return out


def _broad_path(content: str) -> bool:
    """True for path patterns that cover the filesystem root or an entire home directory."""
    path = content.strip()
    for suffix in ("/**", "/*", "**"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    if path in ("", "/", "//", "~", "~/", "."):
        return path != "."
    if path.startswith("~/"):
        return False
    depth = len([p for p in path.strip("/").split("/") if p])
    return path.startswith("/") and depth <= 2


def _has_flag(arg: str, flags: tuple) -> bool:
    for flag in flags:
        if arg == flag or arg.startswith(flag + "="):
            return True
        if len(flag) == 2 and flag[0] == "-" and arg.startswith(flag) and not arg.startswith("--"):
            return True  # attached value or suffix: -i.bak, -ofile
    return False


def segment_risk(words: list, wildcard: bool = False) -> tuple:
    """Risk of one simple command. With wildcard=True, rate the worst command the prefix permits."""
    if not words:
        return LOW, "empty"
    prog = words[0].rsplit("/", 1)[-1]
    args = words[1:]
    if prog in _HIGH:
        return HIGH, "%s can reach the network, run arbitrary code, or destroy data" % prog
    if prog in _INTERPRETERS:
        if prog in ("python", "python3") and len(args) >= 2 and args[0] == "-m":
            module = args[1]
            if module in ("pytest", "unittest", "mypy", "ruff", "black", "pip"):
                return (MEDIUM if module == "pip" else LOW), "python -m %s" % module
            return MEDIUM, "python -m %s runs project code" % module
        if any(a in ("-c", "-e", "--eval", "-E") for a in args):
            return HIGH, "%s with inline code runs arbitrary code" % prog
        return HIGH, "%s runs arbitrary code" % prog
    if prog in _FLAG_RISK:
        flags, level, why = _FLAG_RISK[prog]
        if wildcard or any(_has_flag(a, flags) for a in args):
            return level, why
        return LOW, "%s without %s" % (prog, flags[0])
    if prog in _READ_ONLY:
        return LOW, "%s is read-only" % prog
    if prog in _CHECK_PROGRAMS:
        return LOW, "%s is a project-local check" % prog
    if prog == "git":
        if "-c" in args or any(a.startswith("--config-env") for a in args):
            return HIGH, "git -c can set config that runs commands"
        args = _drop_option_values(args, ("-C", "--git-dir", "--work-tree", "--namespace"))
    sub = next((a for a in args if not a.startswith("-")), "")
    if prog in _SUBCOMMAND_TOOLS and prog not in ("gh", "make") and not sub:
        if wildcard:
            # `git *`, `git --no-pager *`, `/usr/bin/git *`: no subcommand means every subcommand.
            return HIGH, "%s with any subcommand" % prog
        if args and all(a in ("--version", "-v", "-V", "--help", "-h") for a in args):
            return LOW, "%s version or help" % prog
    if prog == "git":
        table = _SUBCOMMAND_RISK["git"]
    elif prog == "gh":
        positional = [a for a in args if not a.startswith("-")]
        noun = positional[0] if positional else ""
        verb = positional[1] if len(positional) > 1 else ""
        if noun in _GH_HIGH_NOUNS:
            return HIGH, "gh %s can expose credentials or call arbitrary endpoints" % noun
        if noun in ("status", "help", "search", "version"):
            return LOW, "gh %s is read-only" % noun
        if verb in _GH_READ_VERBS:
            return LOW, "gh %s %s is read-only" % (noun, verb)
        if verb == "checkout":
            return MEDIUM, "gh %s checkout changes the local branch" % noun
        if not verb:
            return HIGH, "gh %s with any action, including outward-facing writes" % (noun or "(any)")
        return HIGH, "gh %s %s changes state on GitHub" % (noun, verb)
    elif prog in _PKG_TOOLS:
        table = _SUBCOMMAND_RISK["_pkg"]
    elif prog in _INFRA_TOOLS:
        table = _SUBCOMMAND_RISK["_infra"]
    elif prog == "make":
        return MEDIUM, "make runs arbitrary Makefile recipes"
    elif prog in _WRITE_LOCAL:
        return MEDIUM, "%s writes local files" % prog
    else:
        return MEDIUM, "%s is not in the known-command tables" % prog
    for level in (HIGH, MEDIUM, LOW):
        if sub in table[level]:
            return level, "%s %s" % (prog, sub)
    return MEDIUM, "%s %s is not in the known-subcommand table" % (prog, sub or "(no subcommand)")


# ---------------------------------------------------------------- permission rules

_RULE_RE = re.compile(r"^([A-Za-z0-9_]+(?:__[A-Za-z0-9_.-]+)*)(?:\((.*)\))?$", re.S)
_READ_VERB_RE = re.compile(
    r"(?:^|[_-])(get|list|search|read|fetch|query|view|find|lookup|describe|status|retrieve)(?:[_-]|$)", re.I
)
_WRITE_VERB_RE = re.compile(
    r"(?:^|[_-])(create|update|delete|remove|send|post|write|merge|push|share|trash|apply|execute|exec|run|deploy|"
    r"publish|upload|move|copy|edit|set|add|archive|pause|restore|reset|rebase|fire|trigger|spawn|install)(?:[_-]|$)",
    re.I,
)


def rule_string(tool_name: str, content: str | None) -> str:
    return "%s(%s)" % (tool_name, content) if content else tool_name


def parse_rule(rule: str) -> tuple:
    match = _RULE_RE.match((rule or "").strip())
    if not match:
        return None, None
    return match.group(1), match.group(2)


def _bash_rule_command(content: str) -> str:
    """Strip the trailing wildcard from a Bash rule's content (`git log *` or legacy `git log:*`)."""
    content = content.strip()
    for suffix in (":*", " *", "*"):
        if content.endswith(suffix):
            return content[: -len(suffix)].strip()
    return content


def rule_risk(rule: str) -> tuple:
    tool, content = parse_rule(rule)
    if tool is None:
        return HIGH, "unparseable rule"
    if tool == "Bash":
        if not content or content.strip() in ("*", ":*"):
            return HIGH, "allows every shell command"
        command = _bash_rule_command(content)
        if not command:
            return HIGH, "allows every shell command"
        scan = _scan(command)
        if scan["compound"] or scan["subst"] or scan["redirect"]:
            return HIGH, "rule contains shell operators"
        wildcard = content.strip().endswith("*")
        words = _words(command)
        level, reason = segment_risk(words, wildcard=wildcard)
        if wildcard and words and words[0].rsplit("/", 1)[-1] == "make" and len(words) < 2:
            return HIGH, "make with any target"
        return level, reason
    if tool in ("Read", "Glob", "Grep", "LS", "NotebookRead"):
        if content and is_secret_path(content):
            return HIGH, "path can contain secrets"
        if content and _broad_path(content):
            return MEDIUM, "read access to a whole home directory or filesystem"
        return LOW, "read-only file access"
    if tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        if not content:
            return MEDIUM, "edits anywhere in the working directories"
        if is_secret_path(content):
            return HIGH, "path can contain secrets"
        if _broad_path(content):
            return HIGH, "writes across a whole home directory or filesystem"
        return MEDIUM, "scoped file writes"
    if tool == "WebFetch":
        if not content:
            return HIGH, "fetches any URL, which can leak data through query strings"
        if content.startswith("domain:") and "*" not in content:
            return LOW, "fetches from one domain"
        return MEDIUM, "fetches from a wildcard domain"
    if tool == "WebSearch":
        return LOW, "web search"
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        if len(parts) < 3 or parts[2] in ("", "*"):
            return HIGH, "allows every tool of an MCP server"
        name = parts[2]
        if _WRITE_VERB_RE.search(name):
            return HIGH, "MCP tool %s changes external state" % name
        if _READ_VERB_RE.search(name):
            return LOW, "read-only MCP tool"
        return MEDIUM, "MCP tool of unknown effect"
    if tool in ("Task", "Agent", "Skill", "TodoWrite", "ToolSearch", "TaskCreate", "TaskUpdate", "TaskList"):
        return LOW, "orchestration tool"
    return MEDIUM, "tool %s is not in the risk table" % tool


def synth_rule(tool_name: str, tool_input) -> str | None:
    """Narrowest reasonable allow rule for a tool call, or None when no safe rule exists."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool_name == "Bash":
        command = str(tool_input.get("command", ""))
        scan = _scan(command)
        if scan["compound"] or scan["subst"] or scan["redirect"] or len(scan["segments"]) != 1:
            return None
        words = _words(scan["segments"][0])
        if not words:
            return None
        prog = words[0]
        if prog.rsplit("/", 1)[-1] in ("python", "python3") and len(words) >= 3 and words[1] == "-m":
            return "Bash(%s -m %s *)" % (prog, words[2])
        if prog == "gh":
            positional = [w for w in words[1:] if not w.startswith("-")]
            return "Bash(gh %s *)" % " ".join(positional[:2]) if len(positional) >= 2 else None
        if prog.rsplit("/", 1)[-1] in _SUBCOMMAND_TOOLS:
            sub = words[1] if len(words) > 1 and not words[1].startswith("-") else None
            return "Bash(%s %s *)" % (prog, sub) if sub else None
        return "Bash(%s *)" % prog
    if tool_name == "WebFetch":
        host = urlparse(str(tool_input.get("url", ""))).hostname
        return "WebFetch(domain:%s)" % host if host else None
    if tool_name.startswith("mcp__"):
        return tool_name
    if tool_name in ("WebSearch", "Skill", "Task", "Agent"):
        return tool_name
    return None


def rules_from_suggestions(suggestions) -> list:
    """Extract allow rules from a PermissionRequest `permission_suggestions` payload.

    The payload mirrors the SDK's PermissionUpdate objects
    ({"type": "addRules", "behavior": "allow", "rules": [{"toolName", "ruleContent"}], "destination"}).
    Parsed defensively because the shape is not documented for hooks.
    """
    found = []

    def walk(node):
        if isinstance(node, dict):
            behavior = node.get("behavior", "allow")
            rules = node.get("rules")
            if isinstance(rules, list) and behavior == "allow":
                for rule in rules:
                    if isinstance(rule, dict) and rule.get("toolName"):
                        found.append(rule_string(str(rule["toolName"]), rule.get("ruleContent")))
            for value in node.values():
                if isinstance(value, (dict, list)):
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(suggestions)
    seen, out = set(), []
    for rule in found:
        if rule not in seen:
            seen.add(rule)
            out.append(rule)
    return out


# ---------------------------------------------------------------- join keys


def input_key(tool_name: str, tool_input) -> str:
    """Stable key for matching a hook event's tool_input to a transcript tool_use input."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool_name == "Bash":
        basis = str(tool_input.get("command", "")).strip()
    elif "file_path" in tool_input:
        basis = str(tool_input.get("file_path"))
    elif "notebook_path" in tool_input:
        basis = str(tool_input.get("notebook_path"))
    elif "url" in tool_input:
        basis = str(tool_input.get("url"))
    else:
        basis = json.dumps(tool_input, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(("%s\x00%s" % (tool_name, basis)).encode("utf-8")).hexdigest()[:16]


def summarize_input(tool_name: str, tool_input, limit: int = 200) -> str:
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    for field in ("command", "file_path", "notebook_path", "url", "pattern", "query", "prompt", "skill"):
        if field in tool_input:
            text = str(tool_input[field])
            break
    else:
        text = json.dumps(tool_input, ensure_ascii=False, sort_keys=True)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."
