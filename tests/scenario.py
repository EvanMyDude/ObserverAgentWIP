"""A three-day, two-project history that exercises every detector and rule."""
from __future__ import annotations

from pathlib import Path

from fixtures import Session, hook_event

INSTRUCTION = "Always use pnpm instead of npm in this repo."
JQ_MISSING = "Exit code 127\nbash: frobctl: command not found"
PY_MISSING = "Exit code 127\nzsh: command not found: python"
OUTSIDE = ("Read of '/Users/test/Documents/Deals/%s' was refused: the permissions.blockReadsOutsideWorkingDirectories "
           "setting blocks reads outside the working directories. Ask the user to add the directory with /add-dir.")
REJECTED = ("The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, "
            "the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed.")
GIT_LOG_SUGGESTION = [{"type": "addRules", "behavior": "allow", "destination": "localSettings",
                       "rules": [{"toolName": "Bash", "ruleContent": "git log:*"}]}]


def _prompted(session: Session, spool: Path, name: str, tool_input: dict, result: str, suggestions=None) -> None:
    """A tool call that triggered a permission prompt the user approved."""
    session.tool(name, tool_input, result)
    use_ts = session.records[-2]["timestamp"]
    fields = {"tool_name": name, "tool_input": tool_input}
    if suggestions is not None:
        fields["permission_suggestions"] = suggestions
    hook_event(spool, session, "PermissionRequest", use_ts, **fields)


def build(projects_root: Path, transcripts: Path, spool: Path) -> dict:
    alpha = str(projects_root / "alpha")
    beta = str(projects_root / "beta")
    sessions = {}

    s1 = Session(transcripts, alpha, days_ago=3)
    s1.prompt(INSTRUCTION + " Fix the build.")
    s1.tool("Bash", {"command": "frobctl . package.json"}, JQ_MISSING, is_error=True)
    _prompted(s1, spool, "Bash", {"command": "git log --oneline"}, "abc123 init", GIT_LOG_SUGGESTION)
    _prompted(s1, spool, "Bash", {"command": "curl -s https://api.example.com/x"}, "{}")
    s1.tool("Bash", {"command": "git push origin main"}, REJECTED, is_error=True)
    for _ in range(3):
        s1.tool("Edit", {"file_path": alpha + "/src/a.ts", "old_string": "x", "new_string": "y"},
                "<tool_use_error>String to replace not found in file.\nString: x</tool_use_error>", is_error=True)
    s1.interrupt()
    s1.prompt("no, stop editing that file and read it first")
    s1.skill_load("title-skill", "/skills/title-skill")
    for i in range(25):
        s1.tool("Read", {"file_path": alpha + "/docs/%d.md" % i}, "content")
    s1.say("Done.")
    sessions["s1"] = s1

    s2 = Session(transcripts, alpha, days_ago=2)
    s2.prompt(INSTRUCTION)
    s2.tool("Bash", {"command": "frobctl .version package.json"}, JQ_MISSING, is_error=True)
    _prompted(s2, spool, "Bash", {"command": "git log -5"}, "abc123 init", GIT_LOG_SUGGESTION)
    _prompted(s2, spool, "Bash", {"command": "curl -s https://api.example.com/y"}, "{}")
    s2.tool("Bash", {"command": "git push origin main"}, REJECTED, is_error=True)
    s2.tool("Read", {"file_path": "/Users/test/Documents/Deals/a.pdf"}, OUTSIDE % "a.pdf", is_error=True)
    s2.tool("Read", {"file_path": "/Users/test/Documents/Deals/b.pdf"}, OUTSIDE % "b.pdf", is_error=True)
    s2.say("I don't have access to your Notion workspace from this session.")
    sessions["s2"] = s2

    s3 = Session(transcripts, beta, days_ago=1)
    s3.prompt("Please " + INSTRUCTION.lower())
    _prompted(s3, spool, "Bash", {"command": "git log --stat"}, "abc123 init", GIT_LOG_SUGGESTION)
    _prompted(s3, spool, "Bash", {"command": "curl -s https://api.example.com/z"}, "{}")
    s3.tool("Bash", {"command": "git push origin main"}, REJECTED, is_error=True)
    s3.tool("Read", {"file_path": "/Users/test/Documents/Deals/c.pdf"}, OUTSIDE % "c.pdf", is_error=True)
    s3.tool("Bash", {"command": "python script.py"}, PY_MISSING, is_error=True)
    s3.tool("Bash", {"command": "python -V"}, PY_MISSING, is_error=True)
    s3.say("I can't access the Notion workspace, so I used the local notes instead.")
    for i in range(25):
        s3.tool("Grep", {"pattern": "todo%d" % i, "path": beta}, "match")
    sub = s3.subagent("Explore")
    sub.prompt(INSTRUCTION + " Find the config files.")  # delegation text, not the user
    for i in range(25):
        sub.tool("Read", {"file_path": beta + "/missing%d.ts" % (i % 3)}, "File does not exist.", is_error=True)
    sessions["s3"] = s3
    sessions["s3_sub"] = sub

    for s in sessions.values():
        s.write()
    return {"alpha": alpha, "beta": beta, "sessions": sessions}
