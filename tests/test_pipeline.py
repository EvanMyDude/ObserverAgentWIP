import datetime
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fixtures
import scenario
from observer import outcomes, pipeline
from observer.config import Config
from observer.ingest import TranscriptIngestor
from observer.store import connect, loads


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, fixtures.isolated_env(self.tmp))
        self.env.start()
        self.cfg = Config()
        self.cfg.judge_enabled = False
        self.data = scenario.build(self.tmp / "proj", Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects", self.cfg.spool_dir)

    def tearDown(self):
        self.env.stop()

    def run_pipeline(self, days_later=0):
        return pipeline.run(self.cfg, use_judge=False, now=fixtures.NOW + datetime.timedelta(days=days_later))

    def recs(self):
        conn = connect(self.cfg.db_path)
        rows = {(r["type"], r["target"]): r for r in conn.execute("SELECT * FROM recommendations")}
        conn.close()
        return rows

    def find(self, rtype, target_contains):
        matches = [r for (t, target), r in self.recs().items() if t == rtype and target_contains in target]
        self.assertEqual(len(matches), 1, "expected one %s matching %r, got %r" % (rtype, target_contains, list(self.recs())))
        return matches[0]

    def test_recommendations_from_scenario(self):
        self.run_pipeline()
        allow = self.find("allow_permission", "Bash(git log:*)")
        self.assertEqual(allow["status"], "open")
        self.assertEqual(allow["risk"], "low")
        self.assertEqual(loads(allow["patch_json"])["file"], "~/.claude/settings.json")  # two projects

        curl = self.find("allow_permission", "Bash(curl *)")
        self.assertEqual(curl["status"], "blocked")
        self.assertIn("high risk", curl["status_reason"])

        self.assertEqual(self.find("deny_permission", "Bash(git push *)")["status"], "open")
        self.assertEqual(self.find("install_tool", "frobctl")["status"], "open")
        alias = self.find("add_context", "alias:python")
        self.assertIn("python3", loads(alias["patch_json"])["text"])
        instruction = self.find("add_context", "::instr:")
        self.assertIn(scenario.INSTRUCTION, loads(instruction["patch_json"])["text"])
        self.assertEqual(loads(instruction["patch_json"])["file"], "~/.claude/CLAUDE.md")
        self.assertEqual(self.find("add_dir", "/Users/test/Documents/Deals")["risk"], "medium")
        self.assertEqual(self.find("tune_agent", "agent:Explore")["status"], "open")
        self.assertEqual(self.find("add_capability", "gap:notion workspace")["status"], "open")

    def test_installed_but_not_on_agent_path(self):
        session = fixtures.Session(Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects", self.data["alpha"], days_ago=1)
        for _ in range(2):
            session.tool("Bash", {"command": "sh -c true"}, "Exit code 127\nbash: sh: command not found", is_error=True)
        session.write()
        self.run_pipeline()
        rec = self.find("fix_environment", "path:sh")
        self.assertIn("PATH", rec["title"] + rec["rationale"])

    def test_detectors(self):
        self.run_pipeline()
        conn = connect(self.cfg.db_path)
        kinds = {r["kind"]: r["n"] for r in conn.execute("SELECT kind, COUNT(*) n FROM frictions GROUP BY kind")}
        self.assertGreaterEqual(kinds.get("retry_loop", 0), 1)
        self.assertEqual(kinds.get("interrupt"), 1)
        self.assertEqual(kinds.get("correction"), 1)
        self.assertEqual(kinds.get("permission_prompt"), 6)
        subkinds = {r["subkind"] for r in conn.execute("SELECT subkind FROM frictions WHERE kind='permission_prompt'")}
        self.assertEqual(subkinds, {"approved"})  # every prompt was joined to its executed tool call
        # The subagent's delegation prompt is not the user typing.
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM messages WHERE kind='human' AND agent_id IS NOT NULL").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT path FROM skill_paths WHERE skill='title-skill'").fetchone()[0], "/skills/title-skill")
        conn.close()

    def test_rerun_is_idempotent(self):
        self.run_pipeline()
        conn = connect(self.cfg.db_path)
        before = conn.execute("SELECT COUNT(*) FROM frictions").fetchone()[0]
        conn.close()
        ids = set(r["id"] for r in self.recs().values())
        self.run_pipeline()
        conn = connect(self.cfg.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM frictions").fetchone()[0], before)
        conn.close()
        self.assertEqual(set(r["id"] for r in self.recs().values()), ids)

    def test_applied_then_verified(self):
        self.run_pipeline()
        settings = Path(os.environ["CLAUDE_CONFIG_DIR"]) / "settings.json"
        settings.write_text(json.dumps({"permissions": {"allow": ["Bash(git log:*)"]}}))
        self.run_pipeline()
        allow = self.find("allow_permission", "Bash(git log:*)")
        self.assertEqual(allow["status"], "applied")
        self.assertGreater(allow["baseline_per_day"], 0)
        self.run_pipeline(days_later=8)
        allow = self.find("allow_permission", "Bash(git log:*)")
        self.assertEqual(allow["status"], "verified")
        report = (self.cfg.reports_dir / "latest.md").read_text()
        self.assertIn("## Applied changes", report)

    def test_dismissed_stays_dismissed_until_evidence_doubles(self):
        self.run_pipeline()
        rec = self.find("install_tool", "frobctl")
        conn = connect(self.cfg.db_path)
        outcomes.dismiss(conn, rec["id"], "using python instead")
        conn.close()
        self.run_pipeline()
        self.assertEqual(self.find("install_tool", "frobctl")["status"], "dismissed")

    def test_report(self):
        result = self.run_pipeline()
        report = Path(result["report"]).read_text()
        for heading in ("## Do today", "## Blocked by policy", "## Agent scorecard", "## Pipeline health"):
            self.assertIn(heading, report)
        self.assertIn("Bash(curl *)", report)
        self.assertIn("underperforming", report)
        self.assertNotIn("Hooks are not installed", report)  # hook events exist, so analytics are on
        self.assertEqual((self.cfg.reports_dir / "latest.md").read_text(), report)


class IncrementalIngestTest(unittest.TestCase):
    def test_partial_lines_wait_for_completion(self):
        tmp = Path(tempfile.mkdtemp())
        with mock.patch.dict(os.environ, fixtures.isolated_env(tmp)):
            cfg = Config()
            session = fixtures.Session(Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects", str(tmp / "p"))
            session.prompt("first prompt here please")
            session.tool("Bash", {"command": "ls"}, "a b")
            path = session.write()
            full = path.read_text()
            lines = full.splitlines(keepends=True)
            path.write_text("".join(lines[:-1]) + lines[-1].rstrip("\n"))  # last record half-written
            conn = connect(cfg.db_path)
            TranscriptIngestor(conn, cfg).run()
            self.assertEqual(conn.execute("SELECT outcome FROM tool_calls").fetchone()[0], "pending")
            path.write_text(full)
            TranscriptIngestor(conn, cfg).run()
            self.assertEqual(conn.execute("SELECT outcome FROM tool_calls").fetchone()[0], "ok")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM messages WHERE kind='human'").fetchone()[0], 1)
            conn.close()


if __name__ == "__main__":
    unittest.main()
