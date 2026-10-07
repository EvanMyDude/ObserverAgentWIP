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
        # A week passes with no work in the affected projects: no errors, but nothing was tested either.
        self.run_pipeline(days_later=8)
        allow = self.find("allow_permission", "Bash(git log:*)")
        self.assertEqual(allow["status"], "applied")
        self.assertIn("waiting: no sessions in", allow["status_reason"])
        # Work resumes in one of those projects and the friction does not come back.
        later = fixtures.Session(Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects", self.data["alpha"], days_ago=-7)
        later.prompt("continue the build work from yesterday")
        later.tool("Bash", {"command": "ls"}, "a b")
        later.write()
        self.run_pipeline(days_later=8)
        allow = self.find("allow_permission", "Bash(git log:*)")
        self.assertEqual(allow["status"], "verified")
        report = (self.cfg.reports_dir / "latest.md").read_text()
        self.assertIn("## Applied changes", report)

    def test_recommendations_expire_when_evidence_ages_out(self):
        self.run_pipeline()
        rec = self.find("install_tool", "frobctl")
        self.assertEqual(rec["status"], "open")
        self.run_pipeline(days_later=30)  # every fixture event is now outside the 14-day window
        rec = self.find("install_tool", "frobctl")
        self.assertEqual(rec["status"], "expired")
        conn = connect(self.cfg.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM recommendations WHERE status='open'").fetchone()[0], 0)
        conn.close()

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
        # A second run with no new activity reads nothing new but still reports the database totals.
        report = Path(self.run_pipeline()["report"]).read_text()
        self.assertIn("0 changed since the last run", report)
        self.assertIn("Sessions started in the last 7 days:", report)
        self.assertRegex(report, r"Database: [1-9]\d* sessions, [1-9]\d* tool calls")


COWORK_ROOT = "Library/Application Support/Claude/local-agent-mode-sessions/acct/org/local_%s/.claude/projects"


class CoworkTest(unittest.TestCase):
    """Cowork sessions are read from their own transcript trees, scored separately, and never told to edit ~/.claude."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, fixtures.isolated_env(self.tmp))
        self.env.start()
        self.cfg = Config()
        self.cfg.judge_enabled = False
        scenario.build(self.tmp / "proj", Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects", self.cfg.spool_dir)
        for name in ("a1", "b2"):
            root = Path(os.environ["HOME"]) / (COWORK_ROOT % name)
            session = fixtures.Session(root, "/sessions/brave-%s" % name, days_ago=1)
            session.prompt("summarize the lease files please")
            # `sh` exists on this machine; Cowork evidence must not turn into a "fix your Mac's PATH" item.
            session.tool("Bash", {"command": "sh build.sh"}, "Exit code 127\nbash: sh: command not found", is_error=True)
            session.records.append({"type": "ai-title", "title": "Lease summary", "sessionId": session.session_id})
            session.write()

    def tearDown(self):
        self.env.stop()

    def test_cowork_sessions_are_ingested_scored_and_redirected(self):
        result = pipeline.run(self.cfg, use_judge=False, now=fixtures.NOW)
        conn = connect(self.cfg.db_path)
        surfaces = {r["surface"] for r in conn.execute("SELECT surface FROM sessions WHERE cwd LIKE '/sessions/%'")}
        self.assertEqual(surfaces, {"cowork"})
        rec = conn.execute("SELECT * FROM recommendations WHERE target='cowork:sh'").fetchone()
        self.assertIsNotNone(rec)
        self.assertEqual(rec["type"], "install_tool")
        self.assertEqual(loads(rec["patch_json"])["kind"], "manual")
        self.assertTrue(rec["title"].endswith("(Cowork)"))
        self.assertIsNone(conn.execute("SELECT 1 FROM recommendations WHERE target='path:sh'").fetchone())
        conn.close()
        report = Path(result["report"]).read_text()
        self.assertIn("| cowork/main | 2 | 2 | n/a (few calls) |", report)
        self.assertNotIn("does not recognize", report)  # ai-title and friends are known metadata now
        self.assertIn("2 Cowork", report)
        scorecard = report.split("## Agent scorecard")[1].split("## ")[0]
        self.assertGreater(scorecard.index("cowork/main"), scorecard.index("agent:Explore"))  # small samples last

    def test_doctor_counts_cowork(self):
        import contextlib
        import io
        from observer import install
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(install.doctor(self.cfg), 0)
        self.assertIn("Cowork: 2 session files", out.getvalue())
        self.assertNotIn("local-agent-mode-sessions", out.getvalue())


class MigrationTest(unittest.TestCase):
    def test_version_1_database_gains_surface_column(self):
        import sqlite3
        from observer import store
        path = Path(tempfile.mkdtemp()) / "observer.db"
        old = sqlite3.connect(str(path))
        old.executescript(store.SCHEMA.replace("    surface TEXT,                    -- cli | cowork\n", ""))
        old.execute("PRAGMA user_version=1")
        old.execute("INSERT INTO sessions(session_id, cwd) VALUES('s1', '/x')")
        old.commit()
        old.close()
        conn = store.connect(path)
        self.assertIn("surface", [r[1] for r in conn.execute("PRAGMA table_info(sessions)")])
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], store.SCHEMA_VERSION)
        self.assertEqual(conn.execute("SELECT cwd FROM sessions").fetchone()[0], "/x")
        self.assertIsNotNone(conn.execute("SELECT name FROM sqlite_master WHERE name='meta'").fetchone())
        conn.close()
        self.assertEqual(store.connect(path).execute("PRAGMA user_version").fetchone()[0], store.SCHEMA_VERSION)

    def test_stored_errors_are_relabelled_once_when_the_classifier_changes(self):
        from observer import ingest, store
        conn = store.connect(Path(tempfile.mkdtemp()) / "observer.db")
        conn.execute("INSERT INTO tool_calls(tool_use_id, session_id, ts, tool_name, input_json, outcome, error_class, "
                     "result_excerpt) VALUES('t1', 's1', '2026-10-01T00:00:00.000Z', 'mcp__workspace__bash', "
                     "'{\"command\": \"python3 x.py\"}', 'error', 'mcp_error', 'Exit code 1\nTraceback')")
        conn.commit()
        self.assertEqual(ingest.reclassify(conn), 1)
        self.assertEqual(conn.execute("SELECT error_class FROM tool_calls").fetchone()[0], "nonzero_exit")
        self.assertEqual(ingest.reclassify(conn), 0)  # recorded version matches; no second pass
        conn.close()


class OutsideWorkdirFingerprintTest(unittest.TestCase):
    def test_bash_paths_come_from_the_error_or_command(self):
        # Review finding: Bash calls have no file_path, so every one was fingerprinted "dir:" and dropped.
        from observer.detect import _error_fingerprint
        row = {"error_class": "outside_workdir", "tool_name": "Bash",
               "result_excerpt": "cd to '/Users/me/other-repo/src' was blocked: outside the allowed working "
                                 "directories. Ask the user to add the directory with /add-dir."}
        self.assertEqual(_error_fingerprint(row, {"command": "cd /Users/me/other-repo/src && ls"}),
                         "dir:/Users/me/other-repo/src")
        row["result_excerpt"] = "blocked: outside the working directories"
        self.assertEqual(_error_fingerprint(row, {"command": "ls /Users/me/elsewhere/data/file.csv"}),
                         "dir:/Users/me/elsewhere/data")


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
