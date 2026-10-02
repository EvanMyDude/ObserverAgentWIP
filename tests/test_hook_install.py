import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fixtures
from observer import install

HOOK = Path(install.HOOK_SCRIPT)


class HookScriptTest(unittest.TestCase):
    def run_hook(self, payload, extra_env=None):
        tmp = Path(tempfile.mkdtemp())
        env = dict(os.environ, OBSERVER_HOME=str(tmp), **(extra_env or {}))
        proc = subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True, text=True, env=env, timeout=30)
        return tmp, proc

    def test_appends_one_line_and_prints_nothing(self):
        payload = json.dumps({"hook_event_name": "PermissionRequest", "session_id": "s1", "tool_name": "Bash",
                              "tool_input": {"command": "git log " + "x" * 5000}, "unrelated": "dropped",
                              "permission_suggestions": [{"type": "addRules"}]})
        tmp, proc = self.run_hook(payload)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")  # stdout would be parsed as a hook decision
        lines = [l for f in (tmp / "spool").glob("*.jsonl") for l in f.read_text().splitlines()]
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["hook_event_name"], "PermissionRequest")
        self.assertNotIn("unrelated", record)
        self.assertLess(len(record["tool_input"]["command"]), 2100)
        self.assertEqual(oct((tmp / "spool").stat().st_mode & 0o777), "0o700")

    def test_ignores_observer_internal_calls(self):
        tmp, proc = self.run_hook(json.dumps({"hook_event_name": "SessionEnd"}), {"OBSERVER_INTERNAL": "1"})
        self.assertEqual(proc.returncode, 0)
        self.assertFalse((tmp / "spool").exists())

    def test_bad_input_never_fails_the_session(self):
        tmp, proc = self.run_hook("{not json")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertTrue((tmp / "logs" / "hook-errors.log").exists())


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, fixtures.isolated_env(self.tmp))
        self.env.start()
        self.settings = install.settings_path()
        existing = {"model": "opus", "hooks": {"Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "~/stop.sh"}]}],
                                               "Notification": [{"matcher": "", "hooks": [{"type": "command", "command": "say hi"}]}]}}
        self.settings.write_text(json.dumps(existing))

    def tearDown(self):
        self.env.stop()

    def test_dry_run_changes_nothing(self):
        before = self.settings.read_text()
        install.install_hooks(apply=False)
        self.assertEqual(self.settings.read_text(), before)

    def test_install_is_idempotent_and_preserves_existing_hooks(self):
        install.install_hooks(apply=True)
        install.install_hooks(apply=True)
        data = json.loads(self.settings.read_text())
        self.assertEqual(data["model"], "opus")
        self.assertEqual(data["hooks"]["Stop"][0]["hooks"][0]["command"], "~/stop.sh")
        for event in install.HOOK_EVENTS:
            ours = [h for g in data["hooks"][event] for h in g["hooks"] if install.HOOK_MARKER in h["command"]]
            self.assertEqual(len(ours), 1, event)
        self.assertEqual(len(data["hooks"]["Notification"]), 2)
        self.assertTrue(list(self.settings.parent.glob("settings.json.observer-backup-*")))
        self.assertTrue(install.hooks_installed())

    def test_uninstall_removes_only_ours(self):
        install.install_hooks(apply=True)
        install.uninstall_hooks(apply=True)
        data = json.loads(self.settings.read_text())
        self.assertFalse(install.hooks_installed())
        self.assertEqual(set(data["hooks"]), {"Stop", "Notification"})
        self.assertEqual(data["hooks"]["Notification"][0]["hooks"][0]["command"], "say hi")

    def test_refuses_unparseable_settings(self):
        self.settings.write_text("{broken")
        self.assertEqual(install.install_hooks(apply=True), 1)
        self.assertEqual(self.settings.read_text(), "{broken")

    def test_doctor_passes_before_install(self):
        # Missing hooks and schedule are expected on a first run and must not fail `make doctor`.
        session = fixtures.Session(Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects", str(self.tmp / "p"))
        session.prompt("a prompt with enough words")
        session.write()
        with mock.patch("sys.stdout"):
            self.assertEqual(install.doctor(install.Config()), 0)

    def test_doctor_fails_without_transcripts(self):
        with mock.patch("sys.stdout"):
            self.assertEqual(install.doctor(install.Config()), 1)

    def test_launchd_plist_uses_absolute_paths(self):
        plist = install._launchd_plist(install.Config(), 6, 15)
        self.assertEqual(plist["StartCalendarInterval"], {"Hour": 6, "Minute": 15})
        self.assertTrue(os.path.isabs(plist["ProgramArguments"][0]))
        self.assertIn("/opt/homebrew/bin", plist["EnvironmentVariables"]["PATH"])
        self.assertEqual(plist["EnvironmentVariables"]["PYTHONPATH"], str(install.REPO_ROOT))


if __name__ == "__main__":
    unittest.main()
