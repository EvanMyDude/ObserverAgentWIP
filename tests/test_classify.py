import unittest

from observer import classify as c


class RuleRiskTest(unittest.TestCase):
    CASES = {
        "Bash(git log *)": "low",
        "Bash(git log:*)": "low",
        "Bash(git branch *)": "medium",   # includes git branch -D
        "Bash(git push *)": "high",
        "Bash(git config *)": "high",     # can set a pager or ssh command that runs code
        "Bash(git -c core.pager=x log *)": "high",
        "Bash(gh pr view *)": "low",
        "Bash(gh pr *)": "high",          # includes gh pr merge
        "Bash(gh api *)": "high",
        "Bash(curl *)": "high",
        "Bash(*)": "high",
        "Bash": "high",
        "Bash(npm test *)": "low",
        "Bash(npm run *)": "medium",
        "Bash(npx *)": "high",
        "Bash(python3 -m pytest *)": "low",
        "Bash(python3 *)": "high",
        "Bash(make *)": "high",
        "Bash(ls && rm -rf /)": "high",
        "Bash(kubectl get *)": "medium",
        "WebFetch": "high",
        "WebFetch(domain:docs.python.org)": "low",
        "mcp__notion__notion-search": "low",
        "mcp__github__merge_pull_request": "high",
        "mcp__github": "high",
        "Read(~/.ssh/**)": "high",
        "Read(//Users/me/proj/**)": "low",
        "Edit(//Users/me/**)": "high",
        "Edit(./src/**)": "medium",
    }

    def test_table(self):
        for rule, expected in self.CASES.items():
            with self.subTest(rule=rule):
                self.assertEqual(c.rule_risk(rule)[0], expected)


class ShellTest(unittest.TestCase):
    def test_synth_rule_is_narrow(self):
        self.assertEqual(c.synth_rule("Bash", {"command": "git status"}), "Bash(git status *)")
        self.assertEqual(c.synth_rule("Bash", {"command": "gh pr view 12"}), "Bash(gh pr view *)")
        self.assertEqual(c.synth_rule("Bash", {"command": "FOO=1 npm test"}), "Bash(npm test *)")
        self.assertEqual(c.synth_rule("Bash", {"command": "npm test 2>&1"}), "Bash(npm test *)")
        self.assertEqual(c.synth_rule("WebFetch", {"url": "https://docs.python.org/3/x"}), "WebFetch(domain:docs.python.org)")

    def test_synth_rule_refuses_compound_commands(self):
        for command in ("cd x && git log", "ls | head", "echo $(whoami)", "ls > out.txt", "git -C /x status"):
            with self.subTest(command=command):
                self.assertIsNone(c.synth_rule("Bash", {"command": command}))

    def test_first_program_skips_prefixes(self):
        self.assertEqual(c.first_program("cd repo && FOO=1 pytest -q"), "pytest")
        self.assertEqual(c.first_program("/usr/local/bin/jq . x.json"), "jq")

    def test_bash_risk(self):
        self.assertEqual(c.bash_risk("ls -la | head")[0], "low")
        self.assertEqual(c.bash_risk("cat x 2>/dev/null")[0], "low")
        self.assertEqual(c.bash_risk("ls > out.txt")[0], "medium")
        self.assertEqual(c.bash_risk("echo `id`")[0], "high")
        self.assertEqual(c.bash_risk("find . -name x -delete")[0], "high")

    def test_missing_program(self):
        self.assertEqual(c.missing_program("bash: jq: command not found"), "jq")
        self.assertEqual(c.missing_program("zsh: command not found: rg"), "rg")
        self.assertEqual(c.missing_program("/bin/sh: 1: fd: not found"), "fd")
        self.assertEqual(c.missing_program("Exit code 127\n/opt/bin/bash: line 3: pdftotext: command not found"), "pdftotext")


class ResultTest(unittest.TestCase):
    def test_error_classes_from_real_messages(self):
        # Strings captured from Claude Code 2.1.287 tool results.
        self.assertEqual(c.classify_result("Read", {}, "File does not exist. Note: your current working directory is /x.", True),
                         ("error", "file_not_found"))
        self.assertEqual(c.classify_result("Edit", {}, "<tool_use_error>String to replace not found in file.\nString: x</tool_use_error>", True),
                         ("error", "edit_mismatch"))
        self.assertEqual(c.classify_result("Bash", {"command": "ls /nope"}, "Exit code 3\nls: cannot access '/nope': No such file or directory", True),
                         ("error", "file_not_found"))

    def test_benign_failures(self):
        self.assertEqual(c.classify_result("Bash", {"command": "grep foo x"}, "Exit code 1", True), ("error", "no_match"))
        self.assertEqual(c.classify_result("Bash", {"command": "pytest -q"}, "Exit code 1\nFAILED test_x", True),
                         ("error", "check_failure"))

    def test_rejection_and_denial(self):
        reject = ("The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file "
                  "edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user.")
        self.assertEqual(c.classify_result("Bash", {}, reject, True), ("rejected", None))
        self.assertEqual(c.classify_result("Bash", {}, "Permission to use Bash with command git push has been denied.", True),
                         ("denied", None))

    def test_quoted_rejection_text_in_output_is_not_a_rejection(self):
        # Regression: a grep over the CLI binary printed the rejection phrase inside normal output.
        output = "== reject strings\nThe user doesn't want to proceed with this tool use"
        self.assertEqual(c.classify_result("Bash", {"command": "grep -a x bin"}, output, False), ("ok", None))
        self.assertEqual(c.classify_result("Bash", {"command": "grep -a x bin"}, "Exit code 2\n" + output, True)[0], "error")

    def test_text_signals(self):
        self.assertIn("Notion", c.capability_gap_sentence("Sorry, I don't have access to your Notion workspace here."))
        self.assertIsNone(c.capability_gap_sentence("I updated the file."))
        self.assertTrue(c.looks_like_correction("No, use pnpm instead"))
        self.assertFalse(c.looks_like_correction("Now add tests"))

    def test_rules_from_suggestions(self):
        suggestions = [{"type": "addRules", "behavior": "allow", "destination": "localSettings",
                        "rules": [{"toolName": "Bash", "ruleContent": "git log:*"}]},
                       {"type": "addRules", "behavior": "deny", "rules": [{"toolName": "Bash", "ruleContent": "rm:*"}]}]
        self.assertEqual(c.rules_from_suggestions(suggestions), ["Bash(git log:*)"])
        self.assertEqual(c.rules_from_suggestions(None), [])

    def test_input_key_matches_hook_and_transcript(self):
        self.assertEqual(c.input_key("Bash", {"command": "git log", "description": "a"}),
                         c.input_key("Bash", {"command": "git log"}))


if __name__ == "__main__":
    unittest.main()
