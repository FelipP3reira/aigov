import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from aigov.cli import EXIT_GATE_FAILED, EXIT_OK, EXIT_USAGE, clean, main
from tests.helpers import TempRepoCase, remove_tree

FAKE_KEY = "sk-ant-" + "api03-" + "Zx9Qw2Lm7Rt4Yp8Nc3Vb6Hk1Jd5Gf0Sa"
LENIENT = {"min_score": 0, "block_on_critical": False}


class CliTests(TempRepoCase):
    def setUp(self):
        super().setUp()
        self.out_dir = tempfile.mkdtemp(prefix="aigov-out-")
        self.addCleanup(remove_tree, self.out_dir)

    def out_path(self, name):
        return os.path.join(self.out_dir, name)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        code = main(list(args), out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def policy_file(self, data):
        path = self.out_path("policy.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        return path

    def test_gate_failure_exit_1(self):
        code, out, _ = self.run_cli("scan", self.root, "--no-html")
        self.assertEqual(code, EXIT_GATE_FAILED)
        self.assertIn("[FAIL] GOV-01", out)
        self.assertIn("gate FAILED", out)
        self.assertIn("not legal advice", out)

    def test_gate_pass_exit_0(self):
        code, out, _ = self.run_cli("scan", self.root, "--no-html",
                                    "--policy", self.policy_file(LENIENT))
        self.assertEqual(code, EXIT_OK, out)

    def test_fail_under_overrides_policy(self):
        policy = self.policy_file(LENIENT)
        code, _, _ = self.run_cli("scan", self.root, "--no-html", "--policy", policy, "--fail-under", "99")
        self.assertEqual(code, EXIT_GATE_FAILED)

    def test_critical_blocks(self):
        self.write("config.py", "KEY = '%s'\n" % FAKE_KEY)
        policy = self.policy_file({"min_score": 0})
        code, out, _ = self.run_cli("scan", self.root, "--no-html", "--policy", policy)
        self.assertEqual(code, EXIT_GATE_FAILED)
        self.assertIn("Blocked", out)

    def test_usage_errors_exit_2(self):
        cases = [
            ("scan", os.path.join(self.root, "missing")),
            ("scan", self.root, "--policy", os.path.join(self.root, "missing.json")),
            ("scan", self.root, "--policy", self.policy_file({"bogus": 1})),
            ("scan", self.root, "--fail-under", "150"),
            ("scan", self.root, "--html", "a.html", "--no-html"),
            ("scan", self.root, "--unknown"),
            (),
        ]
        for args in cases:
            with self.subTest(args=args):
                code, _, err = self.run_cli(*args)
                self.assertEqual(code, EXIT_USAGE)
                self.assertIn("aigov:", err)

    def test_reports_written_and_masked(self):
        self.write("config.py", "KEY = '%s'\n" % FAKE_KEY)
        html, js = self.out_path("r.html"), self.out_path("sub/r.json")
        code, out, _ = self.run_cli("scan", self.root, "--html", html, "--json", js)
        self.assertEqual(code, EXIT_GATE_FAILED)
        with open(js, encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(len(data["controls"]), 13)
        self.assertEqual(data["verdict"], "Blocked")
        with open(html, encoding="utf-8") as handle:
            page = handle.read()
        for text in (out, json.dumps(data), page):
            self.assertNotIn(FAKE_KEY, text)
            self.assertNotIn(FAKE_KEY[8:], text)
        self.assertIn("sk-a… (%d characters, masked)" % len(FAKE_KEY), out)

    def test_quiet(self):
        code, out, _ = self.run_cli("scan", self.root, "--no-html", "--quiet")
        self.assertEqual(code, EXIT_GATE_FAILED)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertTrue(out.startswith("Score "))

    def test_scanned_repo_is_not_written_to(self):
        self.write("app.py", "x = 1\n")
        before = sorted(os.listdir(self.root))
        cwd = os.getcwd()
        os.chdir(self.out_dir)
        try:
            self.run_cli("scan", self.root, "--json", "r.json")
        finally:
            os.chdir(cwd)
        self.assertEqual(sorted(os.listdir(self.root)), before)
        self.assertTrue(os.path.isfile(self.out_path("aigov-report.html")))

    def test_control_characters_stripped(self):
        self.assertEqual(clean("a\x1b[31mb\x07"), "a?[31mb?")

    def test_module_entry_point(self):
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, "-m", "aigov", "scan", self.root, "--no-html", "--quiet"],
            cwd=root_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, EXIT_GATE_FAILED, proc.stderr)
        self.assertTrue(proc.stdout.startswith(b"Score "))


if __name__ == "__main__":
    unittest.main()
