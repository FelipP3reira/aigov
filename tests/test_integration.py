"""End-to-end checks on the bundled examples and the demo builder."""

import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import unittest

from aigov.cli import EXIT_GATE_FAILED, EXIT_OK, main
from aigov.engine import run_scan
from aigov.policy import load_policy
from aigov.report import render_html
from tests.helpers import GIT, remove_tree

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")

_spec = importlib.util.spec_from_file_location("build_demo", os.path.join(ROOT, "scripts", "build_demo.py"))
build_demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_demo)

EXPECTED_BEFORE = {
    "GOV-01": "fail", "GOV-02": "fail", "GOV-03": "fail",
    "MAP-01": "fail", "MAP-02": "fail", "MAP-03": "warn",
    "MEA-01": "fail", "MEA-02": "fail", "MEA-03": "fail",
    "MAN-01": "na", "MAN-02": "fail", "MAN-03": "warn", "MAN-04": "fail",
}


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as handle:
        return handle.read()


class ExampleCase(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="aigov-it-")
        self.addCleanup(remove_tree, self.workdir)

    def copy(self, name):
        target = os.path.join(self.workdir, name)
        shutil.copytree(os.path.join(EXAMPLES, name), target)
        return target

    def statuses(self, result):
        return {c.id: c.status for c in result.controls}


class NeedsRemediationTests(ExampleCase):
    def setUp(self):
        super().setUp()
        self.target = self.copy("needs-remediation")
        self.result = run_scan(self.target, load_policy(root=self.target))

    def test_expected_statuses(self):
        self.assertEqual(self.statuses(self.result), EXPECTED_BEFORE)
        self.assertEqual(self.result.verdict, "Blocked")
        self.assertFalse(self.result.gate_passed)

    def test_key_findings(self):
        controls = {c.id: c for c in self.result.controls}
        self.assertEqual([f.severity for f in controls["MEA-01"].findings], ["critical"])
        self.assertEqual({f.severity for f in controls["MEA-02"].findings}, {"high"})
        self.assertEqual(len(controls["MEA-02"].findings), 2)
        self.assertEqual(controls["MAP-03"].findings[0].severity, "medium")
        self.assertIn('"openai"', controls["MAP-02"].findings[0].message)

    def test_raw_values_never_leave(self):
        source = read(self.target, "app", "summarizer.py")
        key = re.search(r'"(sk-proj-[^"]+)"', source).group(1)
        cpf = re.search(r'"cpf": "([^"]+)"', read(self.target, "app", "fixtures", "customers.json")).group(1)
        outputs = [render_html(self.result), json.dumps(self.result.to_dict())]
        out = io.StringIO()
        main(["scan", self.target, "--no-html"], out=out, err=io.StringIO())
        outputs.append(out.getvalue())
        for text in outputs:
            for raw in (key, key[6:], cpf, cpf[:11]):
                self.assertNotIn(raw, text)
        self.assertIn("***.***.***-" + cpf[-2:], outputs[0])

    def test_cli_exit_code(self):
        code = main(["scan", self.target, "--no-html", "--quiet"], out=io.StringIO(), err=io.StringIO())
        self.assertEqual(code, EXIT_GATE_FAILED)


class RemediatedTests(ExampleCase):
    def setUp(self):
        super().setUp()
        self.target = self.copy("remediated")

    def test_all_pass_without_git(self):
        result = run_scan(self.target, load_policy(root=self.target))
        expected = {cid: "pass" for cid in EXPECTED_BEFORE}
        expected["MAN-01"] = "na"
        self.assertEqual(self.statuses(result), expected,
                         [(c.id, [f.message for f in c.findings]) for c in result.controls])
        self.assertEqual((result.score, result.verdict, result.gate_passed), (100.0, "Aligned", True))
        self.assertEqual(result.policy.min_score, 85)

    def test_cli_exit_code(self):
        code = main(["scan", self.target, "--no-html", "--quiet"], out=io.StringIO(), err=io.StringIO())
        self.assertEqual(code, EXIT_OK)


@unittest.skipUnless(GIT, "git is not installed")
class HistoryTests(ExampleCase):
    def test_review_evidence(self):
        before = build_demo.scan_example("needs-remediation", self.workdir)
        after = build_demo.scan_example("remediated", self.workdir)
        man01 = [next(c for c in r.controls if c.id == "MAN-01") for r in (before, after)]
        self.assertEqual([c.status for c in man01], ["fail", "pass"])
        self.assertEqual(len(before.git.commits), 1)
        self.assertFalse(before.git.commits[0].human_reviewed)
        self.assertEqual(after.git.commits[0].reviewers, ["Bruno Lima"])
        self.assertNotIn("example.com", json.dumps(after.to_dict()))

    def test_build_demo_outputs(self):
        out_dir = os.path.join(self.workdir, "demo")
        results = dict(build_demo.build(out_dir))
        self.assertEqual(sorted(os.listdir(out_dir)), [
            "index.html", "needs-remediation.html", "needs-remediation.json",
            "remediated.html", "remediated.json",
        ])
        self.assertEqual(results["remediated"].verdict, "Aligned")
        self.assertEqual(results["needs-remediation"].verdict, "Blocked")
        index = read(out_dir, "index.html")
        self.assertIn('src="needs-remediation.html"', index)
        self.assertIn('src="remediated.html"', index)


class SelfScanPolicyTests(unittest.TestCase):
    def test_root_policy_ignores_examples(self):
        policy = load_policy(root=ROOT)
        self.assertIn("examples/*", policy.ignore)
        result = run_scan(ROOT, policy)
        scanned = json.dumps(result.to_dict())
        self.assertNotIn("examples/needs-remediation", scanned)
        mea01 = next(c for c in result.controls if c.id == "MEA-01")
        self.assertEqual(mea01.findings, [])

    def test_project_passes_its_own_scan(self):
        result = run_scan(ROOT, load_policy(root=ROOT))
        self.assertTrue(result.gate_passed, result.gate_reasons)
        self.assertEqual(result.critical_count, 0)


if __name__ == "__main__":
    unittest.main()
