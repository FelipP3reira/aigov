import unittest

from aigov.engine import (
    compute_headline, compute_score, compute_verdict, evaluate_gate, run_scan,
)
from aigov.models import CONTROL_IDS, ControlResult
from aigov.policy import Policy
from tests.helpers import TempRepoCase


def control(status, weight=1, function="Govern"):
    return ControlResult("X", "t", function, weight, status, "", "", "")


class ScoreTests(unittest.TestCase):
    def test_weighted_score(self):
        controls = [control("pass", 3), control("warn", 2), control("fail", 1), control("na", 5)]
        # (3*1 + 2*0.5 + 1*0) / (3 + 2 + 1) = 4 / 6
        self.assertEqual(compute_score(controls), 66.7)

    def test_all_na(self):
        self.assertIsNone(compute_score([control("na")]))

    def test_verdict(self):
        self.assertEqual(compute_verdict(100, 1), "Blocked")
        self.assertEqual(compute_verdict(85, 0), "Aligned")
        self.assertEqual(compute_verdict(84.9, 0), "Partial")
        self.assertEqual(compute_verdict(60, 0), "Partial")
        self.assertEqual(compute_verdict(59.9, 0), "Gaps")
        self.assertEqual(compute_verdict(None, 0), "Gaps")

    def test_headline(self):
        controls = [control("warn"), control("fail"), control("fail"), control("pass")]
        self.assertEqual(compute_headline("Partial", controls, 0),
                         "Partial alignment: 3 controls need work before this ships")
        self.assertEqual(compute_headline("Aligned", controls[:1], 0),
                         "Aligned: 1 control needs attention")
        self.assertEqual(compute_headline("Blocked", controls, 1),
                         "Blocked: 1 critical finding must be fixed before this ships")

    def test_gate(self):
        policy = Policy()
        self.assertEqual(evaluate_gate(80, 0, policy), [])
        self.assertEqual(len(evaluate_gate(69, 0, policy)), 1)
        self.assertEqual(len(evaluate_gate(90, 2, policy)), 1)
        self.assertEqual(evaluate_gate(90, 2, Policy(block_on_critical=False)), [])
        self.assertEqual(len(evaluate_gate(80, 0, policy, fail_under=90)), 1)


class RunScanTests(TempRepoCase):
    def test_all_controls_present_in_order(self):
        result = run_scan(self.root, Policy())
        self.assertEqual([c.id for c in result.controls], list(CONTROL_IDS))
        self.assertEqual(set(result.function_scores), {"Govern", "Map", "Measure", "Manage"})

    def test_disabled_controls_are_na(self):
        result = run_scan(self.root, Policy(disabled_controls=["GOV-01", "MAN-04"]))
        disabled = [c for c in result.controls if c.id in ("GOV-01", "MAN-04")]
        for c in disabled:
            self.assertEqual((c.status, c.summary, c.findings), ("na", "Disabled by policy", []))

    def test_empty_repo_fails_gate(self):
        result = run_scan(self.root, Policy())
        self.assertFalse(result.gate_passed)
        self.assertIn(result.verdict, ("Gaps", "Partial"))
        self.assertIn("not legal advice", result.to_dict()["disclaimer"])


if __name__ == "__main__":
    unittest.main()
