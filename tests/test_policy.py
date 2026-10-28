import json
import os
import unittest

from aigov.policy import Policy, PolicyError, load_policy, policy_from_dict
from tests.helpers import TempRepoCase


class PolicyDictTests(unittest.TestCase):
    def test_defaults(self):
        policy = policy_from_dict({})
        self.assertEqual(policy.ai_usage, "declared")
        self.assertEqual(policy.min_score, 70)
        self.assertTrue(policy.block_on_critical)
        self.assertEqual(policy.review_threshold, 0.8)
        self.assertEqual(policy.min_test_ratio, 0.1)
        self.assertEqual(policy.max_file_bytes, 1_000_000)

    def test_unknown_key_is_error(self):
        with self.assertRaisesRegex(PolicyError, "unknown policy key"):
            policy_from_dict({"min_scor": 80})

    def test_invalid_values(self):
        bad = [
            {"ai_usage": "sometimes"},
            {"min_score": 101},
            {"min_score": True},
            {"block_on_critical": "yes"},
            {"review_threshold": 1.5},
            {"min_test_ratio": -1},
            {"max_file_bytes": 0},
            {"ignore": "examples/*"},
            {"disabled_controls": ["GOV-99"]},
            {"extra_ai_commit_patterns": ["("]},
            [],
        ]
        for data in bad:
            with self.subTest(data=data):
                with self.assertRaises(PolicyError):
                    policy_from_dict(data)

    def test_valid_full_policy(self):
        policy = policy_from_dict({
            "ai_usage": "none",
            "min_score": 85,
            "block_on_critical": False,
            "review_threshold": 1,
            "min_test_ratio": 0.25,
            "max_file_bytes": 2048,
            "ignore": ["examples/*"],
            "disabled_controls": ["MAN-04"],
            "extra_ai_commit_patterns": [r"\[ai\]"],
        })
        self.assertTrue(policy.is_disabled("MAN-04"))
        self.assertFalse(policy.is_disabled("MAN-03"))
        self.assertTrue(policy.compiled_commit_patterns[0].search("feat: x [AI]"))


class PolicyFileTests(TempRepoCase):
    def test_missing_default_file_gives_defaults(self):
        policy = load_policy(root=self.root)
        self.assertIsNone(policy.source)
        self.assertEqual(policy, Policy())

    def test_default_file_loaded_from_root(self):
        self.write("aigov.policy.json", json.dumps({"min_score": 90}))
        policy = load_policy(root=self.root)
        self.assertEqual(policy.min_score, 90)
        self.assertTrue(policy.source.endswith("aigov.policy.json"))

    def test_explicit_missing_file_is_error(self):
        with self.assertRaises(PolicyError):
            load_policy(os.path.join(self.root, "nope.json"))

    def test_invalid_json_is_error(self):
        path = self.write("p.json", "{not json")
        with self.assertRaisesRegex(PolicyError, "not valid JSON"):
            load_policy(path)


if __name__ == "__main__":
    unittest.main()
