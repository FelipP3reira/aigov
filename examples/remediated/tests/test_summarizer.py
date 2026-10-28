import sys
import types
import unittest

# The SDKs are not needed to test the pure logic.
sys.modules.setdefault("openai", types.ModuleType("openai"))
sys.modules.setdefault("requests", types.ModuleType("requests"))

from app.summarizer import priority  # noqa: E402


class PriorityTests(unittest.TestCase):
    def test_stale(self):
        self.assertTrue(priority({"age_days": 5}, "stale"))
        self.assertFalse(priority({"age_days": 1}, "stale"))

    def test_vip(self):
        self.assertTrue(priority({"plan": "enterprise"}, "vip"))

    def test_unknown_rule_is_rejected(self):
        with self.assertRaises(KeyError):
            priority({}, "anything else")


if __name__ == "__main__":
    unittest.main()
