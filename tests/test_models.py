import unittest

from aigov.models import (
    FAIL, PASS, WARN, Finding, mask_card, mask_cpf, mask_secret, status_from_findings,
)


class StatusTests(unittest.TestCase):
    def test_no_findings_pass(self):
        self.assertEqual(status_from_findings([]), PASS)

    def test_info_only_pass(self):
        self.assertEqual(status_from_findings([Finding("x", "info")]), PASS)

    def test_low_and_medium_warn(self):
        self.assertEqual(status_from_findings([Finding("x", "low")]), WARN)
        self.assertEqual(status_from_findings([Finding("x", "medium")]), WARN)

    def test_high_and_critical_fail(self):
        self.assertEqual(status_from_findings([Finding("x", "low"), Finding("y", "high")]), FAIL)
        self.assertEqual(status_from_findings([Finding("x", "critical")]), FAIL)

    def test_unknown_severity_rejected(self):
        with self.assertRaises(ValueError):
            Finding("x", "severe")


class MaskingTests(unittest.TestCase):
    def test_secret_masked(self):
        raw = "sk-" + "d" + "Q7xP2" * 7 + "abcd"
        masked = mask_secret(raw)
        self.assertEqual(masked, "sk-d… (%d characters, masked)" % len(raw))
        self.assertNotIn(raw[4:], masked)

    def test_short_secret_reveals_nothing(self):
        self.assertEqual(mask_secret("hunter2"), "[7 characters, masked]")

    def test_cpf_masked(self):
        raw = "529" + ".982" + ".247-25"
        self.assertEqual(mask_cpf(raw), "***.***.***-25")

    def test_card_masked(self):
        raw = "4111" + " 1111" * 3
        masked = mask_card(raw)
        self.assertEqual(masked, "**** **** **** 1111 (16 digits, masked)")


if __name__ == "__main__":
    unittest.main()
