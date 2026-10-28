import json
import unittest

from aigov.checks import (
    canonical_provider, card_brand, cpf_is_valid, is_owner_rule, luhn_is_valid, shannon_entropy,
)
from aigov.engine import run_scan
from aigov.policy import Policy
from aigov.scanner import IGNORE_TOKEN
from tests.helpers import GIT, TempRepoCase, marker


def make_cpf(base: str = "123456789") -> str:
    """Build a check-digit-valid CPF at runtime from nine base digits."""
    digits = [int(d) for d in base]
    for size in (9, 10):
        total = sum(d * (size + 1 - i) for i, d in enumerate(digits[:size]))
        digits.append(total * 10 % 11 % 10)
    s = "".join(map(str, digits))
    return "%s.%s.%s-%s" % (s[:3], s[3:6], s[6:9], s[9:])


TEST_CARD = "4111" + "1111" * 3  # the well-known Visa test number
FAKE_AWS = "AKIA" + "Q7RT2MZ8LP4XN6VB"
FAKE_ANTHROPIC = "sk-ant-" + "api03-" + "Zx9Qw2Lm7Rt4Yp8Nc3Vb6Hk1Jd5Gf0Sa"
GOOD_POLICY = (
    "# AI usage policy\n\nAll AI output requires human review before merge.\n"
    "Never paste personal data or other sensitive data into assistants.\n"
    "Approved tools: Claude Code and GitHub Copilot.\n"
    "The engineer who merges is accountable for the change.\n"
)


class PureFunctionTests(unittest.TestCase):
    def test_cpf(self):
        self.assertTrue(cpf_is_valid(make_cpf()))
        self.assertTrue(cpf_is_valid(make_cpf("987654321").replace(".", "").replace("-", "")))
        self.assertFalse(cpf_is_valid("123.456.789-00"))
        self.assertFalse(cpf_is_valid("111.111.111-11"))
        self.assertFalse(cpf_is_valid("1234567890"))

    def test_luhn_and_brand(self):
        self.assertTrue(luhn_is_valid(TEST_CARD))
        self.assertFalse(luhn_is_valid(TEST_CARD[:-1] + "2"))
        self.assertEqual(card_brand(TEST_CARD), "Visa")
        self.assertEqual(card_brand("5555" + "5555" + "5555" + "4444"), "Mastercard")
        self.assertIsNone(card_brand("1234567890123456"))

    def test_entropy(self):
        self.assertLess(shannon_entropy("aaaaaaaa"), 1)
        self.assertGreater(shannon_entropy("Zx9Qw2Lm7Rt4"), 3)

    def test_owner_rule(self):
        self.assertTrue(is_owner_rule("* @org/team"))
        self.assertTrue(is_owner_rule("/docs/ dev@example.com"))
        self.assertFalse(is_owner_rule("*"))
        self.assertFalse(is_owner_rule("# * @org/team"))

    def test_canonical_provider(self):
        self.assertEqual(canonical_provider("Google"), "google-gemini")
        self.assertEqual(canonical_provider("google-gemini"), "google-gemini")
        self.assertEqual(canonical_provider("Hugging Face"), "huggingface")
        self.assertEqual(canonical_provider("Anthropic"), "anthropic")
        self.assertIsNone(canonical_provider("acme"))


class ControlCase(TempRepoCase):
    def control(self, control_id, policy=None):
        result = run_scan(self.root, policy or Policy())
        self.result = result
        return next(c for c in result.controls if c.id == control_id)

    def assertStatus(self, control_id, status, policy=None):
        control = self.control(control_id, policy)
        self.assertEqual(control.status, status, [f.message for f in control.findings])
        return control


class GovernTests(ControlCase):
    def test_gov01(self):
        self.assertStatus("GOV-01", "fail")
        self.write("docs/ai-usage.md", "# AI\nAll code gets human review.\n")
        self.assertEqual(len(self.assertStatus("GOV-01", "warn").findings), 3)
        self.write("docs/ai-usage.md", GOOD_POLICY)
        self.assertStatus("GOV-01", "pass")

    def test_gov02(self):
        self.assertStatus("GOV-02", "fail")
        self.write(".github/CODEOWNERS", "# owners\n*\n")
        self.assertStatus("GOV-02", "fail")
        self.write(".github/CODEOWNERS", "* @acme/platform\n")
        self.assertStatus("GOV-02", "pass")

    def test_gov03(self):
        self.assertStatus("GOV-03", "fail")
        self.write(".github/pull_request_template.md", "## Summary\n\n- [ ] Tests added\n")
        self.assertStatus("GOV-03", "warn")
        self.write(".github/pull_request_template.md",
                   "- [ ] AI assistance used? Which tool?\n- [ ] A human reviewed this change\n")
        self.assertStatus("GOV-03", "pass")


class MapTests(ControlCase):
    def test_map01_no_signals_warn(self):
        self.write("app.py", "x = 1\n")
        self.assertStatus("MAP-01", "warn")

    def test_map01_unreviewed_fail_then_pass(self):
        self.write("app.py", marker("ai-generated", "claude") + "\nx = 1\n")
        self.assertStatus("MAP-01", "fail")
        self.write("app.py", marker("ai-generated", "claude") + "\n"
                   + marker("reviewed-by", "Copilot") + "\nx = 1\n")
        control = self.assertStatus("MAP-01", "fail")
        self.assertIn("AI tool", control.findings[0].message)
        self.write("app.py", marker("ai-generated", "claude") + "\n"
                   + marker("reviewed-by", "Ana Souza") + "\nx = 1\n")
        self.assertStatus("MAP-01", "pass")

    def test_map01_missing_file_warn(self):
        self.write(".ai-provenance.json", json.dumps(
            {"files": [{"path": "gone.py", "tool": "claude", "reviewed_by": "Ana"}]}))
        self.assertStatus("MAP-01", "warn")

    def test_map01_policy_none(self):
        self.write("app.py", marker("ai-generated", "claude") + "\n" + marker("reviewed-by", "Ana") + "\n")
        self.assertStatus("MAP-01", "fail", Policy(ai_usage="none"))

    def test_map02(self):
        self.write("app.py", "# import openai\nimport os\n")
        self.assertStatus("MAP-02", "pass")
        self.write("app.py", "import anthropic\n")
        self.write("web/chat.ts", "import OpenAI from 'openai';\n")
        control = self.assertStatus("MAP-02", "fail")
        self.assertEqual(len(control.findings), 2)
        self.write(".ai-provenance.json", json.dumps({"ai_systems": [
            {"provider": "anthropic", "purpose": "summaries", "owner": "data"},
            {"provider": "openai", "purpose": "chat"},
        ]}))
        self.assertStatus("MAP-02", "warn")

    def test_map02_dependency_manifest(self):
        self.write("requirements.txt", "langchain-anthropic==0.3.0\n")
        control = self.assertStatus("MAP-02", "fail")
        self.assertEqual({f.message.split('"')[1] for f in control.findings}, {"anthropic", "langchain"})

    def test_map03(self):
        cpf = make_cpf()
        self.write("src/users.py", "OWNER = '%s'\n" % cpf)
        control = self.assertStatus("MAP-03", "fail")
        self.assertEqual(control.findings[0].evidence, "***.***.***-" + cpf[-2:])
        self.write("src/users.py", "x = 1\n")
        self.write("tests/fixtures/people.json", '{"cpf": "%s", "card": "%s"}\n' % (
            cpf.replace(".", "").replace("-", ""), TEST_CARD))
        control = self.assertStatus("MAP-03", "warn")
        self.assertEqual(len(control.findings), 2)

    def test_map03_ignores_invalid(self):
        self.write("a.txt", "id 123.456.789-00 and 12345678901 and 4111111111111112\n")
        self.assertStatus("MAP-03", "pass")


class MeasureTests(ControlCase):
    def test_mea01_specific_is_critical(self):
        self.write("config.py", "AWS_KEY = '%s'\nCLAUDE = '%s'\n" % (FAKE_AWS, FAKE_ANTHROPIC))
        control = self.assertStatus("MEA-01", "fail")
        self.assertEqual({f.severity for f in control.findings}, {"critical"})
        self.assertEqual(self.result.verdict, "Blocked")

    def test_mea01_generic_and_placeholders(self):
        self.write("settings.py", 'PASSWORD = "changeme"\nAPI_KEY = os.environ["API_KEY"]\n'
                   'token = "aaaaaaaaaaaa"\nDB_URL = "https://db.example"\n')
        self.assertStatus("MEA-01", "pass")
        self.write("settings.py", 'db_password = "Tr0ub4' 'dor&3xQ"\n')
        control = self.assertStatus("MEA-01", "fail")
        self.assertEqual(control.findings[0].severity, "high")

    def test_mea01_env_file(self):
        self.write(".env", "DEBUG=1\n")
        self.assertStatus("MEA-01", "fail")
        self.write(".gitignore", ".env\n")
        self.assertStatus("MEA-01", "pass")

    def test_mea01_raw_value_never_in_output(self):
        self.write("config.py", "KEY = '%s'\nOWNER = '%s'\n" % (FAKE_ANTHROPIC, make_cpf()))
        self.control("MEA-01")
        dumped = json.dumps(self.result.to_dict())
        self.assertNotIn(FAKE_ANTHROPIC, dumped)
        self.assertNotIn(FAKE_ANTHROPIC[8:], dumped)
        self.assertNotIn(make_cpf(), dumped)

    def test_mea02(self):
        self.write("app.py", "# eval(x) in a comment\nimport subprocess\n")
        self.write("tests/test_app.py", "eval('1')\n")
        self.assertStatus("MEA-02", "pass")
        self.write("app.py", "r = requests.get(u, verify=False)\nv = eval(expr)\n")
        control = self.assertStatus("MEA-02", "warn")
        self.assertEqual(len(control.findings), 2)
        self.write("app.py", marker("ai-generated", "claude") + "\nv = eval(expr)\n")
        self.assertStatus("MEA-02", "fail")

    def test_mea02_patterns(self):
        lines = [
            "subprocess.run(cmd, shell=True)",
            "data = pickle.loads(blob)",
            "cfg = yaml.load(f)",
            'cur.execute("SELECT * FROM users WHERE id = " + uid)',
            'cur.execute(f"DELETE FROM t WHERE id = {uid}")',
        ]
        self.write("app.py", "\n".join(lines) + "\nok = yaml.load(f, Loader=yaml.SafeLoader)\n")
        self.write("web/x.js", "el.innerHTML = html;\nrequire('child_process').exec(cmd);\n"
                   "https.request({rejectUnauthorized: false});\n")
        self.write("x.php", "<?php system($cmd); $o = unserialize($s);\n")
        control = self.control("MEA-02")
        self.assertEqual(len(control.findings), 10, [(f.file, f.line, f.message) for f in control.findings])

    def test_mea03(self):
        self.write("src/a.py", "x = 1\n")
        self.assertStatus("MEA-03", "fail")
        for i in range(9):  # 10 source files, 1 test file: ratio 0.10
            self.write("src/m%d.py" % i, "x = 1\n")
        self.write("tests/test_a.py", "pass\n")
        self.assertStatus("MEA-03", "warn", Policy(min_test_ratio=0.5))
        self.assertStatus("MEA-03", "pass")

    def test_mea03_na_without_code(self):
        self.write("README.md", "hi\n")
        self.assertStatus("MEA-03", "na")


class ManageTests(ControlCase):
    def test_man01_na_without_git(self):
        self.assertStatus("MAN-01", "na")

    @unittest.skipUnless(GIT, "git is not installed")
    def test_man01_review_rate(self):
        self.git("init", "-q")
        self.commit("feat: a\n\nCo-authored-by: Claude <noreply@anthropic.com>")
        self.assertStatus("MAN-01", "fail")
        self.commit("feat: b\n\nCo-authored-by: Claude <noreply@anthropic.com>\nReviewed-by: Ana <a@x.io>")
        self.assertStatus("MAN-01", "warn")  # 50% >= 0.8 / 2
        self.commit("feat: c\n\nAI-Assisted: yes\nReviewed-by: Ana <a@x.io>")
        self.assertStatus("MAN-01", "pass", Policy(review_threshold=0.6))

    def test_man02(self):
        self.assertStatus("MAN-02", "fail")
        self.write(".github/workflows/ci.yml", "jobs:\n  b:\n    steps:\n      - run: echo hi\n")
        self.assertStatus("MAN-02", "warn")
        self.write(".github/workflows/ci.yml", "jobs:\n  b:\n    steps:\n      - run: python -m unittest\n")
        self.assertStatus("MAN-02", "pass")

    def test_man03(self):
        self.write("README.md", "")
        self.assertStatus("MAN-03", "na")
        self.write("requirements.txt", "requests>=2\nflask==3.0.0\n")
        self.assertStatus("MAN-03", "warn")
        self.write("web/package.json", "{}")
        self.assertStatus("MAN-03", "fail")
        self.write("web/package-lock.json", "{}")
        self.write("requirements.txt", "requests==2.32.3\nflask==3.0.0\n")
        self.assertStatus("MAN-03", "pass")

    def test_man03_pyproject(self):
        self.write("pyproject.toml", '[project]\nname = "x"\ndependencies = []\n')
        self.assertStatus("MAN-03", "na")
        self.write("pyproject.toml", '[project]\nname = "x"\ndependencies = ["requests>=2"]\n')
        self.assertStatus("MAN-03", "fail")
        self.write("uv.lock", "")
        self.assertStatus("MAN-03", "pass")

    def test_man04(self):
        self.assertStatus("MAN-04", "fail")
        self.write("docs/incident-runbook.md", "# Runbook\n")
        self.assertStatus("MAN-04", "warn")
        self.write("SECURITY.md", "# Security\n")
        self.assertStatus("MAN-04", "pass")


class SuppressionTests(ControlCase):
    def test_line_suppression_is_listed(self):
        self.write("app.py", "x = 1\nv = eval(expr)  # %s reviewed by Ana\n" % IGNORE_TOKEN)
        control = self.assertStatus("MEA-02", "pass")
        self.assertEqual(control.findings, [])
        [suppression] = self.result.suppressions
        self.assertEqual((suppression.file, suppression.line, suppression.scope, suppression.control),
                         ("app.py", 2, "line", "MEA-02"))
        self.assertEqual(self.result.to_dict()["suppressions"][0]["line"], 2)

    def test_file_suppression_is_listed(self):
        self.write("legacy.py", "# %s-file\nv = eval(a)\nw = eval(b)\n" % IGNORE_TOKEN)
        self.control("MEA-02")
        self.assertEqual([(s.line, s.scope, s.directive_line) for s in self.result.suppressions],
                         [(2, "file", 1), (3, "file", 1)])


if __name__ == "__main__":
    unittest.main()
