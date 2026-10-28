import base64
import hashlib
import re
import unittest

from aigov.engine import run_scan
from aigov.policy import Policy
from aigov.report import render_html
from aigov.scanner import IGNORE_TOKEN
from tests.helpers import GIT, TempRepoCase, marker

FAKE_KEY = "sk-ant-" + "api03-" + "Zx9Qw2Lm7Rt4Yp8Nc3Vb6Hk1Jd5Gf0Sa"
EVIL = "<script>alert(1)</script>"


def csp_hashes(page: str):
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    return set(re.findall(r"sha256-([A-Za-z0-9+/=]+)", csp))


def sha(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


class ReportTests(TempRepoCase):
    def render(self, policy=None):
        self.result = run_scan(self.root, policy or Policy())
        return render_html(self.result)

    def test_structure(self):
        page = self.render()
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertEqual(len(re.findall(r'<a class="cell (?:pass|warn|fail|na)" href="#ctl-', page)), 13)
        self.assertEqual(len(re.findall(r'<details class="control [a-z]+" id="ctl-', page)), 13)
        self.assertIn(self.result.headline, page)
        self.assertIn("This is not a compliance attestation.", page)
        self.assertIn("prefers-color-scheme: dark", page)
        self.assertIn("prefers-reduced-motion", page)
        self.assertIn("@media print", page)

    def test_self_contained_and_csp_pinned(self):
        page = self.render()
        self.assertNotRegex(page, r"(?:src|href)=\"(?:https?:)?//")
        self.assertNotIn("@import", page)
        style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
        script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
        self.assertEqual(csp_hashes(page), {sha(style), sha(script)})
        self.assertEqual(page.count("<script"), 1)

    def test_filename_is_escaped(self):
        name = "x%s.py" % EVIL.replace("/", "_")
        try:
            self.write(name, marker("ai-generated", "claude") + "\n")
        except OSError:
            self.skipTest("file system does not allow this name")
        page = self.render()
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;_script&gt;", page)

    def test_manifest_path_is_escaped(self):
        self.write(".ai-provenance.json",
                   '{"files": [{"path": "src/%s.py", "tool": "<b>claude</b>"}]}' % EVIL.replace("/", "\\/"))
        page = self.render()
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<b>claude</b>", page)
        self.assertIn("&lt;b&gt;claude&lt;/b&gt;", page)

    @unittest.skipUnless(GIT, "git is not installed")
    def test_commit_subject_is_escaped(self):
        self.git("init", "-q")
        self.commit("feat: %s\n\nCo-authored-by: Claude <noreply@anthropic.com>" % EVIL,
                    author='Eve "<img src=x onerror=alert(2)>" <eve@example.com>')
        page = self.render()
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("feat: &lt;script&gt;", page)
        self.assertNotIn("eve@example.com", page)

    def test_secrets_masked_and_suppressions_listed(self):
        self.write("config.py", "KEY = '%s'\n" % FAKE_KEY)
        self.write("legacy.py", "v = eval(expr)  # %s accepted by Ana\n" % IGNORE_TOKEN)
        page = self.render()
        self.assertNotIn(FAKE_KEY, page)
        self.assertNotIn(FAKE_KEY[8:], page)
        self.assertIn("sk-a… (%d characters, masked)" % len(FAKE_KEY), page)
        suppressions = page.split('id="h-supp"', 1)[1]
        self.assertIn("legacy.py:1", suppressions)
        self.assertIn("MEA-02", suppressions)

    def test_failing_controls_open(self):
        page = self.render()
        self.assertRegex(page, r'<details class="control fail" id="ctl-GOV-01" open>')
        self.assertRegex(page, r'<details class="control na" id="ctl-MAN-01">')


if __name__ == "__main__":
    unittest.main()
