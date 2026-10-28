import os
import unittest

from aigov.policy import Policy
from aigov.scanner import (
    IGNORE_TOKEN, GitIgnore, is_comment_line, is_env_file, scan_repository,
)
from tests.helpers import TempRepoCase


class WalkTests(TempRepoCase):
    def rels(self, repo):
        return [f.rel for f in repo.files]

    def test_skips_vendor_dirs(self):
        self.write("src/app.py", "x = 1\n")
        for skipped in (".git", "node_modules", "vendor", "venv", "dist", "build"):
            self.write(skipped + "/inner.py", "x = 1\n")
        self.assertEqual(self.rels(scan_repository(self.root)), ["src/app.py"])

    def test_size_limit_and_binary(self):
        self.write("big.py", "a" * 200)
        self.write("image.png", b"\x89PNG\x00\x00data", binary=True)
        self.write("small.py", "ok\n")
        repo = scan_repository(self.root, Policy(max_file_bytes=100))
        self.assertEqual(self.rels(repo), ["small.py"])
        reasons = dict(repo.skipped)
        self.assertIn("larger than", reasons["big.py"])
        self.assertEqual(reasons["image.png"], "binary")

    def test_policy_ignore_globs(self):
        self.write("examples/demo/app.py", "x\n")
        self.write("src/app.py", "x\n")
        self.write("src/bundle.min.js", "x\n")
        repo = scan_repository(self.root, Policy(ignore=["examples/*", "*.min.js"]))
        self.assertEqual(self.rels(repo), ["src/app.py"])
        self.assertEqual(repo.ignored_by_policy, 2)

    def test_symlinks_not_followed(self):
        target = self.write("outside/secret.py", "x\n")
        link = os.path.join(self.root, "link.py")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        repo = scan_repository(self.root)
        self.assertNotIn("link.py", self.rels(repo))
        self.assertIn(("link.py", "symlink not followed"), repo.skipped)

    def test_env_file_ignored_by_git_not_scanned(self):
        self.write(".gitignore", ".env\n")
        self.write(".env", "TOKEN=abc\n")
        self.write("config/.env.production", "TOKEN=abc\n")
        self.write(".env.example", "TOKEN=\n")
        repo = scan_repository(self.root)
        self.assertNotIn(".env", self.rels(repo))
        self.assertIn("config/.env.production", self.rels(repo))
        self.assertIn(".env.example", self.rels(repo))
        self.assertEqual(
            sorted(repo.env_files), [(".env", True), ("config/.env.production", False)]
        )

    def test_test_and_fixture_classification(self):
        self.write("tests/test_app.py", "")
        self.write("src/app_test.go", "")
        self.write("web/button.spec.ts", "")
        self.write("data/fixtures/people.json", "")
        self.write("src/app.py", "")
        repo = scan_repository(self.root)
        by = {f.rel: f for f in repo.files}
        self.assertTrue(by["tests/test_app.py"].is_test)
        self.assertTrue(by["src/app_test.go"].is_test)
        self.assertTrue(by["web/button.spec.ts"].is_test)
        self.assertFalse(by["data/fixtures/people.json"].is_test)
        self.assertTrue(by["data/fixtures/people.json"].is_fixture)
        self.assertFalse(by["src/app.py"].is_fixture)
        self.assertTrue(by["src/app.py"].is_code)
        self.assertFalse(by["data/fixtures/people.json"].is_code)

    def test_path_exists_rejects_escape(self):
        self.write("a.py", "")
        repo = scan_repository(self.root)
        self.assertTrue(repo.path_exists("a.py"))
        self.assertFalse(repo.path_exists("../a.py"))
        self.assertFalse(repo.path_exists("/etc/passwd"))
        self.assertFalse(repo.path_exists("missing.py"))


class SuppressionTests(TempRepoCase):
    def test_line_directive(self):
        self.write("a.py", "x = 1\ny = eval(s)  # %s\n" % IGNORE_TOKEN)
        source = scan_repository(self.root).get("a.py")
        self.assertIsNone(source.suppression(1))
        self.assertEqual(source.suppression(2), ("line", 2))

    def test_file_directive_in_header(self):
        self.write("a.py", "# %s-file\n" % IGNORE_TOKEN + "x\n" * 5)
        source = scan_repository(self.root).get("a.py")
        self.assertEqual(source.suppression(4), ("file", 1))

    def test_file_directive_after_header_ignored(self):
        self.write("a.py", "x\n" * 45 + "# %s-file\n" % IGNORE_TOKEN)
        source = scan_repository(self.root).get("a.py")
        self.assertIsNone(source.suppression(3))
        # The file directive is not mistaken for a line directive either.
        self.assertIsNone(source.suppression(46))


class HelperTests(TempRepoCase):
    def test_comment_lines(self):
        for line in ("# x", "  // x", "/* x", " * x", "<!-- x", "-- x"):
            self.assertTrue(is_comment_line(line), line)
        for line in ("x = 1", "#!/usr/bin/env python", "", "'text'"):
            self.assertFalse(is_comment_line(line), line)

    def test_env_names(self):
        self.assertTrue(is_env_file(".env"))
        self.assertTrue(is_env_file(".env.local"))
        self.assertTrue(is_env_file("prod.env"))
        self.assertFalse(is_env_file(".env.example"))
        self.assertFalse(is_env_file("environment.py"))

    def test_gitignore_subset(self):
        self.write(".gitignore", "*.env\n!keep.env\nsecrets/\n/.env.local\n")
        self.write("sub/.gitignore", ".env\n")
        ignore = GitIgnore(self.root)
        self.assertTrue(ignore.is_ignored("prod.env"))
        self.assertFalse(ignore.is_ignored("keep.env"))
        self.assertTrue(ignore.is_ignored("secrets/.env"))
        self.assertTrue(ignore.is_ignored(".env.local"))
        self.assertFalse(ignore.is_ignored("deep/.env.local"))
        self.assertTrue(ignore.is_ignored("sub/.env"))
        self.assertTrue(ignore.is_ignored(".env"))  # "*.env" matches ".env" in git too
        self.assertFalse(ignore.is_ignored("config/.env.production"))


if __name__ == "__main__":
    unittest.main()
