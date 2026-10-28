import json
import unittest

from aigov.policy import Policy
from aigov.provenance import (
    analyse_commit, collect_declarations, is_ai_actor, load_manifest, parse_markers,
    parse_trailers, read_git_history,
)
from aigov.scanner import scan_repository
from tests.helpers import GIT, TempRepoCase, marker


class ActorTests(unittest.TestCase):
    def test_ai_actors(self):
        for text in ("Claude <noreply@anthropic.com>", "github-copilot[bot]",
                     "Cursor Agent", "gpt-4o", "aider (gemini)", "OpenAI Codex"):
            self.assertIsNotNone(is_ai_actor(text), text)

    def test_humans(self):
        for text in ("Maria Silva <maria@example.com>", "Gptransport Ltd", "Precursor"):
            self.assertIsNone(is_ai_actor(text), text)


class ManifestTests(TempRepoCase):
    def test_absent(self):
        manifest = load_manifest(self.root)
        self.assertFalse(manifest.present)
        self.assertEqual(manifest.errors, [])

    def test_valid_and_invalid_entries(self):
        self.write(".ai-provenance.json", json.dumps({
            "ai_systems": [
                {"provider": "Anthropic", "purpose": "summaries", "owner": "data-team",
                 "data_categories": ["support tickets"]},
                {"purpose": "no provider"},
                "not an object",
            ],
            "files": [
                {"path": "./src/x.py", "tool": "claude", "reviewed_by": "Ana",
                 "reviewed_at": "2026-10-01"},
                {"path": "../escape.py", "tool": "claude"},
                {"path": "src/y.py"},
                {"path": "src/z.py", "tool": "copilot", "reviewed_at": "01/10/2026"},
            ],
        }))
        manifest = load_manifest(self.root)
        self.assertTrue(manifest.present)
        self.assertEqual([s.provider for s in manifest.ai_systems], ["anthropic"])
        self.assertEqual([f.path for f in manifest.files], ["src/x.py"])
        self.assertEqual(manifest.files[0].reviewed_by, "Ana")
        self.assertEqual(len(manifest.errors), 5)

    def test_invalid_json(self):
        self.write(".ai-provenance.json", "{")
        manifest = load_manifest(self.root)
        self.assertTrue(manifest.present)
        self.assertIn("not valid JSON", manifest.errors[0])


class MarkerTests(TempRepoCase):
    def test_python_markers(self):
        self.write("src/a.py", "\n".join([
            '"""Module."""',
            marker("ai-generated", "claude"),
            marker("model", "claude-opus-5-5"),
            marker("reviewed-by", "Ana Souza"),
            marker("reviewed-at", "2026-10-01"),
            "x = 1",
        ]))
        declaration = parse_markers(scan_repository(self.root).get("src/a.py"))
        self.assertEqual(declaration.tool, "claude")
        self.assertEqual(declaration.model, "claude-opus-5-5")
        self.assertEqual(declaration.reviewed_by, "Ana Souza")
        self.assertEqual(declaration.reviewed_at, "2026-10-01")
        self.assertEqual(declaration.kind, "generated")

    def test_comment_terminators_removed(self):
        self.write("web/a.js", marker("ai-assisted", "copilot */", leader="/*") + "\n")
        self.write("web/b.html", marker("ai-generated", "cursor -->", leader="<!--") + "\n")
        repo = scan_repository(self.root)
        js = parse_markers(repo.get("web/a.js"))
        html = parse_markers(repo.get("web/b.html"))
        self.assertEqual((js.tool, js.kind), ("copilot", "assisted"))
        self.assertEqual(html.tool, "cursor")

    def test_only_code_files_and_header(self):
        self.write("README.md", marker("ai-generated", "claude") + "\n")
        self.write("late.py", "x = 1\n" * 40 + marker("ai-generated", "claude") + "\n")
        self.write("string.py", 'X = "%s"\n' % marker("ai-generated", "claude"))
        repo = scan_repository(self.root)
        for rel in ("README.md", "late.py", "string.py"):
            self.assertIsNone(parse_markers(repo.get(rel)), rel)

    def test_merge_manifest_and_marker(self):
        self.write("src/a.py", "\n".join([
            marker("ai-generated", "claude"), marker("reviewed-by", "Ana"), "x = 1",
        ]))
        self.write("src/b.py", marker("ai-assisted", "copilot") + "\n")
        self.write(".ai-provenance.json", json.dumps({
            "files": [{"path": "src/a.py", "tool": "claude", "model": "m1"}],
        }))
        repo = scan_repository(self.root)
        declarations = collect_declarations(repo, load_manifest(self.root))
        self.assertEqual(sorted(declarations), ["src/a.py", "src/b.py"])
        a = declarations["src/a.py"]
        self.assertEqual((a.model, a.reviewed_by), ("m1", "Ana"))
        self.assertEqual(a.sources, ["manifest", "marker"])


class CommitTests(unittest.TestCase):
    def test_trailers(self):
        message = "feat: x\n\nBody text.\n\nReviewed-by: Ana <ana@example.com>\nCo-authored-by: Claude <noreply@anthropic.com>\n"
        self.assertEqual(parse_trailers(message), [
            ("reviewed-by", "Ana <ana@example.com>"),
            ("co-authored-by", "Claude <noreply@anthropic.com>"),
        ])

    def test_co_author_and_human_review(self):
        commit = analyse_commit(
            "abc", "Ana", "ana@example.com", "2026-10-01T10:00:00+00:00",
            "feat: x\n\nCo-authored-by: Claude <noreply@anthropic.com>\nReviewed-by: Bruno <b@example.com>",
        )
        self.assertTrue(commit.ai_assisted)
        self.assertEqual(commit.ai_signals, ["Co-authored-by: Claude"])
        self.assertEqual(commit.reviewers, ["Bruno"])
        self.assertTrue(commit.human_reviewed)
        self.assertNotIn("example.com", repr(commit.to_dict()))

    def test_ai_reviewer_does_not_count(self):
        commit = analyse_commit(
            "abc", "Ana", "a@example.com", "", "fix\n\nAI-Assisted: yes\nReviewed-by: Copilot"
        )
        self.assertTrue(commit.ai_assisted)
        self.assertFalse(commit.human_reviewed)
        self.assertEqual(commit.ai_reviewers, ["Copilot"])

    def test_generated_with_footer(self):
        commit = analyse_commit(
            "abc", "Ana", "a@example.com", "",
            "fix\n\n\U0001F916 Generated with [Claude Code](https://claude.com/claude-code)",
        )
        self.assertEqual(commit.ai_signals, ["Generated with Claude Code"])

    def test_non_ai_generated_footer_ignored(self):
        commit = analyse_commit("abc", "Ana", "a@example.com", "", "chore\n\nGenerated with protoc")
        self.assertFalse(commit.ai_assisted)

    def test_negative_ai_assisted_value(self):
        commit = analyse_commit("abc", "Ana", "a@example.com", "", "fix\n\nAI-Assisted: no")
        self.assertFalse(commit.ai_assisted)

    def test_assisted_by_and_ai_author(self):
        commit = analyse_commit(
            "abc", "Devin AI", "devin-ai-integration[bot]@users.noreply.github.com", "",
            "fix\n\nAssisted-by: Gemini",
        )
        self.assertEqual(commit.ai_signals, ["Assisted-by: Gemini", "AI author: Devin AI"])

    def test_policy_pattern(self):
        policy = Policy(extra_ai_commit_patterns=[r"\[ai\]"])
        commit = analyse_commit("abc", "Ana", "a@example.com", "", "[AI] refactor", policy)
        self.assertEqual(commit.ai_signals, [r"Policy pattern: \[ai\]"])


@unittest.skipUnless(GIT, "git is not installed")
class GitHistoryTests(TempRepoCase):
    def test_not_a_repository(self):
        history = read_git_history(self.root)
        self.assertFalse(history.available)

    def test_history(self):
        self.git("init", "-q")
        self.write("a.py", "x = 1\n")
        self.commit("feat: human work")
        self.write("b.py", "y = 2\n")
        self.commit("feat: ai work\n\nCo-authored-by: Claude <noreply@anthropic.com>")
        self.write("c.py", "z = 3\n")
        self.commit("feat: reviewed ai work\n\nCo-authored-by: GitHub Copilot <copilot@github.com>\n"
                    "Reviewed-by: Ana Souza <ana@example.com>")
        history = read_git_history(self.root)
        self.assertTrue(history.available)
        self.assertEqual(history.total_commits, 3)
        self.assertEqual([c.subject for c in history.commits],
                         ["feat: reviewed ai work", "feat: ai work"])
        self.assertEqual([c.human_reviewed for c in history.commits], [True, False])
        self.assertEqual(history.commits[0].author, "Test Human")


if __name__ == "__main__":
    unittest.main()
