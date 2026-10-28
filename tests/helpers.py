"""Shared helpers for tests.

Strings that look like secrets, CPFs or provenance markers are assembled at
runtime so this repository can pass its own scan.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

AT = "@"
GIT = shutil.which("git")


def remove_tree(path: str) -> None:
    """rmtree that also removes read-only files (git objects on Windows)."""
    def retry(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry)
    else:
        shutil.rmtree(path, onerror=retry)


def marker(tag: str, value: str, leader: str = "#") -> str:
    return "%s %s%s: %s" % (leader, AT, tag, value)


class TempRepoCase(unittest.TestCase):
    """Creates an empty temporary directory per test."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="aigov-test-")
        self.addCleanup(remove_tree, self.root)

    def write(self, rel: str, content="", binary: bool = False) -> str:
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if binary else "w"
        kwargs = {} if binary else {"encoding": "utf-8", "newline": "\n"}
        with open(path, mode, **kwargs) as handle:
            handle.write(content)
        return path

    def git(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env.update({
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        })
        return subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test Human",
             "-c", "user.email=human@example.com", "-c", "init.defaultBranch=main"]
            + list(args),
            cwd=self.root, env=env, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def commit(self, message: str, author: str = None) -> None:
        self.git("add", "-A")
        args = ["commit", "--allow-empty", "-q", "-m", message]
        if author:
            args += ["--author", author]
        self.git(*args)
