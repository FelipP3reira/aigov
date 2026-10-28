"""Read-only repository walker.

The scanner only reads bytes. It never imports, executes or follows symlinks
into anything in the analysed repository.
"""

import os
import re
from fnmatch import fnmatchcase
from typing import Dict, List, Optional, Tuple

from .policy import Policy

SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "venv", ".venv", "dist", "build",
    "__pycache__", ".hg", ".svn", ".tox", ".mypy_cache", ".pytest_cache",
})
MAX_FILES = 50_000
BINARY_SNIFF_BYTES = 8192
HEADER_LINES = 40

CODE_EXTENSIONS = frozenset({
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue",
    ".svelte", ".java", ".kt", ".kts", ".scala", ".groovy", ".go", ".rs",
    ".rb", ".php", ".cs", ".fs", ".vb", ".c", ".h", ".cc", ".cpp", ".cxx",
    ".hpp", ".m", ".mm", ".swift", ".dart", ".lua", ".pl", ".pm", ".r",
    ".jl", ".ex", ".exs", ".erl", ".clj", ".hs", ".ml", ".sh", ".bash",
    ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".sql",
})
# Provenance markers are honoured in code and in markup that has comments.
MARKER_EXTENSIONS = CODE_EXTENSIONS | frozenset({".html", ".htm", ".css", ".scss", ".less"})

TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "specs", "testing", "e2e"})
FIXTURE_DIRS = frozenset({
    "fixtures", "fixture", "__fixtures__", "testdata", "test_data", "test-data",
    "mocks", "__mocks__",
})
_TEST_NAME = re.compile(
    r"(^test_.*\.py$|.*_test\.(py|go|rb|exs)$|.*\.(test|spec)\.[cm]?[jt]sx?$"
    r"|.*(Test|Tests|Spec)\.(java|kt|cs|scala|swift|php)$|.*_spec\.rb$)"
)

ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".tpl")

# Directive tokens are assembled at runtime so that this module does not
# suppress findings in itself when aigov scans its own source tree.
IGNORE_TOKEN = "aigov:" + "ignore"
_LINE_DIRECTIVE = re.compile(re.escape(IGNORE_TOKEN) + r"(?![-\w])")
_FILE_DIRECTIVE = re.compile(re.escape(IGNORE_TOKEN + "-file") + r"(?![-\w])")

COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--", ";", "rem ", "REM ")


def is_comment_line(line: str) -> bool:
    """Best-effort: does the line start with a common comment leader?"""
    stripped = line.lstrip()
    if not stripped:
        return False
    if stripped.startswith("#!") or stripped.startswith("#include"):
        return False
    return stripped.startswith(COMMENT_PREFIXES)


def is_env_file(name: str) -> bool:
    lower = name.lower()
    if lower.endswith(ENV_TEMPLATE_SUFFIXES):
        return False
    return lower == ".env" or lower.startswith(".env.") or lower.endswith(".env")


def _matches_any(rel: str, globs: List[str]) -> bool:
    for pattern in globs:
        pattern = pattern.strip().rstrip("/")
        if pattern and (fnmatchcase(rel, pattern) or fnmatchcase(rel, pattern + "/*")):
            return True
    return False


class SourceFile:
    """A scanned text file. Paths are POSIX-style and relative to the root."""

    def __init__(self, root: str, rel: str, size: int, data: bytes):
        self.root = root
        self.rel = rel
        self.size = size
        self.name = rel.rsplit("/", 1)[-1]
        self.ext = os.path.splitext(self.name)[1].lower()
        self.text = data.decode("utf-8", errors="replace")
        self.lines = self.text.splitlines()
        parts = [p.lower() for p in rel.split("/")[:-1]]
        self.is_code = self.ext in CODE_EXTENSIONS
        self.is_test = bool(TEST_DIRS.intersection(parts)) or bool(_TEST_NAME.match(self.name))
        self.is_fixture = self.is_test or bool(FIXTURE_DIRS.intersection(parts))
        self.accepts_markers = self.ext in MARKER_EXTENSIONS
        self.file_directive_line = self._find_file_directive()

    @property
    def header(self) -> List[str]:
        return self.lines[:HEADER_LINES]

    def _find_file_directive(self) -> Optional[int]:
        for index, line in enumerate(self.header, start=1):
            if _FILE_DIRECTIVE.search(line):
                return index
        return None

    def suppression(self, line: Optional[int]) -> Optional[Tuple[str, Optional[int]]]:
        """Return (scope, directive line) if a finding at `line` is suppressed."""
        if self.file_directive_line is not None:
            return ("file", self.file_directive_line)
        if line is not None and 1 <= line <= len(self.lines):
            if _LINE_DIRECTIVE.search(self.lines[line - 1]):
                return ("line", line)
        return None


class GitIgnore:
    """A small subset of .gitignore semantics, enough to decide whether an
    env file is excluded from version control. Unsupported constructs are
    treated as non-matching, which errs towards reporting the file."""

    def __init__(self, root: str):
        self.root = root
        self._cache: Dict[str, List[Tuple[bool, bool, str]]] = {}

    def _rules(self, rel_dir: str) -> List[Tuple[bool, bool, str]]:
        if rel_dir not in self._cache:
            rules = []
            path = os.path.join(self.root, *rel_dir.split("/"), ".gitignore") if rel_dir \
                else os.path.join(self.root, ".gitignore")
            if os.path.isfile(path) and not os.path.islink(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        for raw in handle:
                            line = raw.rstrip("\n\r")
                            if not line.strip() or line.startswith("#"):
                                continue
                            negate = line.startswith("!")
                            if negate:
                                line = line[1:]
                            line = line.rstrip()
                            dir_only = line.endswith("/")
                            rules.append((negate, dir_only, line.rstrip("/")))
                except OSError:
                    pass
            self._cache[rel_dir] = rules
        return self._cache[rel_dir]

    @staticmethod
    def _rule_matches(pattern: str, dir_only: bool, rel: str, is_dir: bool) -> bool:
        if dir_only and not is_dir:
            return False
        if "/" in pattern:
            anchored = pattern.lstrip("/")
            if anchored.startswith("**/"):
                tail = anchored[3:]
                return fnmatchcase(rel, tail) or fnmatchcase(rel, "*/" + tail)
            return fnmatchcase(rel, anchored)
        return fnmatchcase(rel.rsplit("/", 1)[-1], pattern)

    def is_ignored(self, rel: str) -> bool:
        parts = rel.split("/")
        # A file inside an ignored directory is ignored.
        for depth in range(1, len(parts)):
            if self._check("/".join(parts[:depth]), is_dir=True):
                return True
        return self._check(rel, is_dir=False)

    def _check(self, rel: str, is_dir: bool) -> bool:
        parts = rel.split("/")
        ignored = False
        for depth in range(len(parts)):
            base = "/".join(parts[:depth])
            sub = "/".join(parts[depth:])
            for negate, dir_only, pattern in self._rules(base):
                if self._rule_matches(pattern, dir_only, sub, is_dir):
                    ignored = not negate
        return ignored


class Repository:
    """Result of walking a directory tree."""

    def __init__(self, root: str, policy: Optional[Policy] = None):
        self.root = os.path.abspath(root)
        self.policy = policy or Policy()
        self.files: List[SourceFile] = []
        self.skipped: List[Tuple[str, str]] = []  # (rel path, reason)
        self.env_files: List[Tuple[str, bool]] = []  # (rel path, gitignored)
        self.ignored_by_policy = 0
        self.truncated = False
        self.gitignore = GitIgnore(self.root)
        self._by_path: Dict[str, SourceFile] = {}

    def get(self, rel: str) -> Optional[SourceFile]:
        return self._by_path.get(rel)

    def path_exists(self, rel: str) -> bool:
        """Does `rel` name a regular file inside the root (scanned or not)?"""
        if not rel or rel.startswith("/") or "\\" in rel or ".." in rel.split("/"):
            return False
        full = os.path.join(self.root, *rel.split("/"))
        return os.path.isfile(full) and not os.path.islink(full)

    def find(self, *candidates: str) -> List[SourceFile]:
        """Scanned files whose relative path matches any candidate (case-insensitive)."""
        wanted = {c.lower() for c in candidates}
        return [f for f in self.files if f.rel.lower() in wanted]

    def walk(self) -> "Repository":
        if not os.path.isdir(self.root):
            raise NotADirectoryError("not a directory: %s" % self.root)
        self._walk_dir(self.root, "")
        self.files.sort(key=lambda f: f.rel)
        return self

    def _walk_dir(self, abs_dir: str, rel_dir: str) -> None:
        try:
            entries = sorted(os.scandir(abs_dir), key=lambda e: e.name)
        except OSError as exc:
            self.skipped.append((rel_dir or ".", "unreadable directory (%s)" % exc.strerror))
            return
        for entry in entries:
            rel = rel_dir + "/" + entry.name if rel_dir else entry.name
            is_junction = getattr(entry, "is_junction", lambda: False)()
            if entry.is_symlink() or is_junction:
                self.skipped.append((rel, "symlink not followed"))
                continue
            if _matches_any(rel, self.policy.ignore):
                self.ignored_by_policy += 1
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in SKIP_DIRS:
                        continue
                    self._walk_dir(entry.path, rel)
                elif entry.is_file(follow_symlinks=False):
                    self._add_file(entry, rel)
            except OSError as exc:
                self.skipped.append((rel, "unreadable (%s)" % exc.strerror))

    def _add_file(self, entry: os.DirEntry, rel: str) -> None:
        if len(self.files) >= MAX_FILES:
            self.truncated = True
            return
        if is_env_file(entry.name):
            ignored = self.gitignore.is_ignored(rel)
            self.env_files.append((rel, ignored))
            if ignored:
                self.skipped.append((rel, "env file ignored by .gitignore (not scanned)"))
                return
        size = entry.stat(follow_symlinks=False).st_size
        if size > self.policy.max_file_bytes:
            self.skipped.append((rel, "larger than %d bytes" % self.policy.max_file_bytes))
            return
        with open(entry.path, "rb") as handle:
            data = handle.read(self.policy.max_file_bytes + 1)
        if b"\x00" in data[:BINARY_SNIFF_BYTES]:
            self.skipped.append((rel, "binary"))
            return
        source = SourceFile(self.root, rel, size, data)
        self.files.append(source)
        self._by_path[rel] = source


def scan_repository(root: str, policy: Optional[Policy] = None) -> Repository:
    return Repository(root, policy).walk()
