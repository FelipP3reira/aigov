"""Provenance signals that a team declares: manifest, file markers, git history.

aigov does not detect AI authorship. It only reads what is declared. The
absence of signals does not prove that AI was not used.
"""

import json
import os
import posixpath
import re
import subprocess
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional, Tuple

from .models import AISystem, Commit, FileDeclaration
from .policy import Policy
from .scanner import Repository, SourceFile

MANIFEST_NAME = ".ai-provenance.json"
MANIFEST_MAX_BYTES = 1_000_000
GIT_TIMEOUT_SECONDS = 30
MAX_COMMITS = 5000

# Names, products and e-mail domains of AI coding assistants. Matching is on
# word boundaries over lower-cased text. A human whose name is one of these
# words (e.g. "Claude") is treated as an AI actor: this errs towards asking
# for more review evidence, never less.
AI_ACTORS = (
    "claude", "anthropic", "copilot", "cursor", "codex", "openai", "chatgpt",
    "gpt", "gemini", "bard", "devin", "aider", "codeium", "windsurf",
    "tabnine", "codewhisperer", "amazon q", "sweep-ai", "continue-dev",
    "cline", "roo-code", "qodo", "openhands", "llm",
)
_AI_ACTOR_RE = re.compile(
    r"(?<![a-z0-9])(" + "|".join(re.escape(a) for a in AI_ACTORS) + r")(?![a-z0-9])"
)

_TRAILER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.+?)\s*$")
_GENERATED_WITH_RE = re.compile(
    r"\bgenerated\s+(?:with|by|using)\s+\[?([^\]\(\r\n]{1,60})", re.IGNORECASE
)
NEGATIVE_VALUES = frozenset({"", "no", "false", "0", "n", "none", "n/a", "na", "off"})

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Header marker tags. The leading "@" is joined at runtime so this module's
# own text is never read as a marker when aigov scans itself.
_TAG_PREFIX = "@"
_MARKER_RE = re.compile(
    r"^\s*(?:#+|//+|/\*+|\*+|<!--|--|;+|%+|rem\s)?\s*"
    + re.escape(_TAG_PREFIX)
    + r"(ai-generated|ai-assisted|model|reviewed-by|reviewed-at)\b\s*:?\s*(.*)$",
    re.IGNORECASE,
)
_COMMENT_TERMINATORS = ("*/", "-->", "#}", "%}", "*)")


def is_ai_actor(text: str) -> Optional[str]:
    """Return the AI actor named in `text`, if any."""
    match = _AI_ACTOR_RE.search((text or "").lower())
    return match.group(1) if match else None


def _strip_email(value: str) -> str:
    return re.sub(r"\s*<[^>]*>", "", value).strip()


# --- Manifest -----------------------------------------------------------------

@dataclass
class Manifest:
    present: bool = False
    ai_systems: List[AISystem] = field(default_factory=list)
    files: List[FileDeclaration] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _clean_str(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalise_path(raw: str) -> Optional[str]:
    if not raw or raw.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", raw):
        return None
    path = posixpath.normpath(raw.replace("\\", "/"))
    if path == "." or path.startswith("../") or path == "..":
        return None
    return path


def _valid_date(value: str) -> bool:
    if not _DATE_RE.match(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def load_manifest(root: str) -> Manifest:
    """Read `.ai-provenance.json`. Invalid entries are dropped and reported."""
    manifest = Manifest()
    path = os.path.join(root, MANIFEST_NAME)
    if os.path.islink(path):
        manifest.present = True
        manifest.errors.append("%s is a symlink and was not followed" % MANIFEST_NAME)
        return manifest
    if not os.path.isfile(path):
        return manifest
    manifest.present = True
    if os.path.getsize(path) > MANIFEST_MAX_BYTES:
        manifest.errors.append("%s is larger than %d bytes" % (MANIFEST_NAME, MANIFEST_MAX_BYTES))
        return manifest
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        manifest.errors.append("%s is not valid JSON (%s)" % (MANIFEST_NAME, exc))
        return manifest
    if not isinstance(data, dict):
        manifest.errors.append("%s must contain a JSON object" % MANIFEST_NAME)
        return manifest

    systems = data.get("ai_systems", [])
    if not isinstance(systems, list):
        manifest.errors.append("ai_systems must be a list")
        systems = []
    for index, entry in enumerate(systems):
        where = "ai_systems[%d]" % index
        if not isinstance(entry, dict):
            manifest.errors.append("%s is not an object; entry dropped" % where)
            continue
        provider = _clean_str(entry.get("provider"))
        if not provider:
            manifest.errors.append("%s has no provider; entry dropped" % where)
            continue
        categories = entry.get("data_categories", [])
        if not isinstance(categories, list) or not all(isinstance(c, str) for c in categories):
            manifest.errors.append("%s.data_categories must be a list of strings; ignored" % where)
            categories = []
        manifest.ai_systems.append(AISystem(
            provider=provider.lower(),
            purpose=_clean_str(entry.get("purpose")),
            owner=_clean_str(entry.get("owner")),
            data_categories=[c.strip() for c in categories if c.strip()],
        ))

    files = data.get("files", [])
    if not isinstance(files, list):
        manifest.errors.append("files must be a list")
        files = []
    for index, entry in enumerate(files):
        where = "files[%d]" % index
        if not isinstance(entry, dict):
            manifest.errors.append("%s is not an object; entry dropped" % where)
            continue
        path = _normalise_path(_clean_str(entry.get("path")))
        if path is None:
            manifest.errors.append("%s has a missing or unsafe path; entry dropped" % where)
            continue
        tool = _clean_str(entry.get("tool"))
        if not tool:
            manifest.errors.append("%s (%s) has no tool; entry dropped" % (where, path))
            continue
        reviewed_at = _clean_str(entry.get("reviewed_at"))
        if reviewed_at and not _valid_date(reviewed_at):
            manifest.errors.append(
                "%s (%s) has reviewed_at that is not a YYYY-MM-DD date; entry dropped" % (where, path)
            )
            continue
        for key in ("model", "reviewed_by"):
            if key in entry and not isinstance(entry[key], str):
                manifest.errors.append("%s (%s).%s must be a string; ignored" % (where, path, key))
        manifest.files.append(FileDeclaration(
            path=path,
            tool=tool,
            model=_clean_str(entry.get("model")),
            reviewed_by=_clean_str(entry.get("reviewed_by")),
            reviewed_at=reviewed_at,
            kind="generated",
            sources=["manifest"],
        ))
    return manifest


# --- File markers ---------------------------------------------------------------

def _clean_marker_value(value: str) -> str:
    value = value.strip()
    changed = True
    while changed:
        changed = False
        for terminator in _COMMENT_TERMINATORS:
            if value.endswith(terminator):
                value = value[: -len(terminator)].rstrip()
                changed = True
    return value


def parse_markers(source: SourceFile) -> Optional[FileDeclaration]:
    """Read provenance markers from the first 40 lines of a code file."""
    if not source.accepts_markers:
        return None
    values: Dict[str, str] = {}
    for line in source.header:
        match = _MARKER_RE.match(line)
        if match:
            tag = match.group(1).lower()
            values.setdefault(tag, _clean_marker_value(match.group(2)))
    if "ai-generated" in values:
        kind, tool = "generated", values["ai-generated"]
    elif "ai-assisted" in values:
        kind, tool = "assisted", values["ai-assisted"]
    else:
        return None
    return FileDeclaration(
        path=source.rel,
        tool=tool or "unspecified",
        model=values.get("model", ""),
        reviewed_by=values.get("reviewed-by", ""),
        reviewed_at=values.get("reviewed-at", ""),
        kind=kind,
        sources=["marker"],
    )


def collect_declarations(repo: Repository, manifest: Manifest) -> Dict[str, FileDeclaration]:
    """Merge manifest entries and file markers into one record per path.
    When both exist, manifest values win and empty fields are filled in from
    the marker."""
    merged: Dict[str, FileDeclaration] = {}
    for declaration in manifest.files:
        merged[declaration.path] = declaration
    for source in repo.files:
        marker = parse_markers(source)
        if marker is None:
            continue
        existing = merged.get(marker.path)
        if existing is None:
            merged[marker.path] = marker
            continue
        for attr in ("model", "reviewed_by", "reviewed_at"):
            if not getattr(existing, attr):
                setattr(existing, attr, getattr(marker, attr))
        if "marker" not in existing.sources:
            existing.sources.append("marker")
    return dict(sorted(merged.items()))


# --- Git history ------------------------------------------------------------------

@dataclass
class GitHistory:
    available: bool
    reason: str = ""
    total_commits: int = 0
    commits: List[Commit] = field(default_factory=list)  # AI-assisted only
    truncated: bool = False


def parse_trailers(message: str) -> List[Tuple[str, str]]:
    """Trailer-shaped lines (`Key: value`) after the subject line.
    Simplification: any such line in the body counts, not only the last
    paragraph as git itself defines trailers."""
    trailers = []
    for line in message.splitlines()[1:]:
        match = _TRAILER_RE.match(line.strip())
        if match:
            trailers.append((match.group(1).lower(), match.group(2)))
    return trailers


def analyse_commit(sha: str, author_name: str, author_email: str, when: str,
                   message: str, policy: Optional[Policy] = None) -> Commit:
    message = message.strip("\n")
    subject = message.splitlines()[0].strip() if message else ""
    commit = Commit(sha=sha, author=author_name.strip(), date=when, subject=subject[:200])

    for key, value in parse_trailers(message):
        if key == "co-authored-by":
            actor = is_ai_actor(value)
            if actor:
                commit.ai_signals.append("Co-authored-by: %s" % (_strip_email(value) or actor))
        elif key in ("ai-assisted", "assisted-by"):
            if value.strip().lower() not in NEGATIVE_VALUES:
                label = "AI-Assisted" if key == "ai-assisted" else "Assisted-by"
                commit.ai_signals.append("%s: %s" % (label, _strip_email(value)[:60]))
        elif key == "reviewed-by":
            name = _strip_email(value) or "unnamed reviewer"
            if is_ai_actor(value):
                commit.ai_reviewers.append(name)
            else:
                commit.reviewers.append(name)

    for match in _GENERATED_WITH_RE.finditer(message):
        tool = match.group(1).strip()
        if is_ai_actor(tool):
            commit.ai_signals.append("Generated with %s" % tool)
            break

    if is_ai_actor(author_name + " " + author_email):
        commit.ai_signals.append("AI author: %s" % (author_name.strip() or "unnamed"))

    if policy is not None:
        for pattern in policy.compiled_commit_patterns:
            if pattern.search(message):
                commit.ai_signals.append("Policy pattern: %s" % pattern.pattern)
    return commit


def _git(root: str, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    # Hardening: no fsmonitor hook, no pager, no signature verification
    # (which could run a configured gpg program), no textconv/external diff.
    command = [
        "git", "-c", "core.fsmonitor=false", "-c", "core.pager=cat",
        "-c", "log.showSignature=false", "--no-pager",
    ] + list(args)
    return subprocess.run(
        command, cwd=root, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=GIT_TIMEOUT_SECONDS, check=False,
    )


def read_git_history(root: str, policy: Optional[Policy] = None,
                     max_commits: int = MAX_COMMITS) -> GitHistory:
    try:
        probe = _git(root, "rev-parse", "--is-inside-work-tree", "--show-prefix")
    except FileNotFoundError:
        return GitHistory(available=False, reason="git executable not found")
    except subprocess.TimeoutExpired:
        return GitHistory(available=False, reason="git timed out after %d s" % GIT_TIMEOUT_SECONDS)
    lines = probe.stdout.decode("utf-8", errors="replace").splitlines()
    if probe.returncode != 0 or not lines or lines[0].strip() != "true":
        return GitHistory(available=False, reason="not a git repository")
    # At the repository root every commit counts (including empty ones); in a
    # subdirectory only commits touching it do.
    prefix = lines[1].strip() if len(lines) > 1 else ""
    pathspec = ["--", "."] if prefix else []

    try:
        result = _git(
            root, "log", "--no-color", "--no-textconv", "--no-ext-diff",
            "--max-count=%d" % (max_commits + 1),
            "--format=%x1e%H%x1f%an%x1f%ae%x1f%aI%x1f%B", *pathspec,
        )
    except subprocess.TimeoutExpired:
        return GitHistory(available=False, reason="git log timed out after %d s" % GIT_TIMEOUT_SECONDS)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        if "does not have any commits" in stderr:
            return GitHistory(available=True, reason="repository has no commits")
        return GitHistory(available=False, reason="git log failed")

    history = GitHistory(available=True)
    records = [r for r in result.stdout.decode("utf-8", errors="replace").split("\x1e") if r.strip()]
    if len(records) > max_commits:
        history.truncated = True
        records = records[:max_commits]
    history.total_commits = len(records)
    for record in records:
        parts = record.split("\x1f", 4)
        if len(parts) != 5:
            continue
        sha, name, email, when, body = parts
        commit = analyse_commit(sha.strip(), name, email, when.strip(), body, policy)
        if commit.ai_assisted:
            history.commits.append(commit)
    return history
