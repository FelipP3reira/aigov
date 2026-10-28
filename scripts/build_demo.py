"""Build the demo reports in docs/demo/.

Copies each example to a temporary directory, gives it a small git history
with an AI co-authored commit (reviewed in `remediated`, not reviewed in
`needs-remediation`), scans it and writes HTML and JSON reports plus a
side-by-side comparison page.

Usage: python scripts/build_demo.py [--out DIR]
"""

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from html import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from aigov.engine import run_scan  # noqa: E402
from aigov.policy import load_policy  # noqa: E402
from aigov.report import render_html  # noqa: E402

EXAMPLES = ("needs-remediation", "remediated")
HUMAN = ("Ana Souza", "ana.souza@example.com")
REVIEWER = "Bruno Lima <bruno.lima@example.com>"
AI_CO_AUTHOR = "Claude <noreply@anthropic.com>"


def remove_tree(path):
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


def git(root, *args, date=None):
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": HUMAN[0], "GIT_AUTHOR_EMAIL": HUMAN[1],
        "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
    })
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main",
         "-c", "core.autocrlf=false"] + list(args),
        cwd=root, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def make_history(root, reviewed):
    """Initial human commit, then one AI co-authored commit."""
    git(root, "init", "-q")
    changelog = os.path.join(root, "CHANGELOG.md")
    with open(changelog, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Changelog\n\n- Initial import.\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "chore: initial import", date="2026-10-01T09:00:00+00:00")

    with open(changelog, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("- Summarise tickets with an LLM.\n")
    trailers = "Co-authored-by: %s" % AI_CO_AUTHOR
    if reviewed:
        trailers += "\nReviewed-by: %s" % REVIEWER
    git(root, "commit", "-q", "-am",
        "feat: summarise support tickets with an LLM\n\n" + trailers,
        date="2026-10-15T14:30:00+00:00")


def scan_example(name, workdir, with_git=True):
    target = os.path.join(workdir, name)
    shutil.copytree(os.path.join(ROOT, "examples", name), target)
    if with_git and shutil.which("git"):
        make_history(target, reviewed=(name == "remediated"))
    return run_scan(target, load_policy(root=target))


INDEX = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aigov demo: side by side</title>
<style>
:root { --bg: #F5F7F8; --ink: #14202B; --muted: #4D5B68; --line: #D8DEE3; }
@media (prefers-color-scheme: dark) { :root { --bg: #0F161D; --ink: #E6ECF1; --muted: #9AA8B5; --line: #2A3743; } }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
header { padding: 20px 24px 8px; }
h1 { font-size: 1.3rem; margin: 0 0 4px; }
p { margin: 0; color: var(--muted); }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px 24px 24px; }
figure { margin: 0; }
figcaption { font-weight: 600; margin-bottom: 6px; }
figcaption a { color: inherit; }
iframe { width: 100%%; height: 82vh; border: 1px solid var(--line); border-radius: 6px; background: #fff; }
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <h1>aigov demo: the same app before and after remediation</h1>
  <p>Heuristic scorecard, not legal advice and not a certification.</p>
</header>
<div class="grid">%s</div>
</body>
</html>
"""


def write_outputs(results, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    frames = []
    for name, result in results:
        with open(os.path.join(out_dir, name + ".html"), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(render_html(result))
        with open(os.path.join(out_dir, name + ".json"), "w", encoding="utf-8", newline="\n") as handle:
            json.dump(result.to_dict(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        frames.append(
            '<figure><figcaption><a href="%s.html">%s</a>: %s (score %s)</figcaption>'
            '<iframe src="%s.html" title="%s report"></iframe></figure>' % (
                name, escape(name), escape(result.verdict),
                "n/a" if result.score is None else "%g" % result.score, name, escape(name))
        )
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(INDEX % "".join(frames))


def build(out_dir):
    workdir = tempfile.mkdtemp(prefix="aigov-demo-")
    try:
        results = [(name, scan_example(name, workdir)) for name in EXAMPLES]
    finally:
        remove_tree(workdir)
    write_outputs(results, out_dir)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build the aigov demo reports.")
    parser.add_argument("--out", default=os.path.join(ROOT, "docs", "demo"),
                        help="output directory (default: docs/demo)")
    args = parser.parse_args(argv)
    for name, result in build(args.out):
        print("%-18s score %-5s %-8s gate %s" % (
            name, result.score, result.verdict, "passed" if result.gate_passed else "failed"))
    print("Wrote reports to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
