"""Command-line interface: `python -m aigov scan [PATH] ...`."""

import argparse
import json
import os
import re
import sys
from typing import List, Optional

from . import __version__
from .engine import DISCLAIMER, ScanResult, run_scan
from .policy import PolicyError, load_policy

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_USAGE = 2

DEFAULT_HTML = "aigov-report.html"
STATUS_LABELS = {"pass": "[PASS]", "warn": "[WARN]", "fail": "[FAIL]", "na": "[N/A] "}
MAX_FINDINGS_SHOWN = 3

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(text) -> str:
    """Strip control characters so repository text cannot drive the terminal."""
    return _CONTROL_CHARS.sub("?", str(text))


class UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="aigov",
        description="Heuristic governance scorecard for AI-assisted code. "
                    "Not legal advice and not a compliance certification.",
    )
    parser.add_argument("--version", action="version", version="aigov " + __version__)
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_Parser)
    scan = commands.add_parser("scan", help="scan a repository and write reports")
    scan.add_argument("path", nargs="?", default=".", metavar="PATH",
                      help="repository to scan (default: current directory)")
    scan.add_argument("--policy", metavar="FILE",
                      help="policy file (default: PATH/aigov.policy.json if present)")
    html = scan.add_mutually_exclusive_group()
    html.add_argument("--html", metavar="FILE",
                      help="HTML report path (default: ./%s)" % DEFAULT_HTML)
    html.add_argument("--no-html", action="store_true", help="do not write an HTML report")
    scan.add_argument("--json", metavar="FILE", help="also write a JSON report")
    scan.add_argument("--fail-under", type=float, metavar="N",
                      help="minimum score for the gate (overrides min_score)")
    scan.add_argument("--quiet", action="store_true", help="print only the final summary line")
    return parser


def _format_score(score: Optional[float]) -> str:
    return "n/a" if score is None else "%g/100" % score


def print_summary(result: ScanResult, quiet: bool, out) -> None:
    gate = "passed" if result.gate_passed else "FAILED"
    final = "Score %s | %s | gate %s" % (_format_score(result.score), result.verdict, gate)
    if quiet:
        print(final, file=out)
        return
    print("aigov %s scan of %s" % (__version__, clean(result.target)), file=out)
    print("", file=out)
    current = None
    for control in result.controls:
        if control.function != current:
            current = control.function
            score = result.function_scores.get(current)
            print("%s (%s)" % (current, _format_score(score)), file=out)
        print("  %s %s %s: %s" % (STATUS_LABELS[control.status], control.id, control.title,
                                  clean(control.summary)), file=out)
        shown = [f for f in control.findings if f.severity != "info"][:MAX_FINDINGS_SHOWN]
        for finding in shown:
            where = ""
            if finding.file:
                where = " (%s%s)" % (clean(finding.file), ":%d" % finding.line if finding.line else "")
            evidence = " [%s]" % clean(finding.evidence) if finding.evidence else ""
            print("         - %s: %s%s%s" % (finding.severity, clean(finding.message), where, evidence),
                  file=out)
        hidden = len([f for f in control.findings if f.severity != "info"]) - len(shown)
        if hidden > 0:
            print("         - ... and %d more" % hidden, file=out)
    print("", file=out)
    if result.suppressions:
        print("%d finding(s) suppressed by aigov directives (listed in the reports)."
              % len(result.suppressions), file=out)
    print(clean(result.headline), file=out)
    for reason in result.gate_reasons:
        print("Gate: %s" % reason, file=out)
    print(final, file=out)
    print("", file=out)
    print(DISCLAIMER, file=out)


def _write(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def cmd_scan(args, out, err) -> int:
    if not os.path.isdir(args.path):
        raise UsageError("not a directory: %s" % args.path)
    if args.fail_under is not None and not 0 <= args.fail_under <= 100:
        raise UsageError("--fail-under must be between 0 and 100")
    policy = load_policy(args.policy, root=args.path)
    result = run_scan(args.path, policy, fail_under=args.fail_under)

    written = []
    if args.json:
        _write(args.json, json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n")
        written.append(args.json)
    if not args.no_html:
        from .report import render_html

        html_path = args.html or DEFAULT_HTML
        _write(html_path, render_html(result))
        written.append(html_path)

    print_summary(result, args.quiet, out)
    if not args.quiet:
        for path in written:
            print("Wrote %s" % path, file=out)
    return EXIT_OK if result.gate_passed else EXIT_GATE_FAILED


def main(argv: Optional[List[str]] = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    for stream in (out, err):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command != "scan":
            raise UsageError("missing command (try: aigov scan PATH)")
        return cmd_scan(args, out, err)
    except UsageError as exc:
        print("aigov: error: %s" % exc, file=err)
        print(parser.format_usage().rstrip(), file=err)
        return EXIT_USAGE
    except PolicyError as exc:
        print("aigov: policy error: %s" % exc, file=err)
        return EXIT_USAGE
    except OSError as exc:
        print("aigov: error: %s" % exc, file=err)
        return EXIT_USAGE
