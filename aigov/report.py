"""Self-contained HTML report.

Every string that can come from the scanned repository (paths, commit
subjects, author names, summaries that embed paths) goes through `esc`.
The page loads nothing external, and a Content-Security-Policy pins the
inline style and script by hash, so an escaping mistake still cannot run
injected script.
"""

import base64
import hashlib
from html import escape
from typing import Iterable, List, Optional

from . import __version__
from .engine import DISCLAIMER, LIMITATIONS, ScanResult
from .models import FUNCTIONS, ControlResult
from .scanner import IGNORE_TOKEN

STATUS_WORDS = {"pass": "Pass", "warn": "Warn", "fail": "Fail", "na": "N/A"}
STATUS_ICONS = {"pass": "✓", "warn": "!", "fail": "✕", "na": "–"}
SEVERITY_CLASS = {"critical": "fail", "high": "fail", "medium": "warn", "low": "warn", "info": "na"}
FUNCTION_BLURBS = {
    "Govern": "Policy, ownership and process",
    "Map": "Where AI is used, by whom, on what data",
    "Measure": "Secrets, risky patterns and tests",
    "Manage": "Review evidence, CI, dependencies, incidents",
}
VERDICT_STATUS = {"Aligned": "pass", "Partial": "warn", "Gaps": "fail", "Blocked": "fail"}

CSS = """
:root {
  --bg: #F5F7F8; --surface: #FFFFFF; --ink: #14202B; --muted: #4D5B68; --line: #D8DEE3;
  --accent: #2F5D8A; --focus: #2F5D8A;
  --pass: #2E7D5B; --warn: #B7791F; --fail: #B3261E; --na: #8A97A3;
  --pass-ink: #2E7D5B; --warn-ink: #85560F; --fail-ink: #B3261E; --na-ink: #5B6772;
  --on-pass: #FFFFFF; --on-warn: #14202B; --on-fail: #FFFFFF; --on-na: #14202B;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0F161D; --surface: #16202A; --ink: #E6ECF1; --muted: #9AA8B5; --line: #2A3743;
    --accent: #8DB4DB; --focus: #8DB4DB;
    --pass-ink: #6CC49A; --warn-ink: #E3AE55; --fail-ink: #F08A80; --na-ink: #A3AFBA;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
@media (prefers-reduced-motion: no-preference) { html { scroll-behavior: smooth; } }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
.page { max-width: 1080px; margin: 0 auto; padding: 40px 24px 64px; }
a { color: var(--accent); }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; border-radius: 2px; }
code, .mono { font-family: var(--mono); font-size: 0.875em; overflow-wrap: anywhere; }
h2 { font-size: 1.35rem; margin: 56px 0 6px; letter-spacing: -0.01em; }
h3 { font-size: 1.05rem; margin: 32px 0 10px; }
.lede { color: var(--muted); margin: 0 0 20px; max-width: 70ch; }
.meta { color: var(--muted); font-size: 0.9rem; margin: 0 0 18px; }

/* Hero */
.hero h1 { font-size: clamp(1.7rem, 4vw, 2.6rem); line-height: 1.15; margin: 0 0 16px;
  letter-spacing: -0.02em; max-width: 24ch; font-weight: 650; }
.facts { display: flex; flex-wrap: wrap; gap: 8px 28px; margin: 0 0 32px; padding: 0; list-style: none; }
.facts li { color: var(--muted); }
.facts strong { color: var(--ink); font-weight: 600; }
.score-num { font-variant-numeric: tabular-nums; }

/* Status label: icon + word, never colour alone */
.st { display: inline-flex; align-items: center; gap: 6px; font-weight: 600; white-space: nowrap; }
.st .ic { display: inline-grid; place-items: center; width: 1.25em; height: 1.25em; border-radius: 50%;
  font-size: 0.8em; line-height: 1; color: var(--surface); }
.st.pass { color: var(--pass-ink); } .st.pass .ic { background: var(--pass-ink); }
.st.warn { color: var(--warn-ink); } .st.warn .ic { background: var(--warn-ink); }
.st.fail { color: var(--fail-ink); } .st.fail .ic { background: var(--fail-ink); }
.st.na { color: var(--na-ink); } .st.na .ic { background: var(--na-ink); }

/* The strip */
.strip { display: flex; gap: 14px; margin: 0; }
.strip-group { min-width: 0; }
.strip-group h2 { font-size: 0.9rem; font-weight: 600; margin: 0 0 6px; color: var(--muted);
  display: flex; justify-content: space-between; gap: 8px; letter-spacing: 0; }
.strip-group h2 span { font-variant-numeric: tabular-nums; }
.cells { display: flex; gap: 3px; }
.cell { flex: 1 1 0; min-width: 0; height: 76px; padding: 8px 8px 7px; display: flex; flex-direction: column;
  justify-content: space-between; text-decoration: none; border-radius: 3px; }
.cells .cell:first-child { border-radius: 6px 3px 3px 6px; }
.cells .cell:last-child { border-radius: 3px 6px 6px 3px; }
.cell .ic { font-size: 1.05rem; font-weight: 700; line-height: 1; }
.cell .id { font-family: var(--mono); font-size: 0.72rem; white-space: nowrap; overflow: hidden; }
.cell .word { font-size: 0.72rem; font-weight: 600; }
.cell.pass { background: var(--pass); color: var(--on-pass); }
.cell.warn { background: var(--warn); color: var(--on-warn); }
.cell.fail { background: var(--fail); color: var(--on-fail); }
.cell.na { background: transparent; color: var(--na-ink); border: 1.5px dashed var(--na); }
@media (prefers-reduced-motion: no-preference) {
  .cell { transition: transform 120ms ease; }
  .cell:hover { transform: translateY(-2px); }
}
.legend { display: flex; flex-wrap: wrap; gap: 6px 20px; margin: 14px 0 0; padding: 0; list-style: none;
  font-size: 0.85rem; }

/* Function summary */
table { width: 100%; border-collapse: collapse; background: var(--surface); font-size: 0.92rem; }
th, td { text-align: left; vertical-align: top; padding: 9px 12px; border-bottom: 1px solid var(--line); }
th { font-weight: 600; color: var(--muted); font-size: 0.85rem; }
tbody tr:last-child td { border-bottom: 0; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 6px; }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.fn-name { font-weight: 600; }
.fn-blurb { display: block; color: var(--muted); font-size: 0.85rem; }

/* Controls */
details.control { background: var(--surface); border: 1px solid var(--line); border-left-width: 4px;
  border-radius: 6px; margin: 0 0 10px; }
details.control.pass { border-left-color: var(--pass); }
details.control.warn { border-left-color: var(--warn); }
details.control.fail { border-left-color: var(--fail); }
details.control.na { border-left-color: var(--na); border-left-style: dashed; }
details.control > summary { cursor: pointer; padding: 14px 16px; list-style: none;
  display: grid; grid-template-columns: 5.5rem 1fr auto; gap: 4px 16px; align-items: baseline; }
details.control > summary::-webkit-details-marker { display: none; }
.c-title { font-weight: 600; }
.c-title .mono { color: var(--muted); font-weight: 400; margin-right: 6px; }
.c-weight { color: var(--muted); font-size: 0.85rem; white-space: nowrap; }
.c-weight::after { content: " \\25B8"; }
details[open] .c-weight::after { content: " \\25BE"; }
.c-summary { grid-column: 2 / 4; color: var(--muted); font-size: 0.93rem; }
.c-body { padding: 4px 16px 18px; border-top: 1px solid var(--line); }
.c-body h4 { font-size: 0.9rem; margin: 18px 0 6px; }
.c-body p { margin: 0; max-width: 75ch; }
.c-body .table-wrap { margin-top: 4px; }
.refs { color: var(--muted); font-size: 0.85rem; margin-top: 14px !important; }
.sev { font-weight: 600; white-space: nowrap; }
.sev.fail { color: var(--fail-ink); } .sev.warn { color: var(--warn-ink); } .sev.na { color: var(--na-ink); }
.empty { color: var(--muted); font-style: italic; margin: 6px 0 0; }

/* Notice */
.notice { border: 1px solid var(--line); border-left: 4px solid var(--accent); background: var(--surface);
  padding: 16px 18px; border-radius: 6px; max-width: 80ch; }
.limits { padding-left: 1.2em; max-width: 80ch; }
.limits li { margin-bottom: 6px; }
footer { margin-top: 56px; color: var(--muted); font-size: 0.85rem; }

@media (max-width: 760px) {
  .page { padding: 28px 16px 48px; }
  .strip { flex-wrap: wrap; }
  .strip-group { flex: 1 1 calc(50% - 7px) !important; }
}
@media (max-width: 480px) {
  .strip-group { flex-basis: 100% !important; }
  details.control > summary { grid-template-columns: 1fr auto; }
  .c-summary { grid-column: 1 / 3; }
}
@media print {
  :root { --bg: #FFFFFF; --surface: #FFFFFF; }
  body { font-size: 11pt; }
  .page { max-width: none; padding: 0; }
  .cell { height: 54px; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .st .ic, .cell { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  details.control { break-inside: avoid; }
  .c-weight::after { content: ""; }
  a { color: inherit; text-decoration: none; }
  h2 { break-after: avoid; }
}
"""

SCRIPT = """
(function () {
  function openFromHash(hash) {
    if (!hash || hash.indexOf('#ctl-') !== 0) return;
    var el = document.getElementById(hash.slice(1));
    if (el && el.tagName === 'DETAILS') el.open = true;
  }
  document.addEventListener('click', function (e) {
    var a = e.target.closest ? e.target.closest('a[href^="#ctl-"]') : null;
    if (a) openFromHash(a.getAttribute('href'));
  });
  window.addEventListener('hashchange', function () { openFromHash(location.hash); });
  window.addEventListener('beforeprint', function () {
    document.querySelectorAll('details').forEach(function (d) { d.open = true; });
  });
  openFromHash(location.hash);
})();
"""


def esc(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-%s'" % base64.b64encode(digest).decode("ascii")


def status_label(status: str, word: Optional[str] = None) -> str:
    """Icon plus word. `word` must already be safe HTML."""
    return '<span class="st %s"><span class="ic" aria-hidden="true">%s</span>%s</span>' % (
        status, STATUS_ICONS[status], word or STATUS_WORDS[status])


def _fmt_score(score: Optional[float]) -> str:
    return "n/a" if score is None else "%g" % score


def _table(headers: Iterable[str], rows: List[str], caption: str = "") -> str:
    head = "".join('<th scope="col">%s</th>' % h for h in headers)
    cap = '<caption class="sr">%s</caption>' % esc(caption) if caption else ""
    return '<div class="table-wrap"><table>%s<thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
        cap, head, "".join(rows))


def _location(file: Optional[str], line: Optional[int]) -> str:
    if not file:
        return '<span class="empty">repository</span>'
    return '<span class="mono">%s%s</span>' % (esc(file), ":%d" % line if line else "")


# --- Sections -------------------------------------------------------------------------

def _hero(result: ScanResult) -> str:
    verdict_status = VERDICT_STATUS.get(result.verdict, "na")
    gate = status_label("pass", "Passed") if result.gate_passed else status_label("fail", "Failed")
    gate_reason = ""
    if result.gate_reasons:
        gate_reason = ' <span class="muted">(%s)</span>' % esc("; ".join(result.gate_reasons))
    counts = result.counts
    return """
<header class="hero">
  <p class="meta">aigov scorecard for <strong class="mono">%(target)s</strong> &middot; %(when)s</p>
  <h1>%(headline)s</h1>
  <ul class="facts">
    <li>Score <strong class="score-num">%(score)s</strong> of 100</li>
    <li>Verdict %(verdict)s</li>
    <li>Gate %(gate)s%(gate_reason)s</li>
    <li>%(p)d pass, %(w)d warn, %(f)d fail, %(n)d not assessed</li>
  </ul>
  %(strip)s
</header>""" % {
        "target": esc(result.target),
        "when": esc(result.generated_at.replace("T", " ").replace("Z", " UTC")),
        "headline": esc(result.headline),
        "score": _fmt_score(result.score),
        "verdict": status_label(verdict_status, esc(result.verdict)),
        "gate": gate,
        "gate_reason": gate_reason,
        "p": counts["pass"], "w": counts["warn"], "f": counts["fail"], "n": counts["na"],
        "strip": _strip(result),
    }


def _strip(result: ScanResult) -> str:
    groups = []
    for function in FUNCTIONS:
        controls = [c for c in result.controls if c.function == function]
        if not controls:
            continue
        cells = "".join(
            '<a class="cell %(s)s" href="#ctl-%(id)s" title="%(id)s %(title)s: %(word)s">'
            '<span class="ic" aria-hidden="true">%(icon)s</span>'
            '<span><span class="id">%(id)s</span><br><span class="word">%(word)s</span></span>'
            '<span class="sr"> %(title)s</span></a>' % {
                "s": c.status, "id": esc(c.id), "title": esc(c.title),
                "word": STATUS_WORDS[c.status], "icon": STATUS_ICONS[c.status],
            }
            for c in controls
        )
        groups.append(
            '<nav class="strip-group g%d" aria-labelledby="sg-%s"><h2 id="sg-%s">%s '
            '<span>%s</span></h2><div class="cells">%s</div></nav>' % (
                len(controls), function, function, function,
                _fmt_score(result.function_scores.get(function)), cells)
        )
    legend = "".join("<li>%s</li>" % status_label(s) for s in ("pass", "warn", "fail", "na"))
    return ('<div class="strip" role="group" aria-label="Controls by function">%s</div>'
            '<ul class="legend" aria-label="Legend">%s</ul>' % ("".join(groups), legend))


def _function_summary(result: ScanResult) -> str:
    rows = []
    for function in FUNCTIONS:
        controls = [c for c in result.controls if c.function == function]
        tally = {s: sum(1 for c in controls if c.status == s) for s in STATUS_WORDS}
        rows.append(
            "<tr><td><span class=\"fn-name\">%s</span><span class=\"fn-blurb\">%s</span></td>"
            "<td class=\"num\">%s</td><td class=\"num\">%d</td><td class=\"num\">%d</td>"
            "<td class=\"num\">%d</td><td class=\"num\">%d</td></tr>" % (
                function, FUNCTION_BLURBS[function], _fmt_score(result.function_scores.get(function)),
                tally["pass"], tally["warn"], tally["fail"], tally["na"])
        )
    headers = ["Function", "Score", status_label("pass"), status_label("warn"),
               status_label("fail"), status_label("na")]
    return """
<section aria-labelledby="h-functions">
  <h2 id="h-functions">Summary by function</h2>
  <p class="lede">Controls are grouped by the four NIST AI RMF functions purely to organise this
  report. Scores are weighted: pass counts fully, warn counts half, fail counts zero, and controls
  that were not assessed are left out.</p>
  %s
</section>""" % _table(headers, rows)


def _control(control: ControlResult) -> str:
    if control.findings:
        rows = [
            "<tr><td><span class=\"sev %s\">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                SEVERITY_CLASS[f.severity], esc(f.severity.capitalize()), _location(f.file, f.line),
                esc(f.message), '<span class="mono">%s</span>' % esc(f.evidence) if f.evidence else "")
            for f in control.findings
        ]
        findings = _table(["Severity", "Location", "Finding", "Evidence (masked)"], rows)
    else:
        findings = '<p class="empty">No findings.</p>'
    refs = ", ".join(esc(r) for r in control.refs)
    return """
<details class="control %(s)s" id="ctl-%(id)s"%(open)s>
  <summary>
    %(label)s
    <span class="c-title"><span class="mono">%(id)s</span>%(title)s</span>
    <span class="c-weight">weight %(weight)d</span>
    <span class="c-summary">%(summary)s</span>
  </summary>
  <div class="c-body">
    <h4>Why it matters</h4><p>%(why)s</p>
    <h4>Findings</h4>%(findings)s
    <h4>Remediation</h4><p>%(remediation)s</p>
    <p class="refs">References: %(refs)s</p>
  </div>
</details>""" % {
        "s": control.status, "id": esc(control.id), "title": esc(control.title),
        "open": " open" if control.status == "fail" else "",
        "label": status_label(control.status), "weight": control.weight,
        "summary": esc(control.summary), "why": esc(control.why), "findings": findings,
        "remediation": esc(control.remediation), "refs": refs,
    }


def _controls(result: ScanResult) -> str:
    parts = ['<section aria-labelledby="h-controls"><h2 id="h-controls">Controls</h2>'
             '<p class="lede">Failing controls are expanded. Select any control to see why it '
             'matters, every finding and how to fix it.</p>']
    for function in FUNCTIONS:
        controls = [c for c in result.controls if c.function == function]
        parts.append("<h3>%s</h3>" % function)
        parts.extend(_control(c) for c in controls)
    parts.append("</section>")
    return "".join(parts)


def _provenance(result: ScanResult) -> str:
    if result.declarations:
        rows = []
        for d in result.declarations:
            reviewed = bool(d.reviewed_by)
            rows.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    _location(d.path, None), esc(d.kind.capitalize()), esc(d.tool), esc(d.model) or "&ndash;",
                    esc(d.reviewed_by) if reviewed else status_label("fail", "None"),
                    esc(d.reviewed_at) or "&ndash;", esc(", ".join(d.sources)))
            )
        body = _table(["File", "Kind", "Tool", "Model", "Reviewed by", "Reviewed at", "Declared in"], rows)
    else:
        body = '<p class="empty">No files are declared as AI-generated or AI-assisted.</p>'
    manifest = "present" if result.manifest_present else "not present"
    return """
<section aria-labelledby="h-prov">
  <h2 id="h-prov">Declared provenance</h2>
  <p class="lede">Files the team declares as AI-generated or AI-assisted, from
  <code>.ai-provenance.json</code> (%s) and header markers. aigov does not detect authorship.</p>
  %s
</section>""" % (manifest, body)


def _commits(result: ScanResult) -> str:
    git = result.git
    if git is None or not git.available:
        reason = git.reason if git else "not assessed"
        body = '<p class="empty">Git history not assessed: %s.</p>' % esc(reason)
    elif not git.commits:
        body = '<p class="empty">No AI-assisted commits among %d commits read.</p>' % git.total_commits
    else:
        rows = []
        for c in git.commits:
            review = status_label("pass", "Yes") if c.human_reviewed else status_label("fail", "No")
            if c.ai_reviewers:
                reviewers = (esc(", ".join(c.reviewers)) or "&ndash;") + \
                    ' <span class="fn-blurb">AI reviewer ignored: %s</span>' % esc(", ".join(c.ai_reviewers))
            else:
                reviewers = esc(", ".join(c.reviewers)) or "&ndash;"
            rows.append(
                "<tr><td class=\"mono\">%s</td><td class=\"num\">%s</td><td>%s</td><td>%s</td>"
                "<td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    esc(c.sha[:10]), esc(c.date[:10]), esc(c.author), esc(c.subject),
                    esc("; ".join(c.ai_signals)), review, reviewers)
            )
        note = " (history truncated)" if git.truncated else ""
        body = ('<p class="lede">%d of %d commits read carry AI signals%s.</p>' % (
            len(git.commits), git.total_commits, note)
            + _table(["Commit", "Date", "Author", "Subject", "AI signals", "Human review", "Reviewers"], rows))
    return """
<section aria-labelledby="h-commits">
  <h2 id="h-commits">AI-assisted commits</h2>
  %s
</section>""" % body


def _suppressions(result: ScanResult) -> str:
    if result.suppressions:
        rows = [
            "<tr><td>%s</td><td>%s</td><td>%s</td><td class=\"num\">%s</td><td>%s</td></tr>" % (
                _location(s.file, s.line), esc(s.control),
                "Whole file" if s.scope == "file" else "Line",
                s.directive_line or "&ndash;", esc(s.message))
            for s in result.suppressions
        ]
        body = _table(["Location", "Control", "Scope", "Directive line", "Suppressed finding"], rows)
    else:
        body = '<p class="empty">No findings were suppressed.</p>'
    return """
<section aria-labelledby="h-supp">
  <h2 id="h-supp">Suppressions</h2>
  <p class="lede">Findings silenced with <code>%s</code> on a line or
  <code>%s-file</code> in a file header. They do not count against the score and are
  listed here so a reviewer can challenge them.</p>
  %s
</section>""" % (IGNORE_TOKEN, IGNORE_TOKEN, body)


def _scan_details(result: ScanResult) -> str:
    skipped = ""
    if result.skipped:
        rows = ["<tr><td>%s</td><td>%s</td></tr>" % (_location(p, None), esc(r)) for p, r in result.skipped]
        skipped = ("<details class=\"control na\"><summary><span class=\"c-title\">%d paths not scanned"
                   "</span><span class=\"c-weight\"></span></summary><div class=\"c-body\">%s</div></details>"
                   % (len(result.skipped), _table(["Path", "Reason"], rows)))
    policy = result.policy
    source = esc(policy.source) if policy.source else "built-in defaults"
    limits = "".join("<li>%s</li>" % esc(item) for item in LIMITATIONS)
    return """
<section aria-labelledby="h-limits">
  <h2 id="h-limits">Limitations and scope</h2>
  <div class="notice"><p><strong>This is not a compliance attestation.</strong> %(disclaimer)s</p></div>
  <ul class="limits">%(limits)s</ul>
  <p class="meta">%(files)d files scanned. Policy: <span class="mono">%(source)s</span>
  (minimum score %(min)g, review threshold %(rt)g%%, minimum test ratio %(tr)g).</p>
  %(skipped)s
</section>""" % {
        "disclaimer": esc(DISCLAIMER), "limits": limits, "files": result.files_scanned,
        "source": source, "min": policy.min_score, "rt": policy.review_threshold * 100,
        "tr": policy.min_test_ratio, "skipped": skipped,
    }


def render_html(result: ScanResult) -> str:
    css = CSS + "\n.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; " \
                "clip: rect(0 0 0 0); white-space: nowrap; }\n.muted { color: var(--muted); }\n"
    for size in sorted({sum(1 for c in result.controls if c.function == f) for f in FUNCTIONS}):
        css += ".strip-group.g%d { flex: %d 1 0; }\n" % (size, size)
    csp = ("default-src 'none'; style-src %s; script-src %s; img-src data:; "
           "base-uri 'none'; form-action 'none'" % (_csp_hash(css), _csp_hash(SCRIPT)))
    body = "".join([
        _hero(result), _function_summary(result), _controls(result), _provenance(result),
        _commits(result), _suppressions(result), _scan_details(result),
    ])
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="%(csp)s">
<meta name="referrer" content="no-referrer">
<title>aigov scorecard: %(target)s</title>
<style>%(css)s</style>
</head>
<body>
<main class="page">
%(body)s
<footer>Generated by aigov %(version)s on %(when)s. A heuristic scorecard: not legal advice, not a
certification.</footer>
</main>
<script>%(script)s</script>
</body>
</html>
""" % {
        "csp": esc(csp), "target": esc(result.target), "css": css, "body": body,
        "version": esc(__version__), "when": esc(result.generated_at), "script": SCRIPT,
    }
