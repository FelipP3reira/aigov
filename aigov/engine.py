"""Runs the controls and turns their results into a score, verdict and gate."""

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import __version__
from .checks import CONTROLS, Collector, Context
from .models import (
    FAIL, FUNCTIONS, NA, STATUS_POINTS, WARN, ControlResult, Suppression, status_from_findings,
)
from .policy import Policy, load_policy
from .provenance import GitHistory, collect_declarations, load_manifest, read_git_history
from .scanner import scan_repository

DISCLAIMER = (
    "aigov is a heuristic scorecard. It is not legal advice, not an audit and not a "
    "certification, and it does not attest compliance with any law, regulation or standard. "
    "NIST AI RMF functions are used only to organise the report."
)

LIMITATIONS = (
    "aigov does not detect AI authorship. It reads what the team declares (manifest, file "
    "markers, commit trailers). The absence of signals does not prove that AI was not used.",
    "All checks are heuristics based on file names and regular expressions. Expect false "
    "positives and false negatives.",
    "Secret and personal-data detection covers a fixed set of formats (e.g. CPF, payment cards, "
    "well-known API key prefixes); other formats are not detected.",
    "Provider detection reads Python, JavaScript/TypeScript and Go imports plus dependency "
    "manifests. Other languages are only covered through their dependency manifests.",
    "Comment detection is line-based; multi-line strings and docstrings are scanned as code.",
    "Commit trailers are read anywhere in the commit body, not only in the final paragraph.",
    "Files over the size limit, binary files, symlinks and git-ignored env files are not scanned.",
)

VERDICT_THRESHOLDS = (("Aligned", 85.0), ("Partial", 60.0))


@dataclass
class ScanResult:
    target: str
    policy: Policy
    controls: List[ControlResult]
    score: Optional[float]
    function_scores: Dict[str, Optional[float]]
    verdict: str
    headline: str
    critical_count: int
    gate_passed: bool
    gate_reasons: List[str]
    suppressions: List[Suppression] = field(default_factory=list)
    declarations: list = field(default_factory=list)
    git: Optional[GitHistory] = None
    manifest_present: bool = False
    files_scanned: int = 0
    skipped: List = field(default_factory=list)
    generated_at: str = ""

    @property
    def counts(self) -> Dict[str, int]:
        counts = {"pass": 0, "warn": 0, "fail": 0, "na": 0}
        for control in self.controls:
            counts[control.status] += 1
        return counts

    def to_dict(self) -> Dict:
        git = self.git
        return {
            "tool": {"name": "aigov", "version": __version__},
            "generated_at": self.generated_at,
            "target": self.target,
            "disclaimer": DISCLAIMER,
            "score": self.score,
            "function_scores": self.function_scores,
            "verdict": self.verdict,
            "headline": self.headline,
            "counts": self.counts,
            "critical_findings": self.critical_count,
            "gate": {"passed": self.gate_passed, "reasons": self.gate_reasons},
            "policy": self.policy.to_dict(),
            "controls": [c.to_dict() for c in self.controls],
            "suppressions": [s.to_dict() for s in self.suppressions],
            "provenance": {
                "manifest_present": self.manifest_present,
                "files": [d.to_dict() for d in self.declarations],
            },
            "git": {
                "available": bool(git and git.available),
                "reason": git.reason if git else "",
                "total_commits": git.total_commits if git else 0,
                "truncated": bool(git and git.truncated),
                "ai_assisted_commits": [c.to_dict() for c in git.commits] if git else [],
            },
            "scan": {
                "files_scanned": self.files_scanned,
                "skipped": [{"path": p, "reason": r} for p, r in self.skipped],
            },
            "limitations": list(LIMITATIONS),
        }


def compute_score(controls: List[ControlResult]) -> Optional[float]:
    """sum(weight x points) / sum(evaluated weights) x 100; N/A is excluded."""
    evaluated = [c for c in controls if c.status != NA]
    total = sum(c.weight for c in evaluated)
    if total == 0:
        return None
    earned = sum(c.weight * STATUS_POINTS[c.status] for c in evaluated)
    return round(earned / total * 100, 1)


def compute_verdict(score: Optional[float], critical_count: int) -> str:
    if critical_count:
        return "Blocked"
    if score is None:
        return "Gaps"
    for verdict, minimum in VERDICT_THRESHOLDS:
        if score >= minimum:
            return verdict
    return "Gaps"


def compute_headline(verdict: str, controls: List[ControlResult], critical_count: int) -> str:
    open_items = sum(1 for c in controls if c.status in (WARN, FAIL))
    noun = "control needs" if open_items == 1 else "controls need"
    if verdict == "Blocked":
        return "Blocked: %d critical finding%s must be fixed before this ships" % (
            critical_count, "" if critical_count == 1 else "s")
    if verdict == "Aligned":
        if not open_items:
            return "Aligned: every evaluated control passes"
        return "Aligned: %d %s attention" % (open_items, noun)
    if verdict == "Partial":
        return "Partial alignment: %d %s work before this ships" % (open_items, noun)
    return "Significant gaps: %d %s work before this ships" % (open_items, noun)


def evaluate_gate(score: Optional[float], critical_count: int, policy: Policy,
                  fail_under: Optional[float] = None) -> List[str]:
    minimum = policy.min_score if fail_under is None else fail_under
    reasons = []
    if score is None or score < minimum:
        reasons.append("score %s is below the minimum of %g" % (
            "n/a" if score is None else "%g" % score, minimum))
    if critical_count and policy.block_on_critical:
        reasons.append("%d critical finding%s and block_on_critical is enabled" % (
            critical_count, "" if critical_count == 1 else "s"))
    return reasons


def run_controls(ctx: Context) -> List[ControlResult]:
    results = []
    for spec in CONTROLS:
        if ctx.policy.is_disabled(spec.id):
            status, summary, findings = NA, "Disabled by policy", []
        else:
            collector = Collector(ctx, spec.id)
            outcome = spec.run(ctx, collector)
            findings = collector.findings
            status = outcome.status or status_from_findings(findings)
            summary = outcome.summary
        results.append(ControlResult(
            id=spec.id, title=spec.title, function=spec.function, weight=spec.weight,
            status=status, summary=summary, why=spec.why, remediation=spec.remediation,
            refs=list(spec.refs), findings=findings,
        ))
    return results


def run_scan(path: str, policy: Optional[Policy] = None,
             fail_under: Optional[float] = None) -> ScanResult:
    root = os.path.abspath(path)
    if policy is None:
        policy = load_policy(root=root)
    repo = scan_repository(root, policy)
    manifest = load_manifest(root)
    declarations = collect_declarations(repo, manifest)
    git = read_git_history(root, policy)
    ctx = Context(repo=repo, policy=policy, manifest=manifest,
                  declarations=declarations, git=git)
    controls = run_controls(ctx)

    score = compute_score(controls)
    function_scores = {
        name: compute_score([c for c in controls if c.function == name]) for name in FUNCTIONS
    }
    critical = sum(1 for c in controls for f in c.findings if f.severity == "critical")
    verdict = compute_verdict(score, critical)
    reasons = evaluate_gate(score, critical, policy, fail_under)
    return ScanResult(
        target=os.path.basename(root.rstrip("\\/")) or root,
        policy=policy,
        controls=controls,
        score=score,
        function_scores=function_scores,
        verdict=verdict,
        headline=compute_headline(verdict, controls, critical),
        critical_count=critical,
        gate_passed=not reasons,
        gate_reasons=reasons,
        suppressions=ctx.suppressions,
        declarations=list(declarations.values()),
        git=git,
        manifest_present=manifest.present,
        files_scanned=len(repo.files),
        skipped=repo.skipped,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
