"""Shared data structures, status rules and masking helpers."""

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

# Statuses a control can end up in.
PASS = "pass"
WARN = "warn"
FAIL = "fail"
NA = "na"
STATUSES = (PASS, WARN, FAIL, NA)

# Points per status used by the scoring formula. N/A is excluded from scoring.
STATUS_POINTS = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

# NIST AI RMF functions, used only to group controls in the report.
FUNCTIONS = ("Govern", "Map", "Measure", "Manage")

CONTROL_IDS = (
    "GOV-01", "GOV-02", "GOV-03",
    "MAP-01", "MAP-02", "MAP-03",
    "MEA-01", "MEA-02", "MEA-03",
    "MAN-01", "MAN-02", "MAN-03", "MAN-04",
)


@dataclass
class Finding:
    """A single observation. `evidence` must already be masked."""

    message: str
    severity: str = "medium"
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None

    def __post_init__(self):
        if self.severity not in SEVERITY_RANK:
            raise ValueError("unknown severity: %r" % self.severity)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Suppression:
    """A finding silenced by an inline or file-level directive."""

    file: str
    line: Optional[int]  # line of the suppressed finding
    scope: str  # "line" or "file"
    control: str
    message: str
    directive_line: Optional[int] = None  # line holding the directive

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ControlResult:
    id: str
    title: str
    function: str
    weight: int
    status: str
    summary: str
    why: str
    remediation: str
    refs: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict:
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


def status_from_findings(findings: List[Finding]) -> str:
    """high/critical -> fail, medium/low -> warn, info only or none -> pass."""
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=-1)
    if worst >= SEVERITY_RANK["high"]:
        return FAIL
    if worst >= SEVERITY_RANK["low"]:
        return WARN
    return PASS


@dataclass
class AISystem:
    """An entry of `ai_systems` in .ai-provenance.json."""

    provider: str
    purpose: str = ""
    owner: str = ""
    data_categories: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class FileDeclaration:
    """A file the team declares as AI-generated or AI-assisted."""

    path: str
    tool: str
    model: str = ""
    reviewed_by: str = ""
    reviewed_at: str = ""
    kind: str = "generated"  # "generated" or "assisted"
    sources: List[str] = field(default_factory=list)  # "manifest", "marker"

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Commit:
    sha: str
    author: str  # name only; e-mail addresses are never kept
    date: str
    subject: str
    ai_signals: List[str] = field(default_factory=list)
    reviewers: List[str] = field(default_factory=list)  # human reviewers only
    ai_reviewers: List[str] = field(default_factory=list)

    @property
    def ai_assisted(self) -> bool:
        return bool(self.ai_signals)

    @property
    def human_reviewed(self) -> bool:
        return bool(self.reviewers)

    def to_dict(self) -> Dict:
        data = asdict(self)
        data["ai_assisted"] = self.ai_assisted
        data["human_reviewed"] = self.human_reviewed
        return data


# --- Masking -----------------------------------------------------------------
# Raw secrets and personal data must never leave the process. Every finding
# that carries evidence builds it with one of these helpers.

def mask_secret(value: str, keep: int = 4) -> str:
    """'sk-d… (40 characters, masked)'. Short values reveal nothing."""
    value = value or ""
    length = len(value)
    if length <= 8:
        return "[%d characters, masked]" % length
    keep = min(keep, length // 4)
    return "%s… (%d characters, masked)" % (value[:keep], length)


def mask_cpf(value: str) -> str:
    """'***.***.***-25': only the two check digits are kept."""
    digits = "".join(ch for ch in value if ch.isdigit())
    return "***.***.***-" + digits[-2:] if len(digits) >= 2 else "***.***.***-**"


def mask_card(value: str) -> str:
    """'**** **** **** 1234 (16 digits, masked)'."""
    digits = "".join(ch for ch in value if ch.isdigit())
    return "**** **** **** %s (%d digits, masked)" % (digits[-4:], len(digits))
