from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Sequence

Severity = Literal["High", "Medium", "Low"]
TargetType = Literal["skill_md", "script"]

SEVERITY_ORDER: dict[Severity, int] = {
    "High": 0,
    "Medium": 1,
    "Low": 2,
}


@dataclass(frozen=True)
class RuleMatch:
    line: int
    evidence: str


@dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    title: str
    file: str
    line: int
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class IgnoredFinding:
    id: str
    severity: Severity
    file: str
    line: int
    reason: str


Matcher = Callable[[Path, str, Sequence[str]], list[RuleMatch]]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    target: TargetType
    description: str
    severity: Severity
    recommendation: str
    matcher: Matcher


@dataclass
class ScanResult:
    scan_root: Path
    scanned_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    ignored: list[IgnoredFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def finding_sort_key(finding: Finding) -> tuple[int, str, int, str]:
    return (
        SEVERITY_ORDER[finding.severity],
        finding.file,
        finding.line,
        finding.id,
    )
