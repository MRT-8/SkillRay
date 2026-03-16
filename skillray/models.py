"""Core data models for SkillRay."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, Enum
from pathlib import Path
from typing import Protocol, Sequence


class Severity(IntEnum):
    """5-level severity classification."""
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def icon(self) -> str:
        return {
            Severity.CRITICAL: "[!]",
            Severity.HIGH: "[H]",
            Severity.MEDIUM: "[M]",
            Severity.LOW: "[L]",
            Severity.INFO: "[i]",
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[self]


class ThreatCategory(str, Enum):
    """9 threat categories for AI skills."""
    PROMPT_INJECTION = "SR-PROMPT"
    TOOL_POISONING = "SR-TOOL"
    CREDENTIAL_THEFT = "SR-CRED"
    DATA_EXFILTRATION = "SR-EXFIL"
    SUPPLY_CHAIN = "SR-SUPPLY"
    PRIVILEGE_ESCALATION = "SR-PRIV"
    OBFUSCATION = "SR-OBFUSC"
    DESTRUCTIVE_OPS = "SR-DESTRUCT"
    CODE_EXECUTION = "SR-EXEC"

    @property
    def display_name(self) -> str:
        return {
            ThreatCategory.PROMPT_INJECTION: "Prompt Injection",
            ThreatCategory.TOOL_POISONING: "Tool Poisoning",
            ThreatCategory.CREDENTIAL_THEFT: "Credential Theft",
            ThreatCategory.DATA_EXFILTRATION: "Data Exfiltration",
            ThreatCategory.SUPPLY_CHAIN: "Supply Chain",
            ThreatCategory.PRIVILEGE_ESCALATION: "Privilege Escalation",
            ThreatCategory.OBFUSCATION: "Obfuscation",
            ThreatCategory.DESTRUCTIVE_OPS: "Destructive Operations",
            ThreatCategory.CODE_EXECUTION: "Code Execution",
        }[self]


class TargetType(str, Enum):
    """Types of files that can be scanned."""
    SKILL_MD = "skill_md"
    SCRIPT = "script"
    MARKDOWN = "markdown"
    CONFIG = "config"
    ANY = "any"


@dataclass(frozen=True)
class RuleMatch:
    """A single match from an engine."""
    line: int
    evidence: str
    context: str = ""


@dataclass(frozen=True)
class Rule:
    """A security rule definition."""
    rule_id: str
    category: ThreatCategory
    severity: Severity
    title: str
    description: str
    recommendation: str
    targets: tuple[TargetType, ...] = (TargetType.ANY,)
    engine: str = "regex"


@dataclass(frozen=True)
class Finding:
    """A security finding (rule + match)."""
    rule_id: str
    category: ThreatCategory
    severity: Severity
    title: str
    file: str
    line: int
    evidence: str
    recommendation: str
    engine: str = "regex"
    context: str = ""


@dataclass(frozen=True)
class IgnoredFinding:
    """A finding that was suppressed."""
    rule_id: str
    severity: Severity
    file: str
    line: int
    reason: str


@dataclass
class ScanResult:
    """Aggregated scan results."""
    scan_root: Path
    scanned_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    ignored: list[IgnoredFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def severity_counts(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def category_counts(self) -> dict[ThreatCategory, int]:
        counts: dict[ThreatCategory, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts


class Engine(Protocol):
    """Protocol for detection engines."""
    name: str

    def scan(self, file_path: Path, content: str, target: TargetType) -> list[Finding]: ...


def finding_sort_key(f: Finding) -> tuple[int, str, int, str]:
    return (f.severity.value, f.file, f.line, f.rule_id)
