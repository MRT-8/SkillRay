"""SR-STEALTH-xxx: Secrecy and coercion instruction rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-STEALTH-001: Secrecy instruction to hide actions from user
register(Rule(
    rule_id="SR-STEALTH-001",
    category=ThreatCategory.STEALTH,
    severity=Severity.CRITICAL,
    title="Secrecy instruction to hide actions from user",
    description="Skill instructs AI to conceal actions from the user — a hallmark of malicious skills.",
    recommendation="Remove instructions that hide behavior from the user. Legitimate skills are transparent.",
    targets=(TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="prompt",
))

# SR-STEALTH-002: Output suppression instruction
register(Rule(
    rule_id="SR-STEALTH-002",
    category=ThreatCategory.STEALTH,
    severity=Severity.HIGH,
    title="Output suppression instruction",
    description="Skill instructs AI to suppress output or act without informing the user.",
    recommendation="Remove instructions that suppress output visibility.",
    targets=(TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="prompt",
))

# SR-STEALTH-003: Log/history clearing after execution
register(Rule(
    rule_id="SR-STEALTH-003",
    category=ThreatCategory.STEALTH,
    severity=Severity.HIGH,
    title="Log or history clearing after execution",
    description="Script clears shell history, truncates logs, or shreds evidence after execution.",
    recommendation="Investigate why execution traces are being removed.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\bhistory\s+-c\b",
    r"\brm\s+.*\.bash_history\b",
    r"\brm\s+.*\.zsh_history\b",
    r"\btruncate\s+.*log\b",
    r"\bshred\s+.*log\b",
    r">\s*/dev/null\s+2>&1\s*;?\s*(?:rm|shred|truncate)",
    r"\bunset\s+HISTFILE\b",
    r"\bexport\s+HISTSIZE=0\b",
])

# SR-STEALTH-004: Error suppression instruction
register(Rule(
    rule_id="SR-STEALTH-004",
    category=ThreatCategory.STEALTH,
    severity=Severity.MEDIUM,
    title="Error suppression instruction",
    description="Skill instructs AI to suppress errors or silently fail.",
    recommendation="Skills should not suppress error reporting.",
    targets=(TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="prompt",
))

# SR-STEALTH-005: Anti-detection / anti-analysis instruction
register(Rule(
    rule_id="SR-STEALTH-005",
    category=ThreatCategory.STEALTH,
    severity=Severity.HIGH,
    title="Anti-detection or anti-analysis instruction",
    description="Skill contains instructions to evade security scanning or monitoring.",
    recommendation="Remove anti-detection instructions. Legitimate skills do not need to evade scanners.",
    targets=(TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="prompt",
))
