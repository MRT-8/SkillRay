"""SR-DESTRUCT-xxx: Destructive operation rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-DESTRUCT-001: Recursive file deletion
register(Rule(
    rule_id="SR-DESTRUCT-001",
    category=ThreatCategory.DESTRUCTIVE_OPS,
    severity=Severity.HIGH,
    title="Recursive file deletion detected",
    description="Commands that recursively delete files or directories.",
    recommendation="Avoid destructive commands; require explicit human confirmation.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\brm\s+-rf\b",
    r"\brm\s+-r\b",
    r"\brmdir\s+/s\b",
    r"\bdel\s+/[sqf]",
    r"\bRemove-Item\b[^\n]*-Recurse[^\n]*-Force",
    r"\bshutil\.rmtree\s*\(",
    r"\bos\.removedirs\s*\(",
])

# SR-DESTRUCT-002: Disk formatting / dd command
register(Rule(
    rule_id="SR-DESTRUCT-002",
    category=ThreatCategory.DESTRUCTIVE_OPS,
    severity=Severity.CRITICAL,
    title="Disk formatting or raw disk write",
    description="Commands that format disks or perform raw disk writes.",
    recommendation="Disk formatting commands should not appear in skill scripts.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\bmkfs\.\w+\b",
    r"\bdd\s+if=",
    r"\bformat\s+[A-Za-z]:\s*/",
    r"\bdiskpart\b",
    r"\bfdisk\b\s+/dev/",
])

# SR-DESTRUCT-003: Git history destruction
register(Rule(
    rule_id="SR-DESTRUCT-003",
    category=ThreatCategory.DESTRUCTIVE_OPS,
    severity=Severity.MEDIUM,
    title="Git history destruction command",
    description="Commands that destroy git history or force-push.",
    recommendation="Avoid destructive git operations in automated scripts.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\bgit\s+push\s+--force\b",
    r"\bgit\s+push\s+-f\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+clean\s+-fd\b",
    r"\bgit\s+filter-branch\b",
    r"\bgit\s+rebase\b.*--force",
])
