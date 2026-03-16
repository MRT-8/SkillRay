"""SR-PRIV-xxx: Privilege escalation rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-PRIV-001: sudo/runas usage
register(Rule(
    rule_id="SR-PRIV-001",
    category=ThreatCategory.PRIVILEGE_ESCALATION,
    severity=Severity.HIGH,
    title="Privilege elevation command (sudo/runas)",
    description="Using sudo, runas, or similar privilege escalation commands.",
    recommendation="Use least-privilege alternatives; avoid sudo in automated scripts.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\bsudo\s+",
    r"\brunas\b\s+/user:",
    r"\bRun\s+as\s+Administrator\b",
    r"\bdoas\s+",
    r"\bpkexec\s+",
])

# SR-PRIV-002: Security bypass instructions
register(Rule(
    rule_id="SR-PRIV-002",
    category=ThreatCategory.PRIVILEGE_ESCALATION,
    severity=Severity.HIGH,
    title="Security mechanism bypass instruction",
    description="Instructions to disable or bypass security mechanisms.",
    recommendation="Document least-privilege alternatives and avoid bypass instructions.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\bSet-ExecutionPolicy\b[^\n]*\bBypass\b",
    r"\bdisable\w*\s+(?:defender|firewall|antivirus|selinux|apparmor)",
    r"\b--no-sandbox\b",
    r"\b--disable-web-security\b",
    r"\ballowRunningOfInsecureContent\b",
    r"\b--no-verify\b",
    r"verify\s*=\s*False",
])

# SR-PRIV-003: Container escape patterns
register(Rule(
    rule_id="SR-PRIV-003",
    category=ThreatCategory.PRIVILEGE_ESCALATION,
    severity=Severity.CRITICAL,
    title="Container escape pattern detected",
    description="Commands or configurations that could enable container escape.",
    recommendation="Ensure container isolation boundaries are maintained.",
    targets=(TargetType.SCRIPT, TargetType.CONFIG),
    engine="regex",
), patterns=[
    r"\b--privileged\b",
    r"\bcapabilities\b.*\bSYS_ADMIN\b",
    r"\bmount\b.*\b/dev/sd[a-z]",
    r"\bnsenter\b",
    r"\bchroot\b\s+/",
    r"\bdocker\.sock\b",
])

# SR-PRIV-004: SetUID/permission modification
register(Rule(
    rule_id="SR-PRIV-004",
    category=ThreatCategory.PRIVILEGE_ESCALATION,
    severity=Severity.HIGH,
    title="File permission modification (SetUID/chmod)",
    description="Changing file permissions to enable privilege escalation.",
    recommendation="Avoid setting SUID/SGID bits or overly permissive file modes.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"\bchmod\s+[u+]*s\b",
    r"\bchmod\s+[0-7]*[4-7][0-7]{2}\b",
    r"\bchmod\s+777\b",
    r"\bchown\s+root\b",
    r"\bsetuid\b",
    r"\bsetgid\b",
])
