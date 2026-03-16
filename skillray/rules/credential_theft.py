"""SR-CRED-xxx: Credential theft rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-CRED-001: Hardcoded API key/token (entropy engine)
register(Rule(
    rule_id="SR-CRED-001",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.CRITICAL,
    title="Hardcoded API key or token detected",
    description="High-entropy string in a secret assignment context.",
    recommendation="Use environment variables or a secrets manager.",
    targets=(TargetType.ANY,),
    engine="entropy",
))

# SR-CRED-002: Environment variable bulk collection + send (dataflow engine)
register(Rule(
    rule_id="SR-CRED-002",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.HIGH,
    title="Environment variable collection with network transmission",
    description="Bulk os.environ access combined with outbound network calls.",
    recommendation="Avoid collecting environment variables and sending them over the network.",
    targets=(TargetType.SCRIPT,),
    engine="dataflow",
))

# SR-CRED-003: SSH key / AWS credential file access (regex)
register(Rule(
    rule_id="SR-CRED-003",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.HIGH,
    title="SSH key or credential file access",
    description="Accessing known credential storage files like SSH keys or AWS credentials.",
    recommendation="Do not access credential files directly. Use proper credential management.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"(?:open|read|cat|type)\s*\(?['\"]?.*(?:\.ssh/id_rsa|\.ssh/id_ed25519|\.aws/credentials|\.netrc|\.pgpass)",
    r"\b(?:scp|rsync)\b[^\n]*(?:\.ssh/id_rsa|\.aws/credentials)",
    r"(?:ssh-keygen|ssh-add)\s+.*(?:-f\s+|<)",
])

# SR-CRED-004: Credential file patterns in skill descriptions (regex)
register(Rule(
    rule_id="SR-CRED-004",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.HIGH,
    title="Credential file reference in skill description",
    description="Skill description references accessing credential files.",
    recommendation="Skills should not instruct reading credential files.",
    targets=(TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r"(?:read|access|open|cat|get|retrieve|send|upload)\s+.*(?:\.env|id_rsa|\.ssh|/etc/passwd|\.aws/credentials|\.netrc|\.pgpass|credentials\.json|token\.json)",
])

# SR-CRED-005: Known key formats (entropy engine)
register(Rule(
    rule_id="SR-CRED-005",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.CRITICAL,
    title="Known secret key format detected",
    description="Matched a well-known secret key prefix pattern (AKIA, ghp_, sk-, etc.).",
    recommendation="Use environment variables or a secrets manager.",
    targets=(TargetType.ANY,),
    engine="entropy",
))
