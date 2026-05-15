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

# SR-CRED-006: Cryptocurrency wallet file access
register(Rule(
    rule_id="SR-CRED-006",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.HIGH,
    title="Cryptocurrency wallet file access",
    description="Accessing cryptocurrency wallet files, seed phrases, or keystore data.",
    recommendation="Do not access cryptocurrency wallet files.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r"\bwallet\.dat\b",
    r"\.bitcoin/",
    r"\.ethereum/(?:keystore|geth)",
    r"keystore/UTC--",
    r"\.config/solana/",
    r"\.monero/",
    r"seed[_\s]*(?:phrase|words|mnemonic)",
])

# SR-CRED-007: Browser credential theft
register(Rule(
    rule_id="SR-CRED-007",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.HIGH,
    title="Browser credential or session theft",
    description="Accessing browser cookie stores, login databases, or session storage.",
    recommendation="Do not access browser credential stores.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"(?:Chrome|Chromium|Google)/.*(?:Default|Profile)/(?:Cookies|Login Data|Web Data)",
    r"\.mozilla/firefox/.*\.default.*(?:cookies|logins|key[34]\.db)",
    r"(?:Local|Session)\s*Storage.*(?:token|session|auth)",
    r"(?:cookie_jar|cookiejar|browser_cookie|browsercookie)",
])

# SR-CRED-008: Cloud CLI credential theft
register(Rule(
    rule_id="SR-CRED-008",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.HIGH,
    title="Cloud CLI credential access",
    description="Accessing cloud provider CLI credential files (gcloud, az, aws, kubectl).",
    recommendation="Do not directly access cloud CLI credential files.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r"\.config/gcloud/(?:credentials|application_default_credentials)",
    r"\.azure/(?:accessTokens|azureProfile)",
    r"\.kube/config",
    r"\.config/gh/hosts\.yml",
    r"\.docker/config\.json",
    r"\.oci/config",
    r"doctl.*auth.*(?:token|init)",
])

# SR-CRED-009: Shell history file access
register(Rule(
    rule_id="SR-CRED-009",
    category=ThreatCategory.CREDENTIAL_THEFT,
    severity=Severity.MEDIUM,
    title="Shell history file access",
    description="Accessing shell or REPL history files that may contain accidentally typed secrets.",
    recommendation="Do not access shell history files.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\.bash_history",
    r"\.zsh_history",
    r"\.python_history",
    r"\.node_repl_history",
    r"\.psql_history",
    r"\.mysql_history",
    r"\.rediscli_history",
])
