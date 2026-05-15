"""SR-EXFIL-xxx: Data exfiltration rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-EXFIL-001: Sensitive read + network send (regex engine cross-line)
register(Rule(
    rule_id="SR-EXFIL-001",
    category=ThreatCategory.DATA_EXFILTRATION,
    severity=Severity.CRITICAL,
    title="Sensitive file read combined with network send",
    description="Reading sensitive files and sending data over the network in the same file.",
    recommendation="Do not couple secret file reads with outbound requests.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
))

# SR-EXFIL-002: Bulk enum + pack + upload (dataflow engine)
register(Rule(
    rule_id="SR-EXFIL-002",
    category=ThreatCategory.DATA_EXFILTRATION,
    severity=Severity.HIGH,
    title="Bulk file enumeration + archive + network upload",
    description="Combining file enumeration, archiving, and network upload.",
    recommendation="Avoid bulk file collection combined with network transmission.",
    targets=(TargetType.SCRIPT,),
    engine="dataflow",
))

# SR-EXFIL-003: DNS exfiltration (dataflow engine)
register(Rule(
    rule_id="SR-EXFIL-003",
    category=ThreatCategory.DATA_EXFILTRATION,
    severity=Severity.HIGH,
    title="Potential DNS exfiltration pattern",
    description="Using DNS queries as a data exfiltration channel.",
    recommendation="DNS-based data exfiltration detected. Review DNS query construction.",
    targets=(TargetType.SCRIPT,),
    engine="dataflow",
))

# SR-EXFIL-004: Clipboard/stdin capture + network (dataflow engine)
register(Rule(
    rule_id="SR-EXFIL-004",
    category=ThreatCategory.DATA_EXFILTRATION,
    severity=Severity.HIGH,
    title="Clipboard/stdin capture with network transmission",
    description="Capturing clipboard or stdin data and sending it over the network.",
    recommendation="Clipboard access combined with network sends is suspicious.",
    targets=(TargetType.SCRIPT,),
    engine="dataflow",
))

# SR-EXFIL-005: Reverse shell pattern
register(Rule(
    rule_id="SR-EXFIL-005",
    category=ThreatCategory.DATA_EXFILTRATION,
    severity=Severity.CRITICAL,
    title="Reverse shell pattern detected",
    description="Code establishes a reverse shell for remote command execution.",
    recommendation="Remove reverse shell code. This is a critical security threat.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r"bash\s+-i\s+>&\s*/dev/tcp/",
    r"\bnc\s+.*-e\s+/bin/(?:sh|bash)\b",
    r"\bmkfifo\s+.*\bnc\b",
    r"\bsocat\b.*\bexec\b",
    r"python.*socket.*\.connect.*(?:os\.dup2|subprocess)",
    r"\bncat\b.*(?:--exec|--sh-exec)",
    r"perl.*socket.*exec",
    r"ruby.*TCPSocket.*exec",
])

# SR-EXFIL-006: DNS subdomain exfiltration in commands (CVE-2025-55284)
register(Rule(
    rule_id="SR-EXFIL-006",
    category=ThreatCategory.DATA_EXFILTRATION,
    severity=Severity.HIGH,
    title="DNS subdomain exfiltration pattern",
    description="Shell command substitution embedded in domain names for DNS-based data exfiltration.",
    recommendation="Do not embed sensitive data in DNS queries or domain names.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r"\$\(.*(?:cat|echo|base64|xxd).*\)\..*\.\w{2,}",
    r"`.*(?:cat|echo|base64).*`\..*\.\w{2,}",
    r"(?:ping|nslookup|dig|host|curl)\s+.*\$\(",
    r"(?:ping|nslookup|dig|host|curl)\s+.*`[^`]+`",
])

# SR-EXFIL-007: Image URL parameter exfiltration
register(Rule(
    rule_id="SR-EXFIL-007",
    category=ThreatCategory.DATA_EXFILTRATION,
    severity=Severity.HIGH,
    title="Image URL parameter exfiltration",
    description="Embedding sensitive data in image URL query parameters for exfiltration.",
    recommendation="Do not include dynamic data in markdown image URLs.",
    targets=(TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r"!\[.*\]\(https?://[^)]*\?[^)]*(?:token|key|secret|data|env|password|cred)=",
    r"<img\s+[^>]*src\s*=\s*['\"]https?://[^'\"]*\?[^'\"]*(?:token|key|secret|data|env)=",
])

# SR-EXFIL-008: Webhook/callback exfiltration to known services
register(Rule(
    rule_id="SR-EXFIL-008",
    category=ThreatCategory.DATA_EXFILTRATION,
    severity=Severity.HIGH,
    title="Exfiltration to known webhook/callback service",
    description="Sending data to known exfiltration/debugging services.",
    recommendation="Do not send data to external webhook or request interception services.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN, TargetType.ANY),
    engine="regex",
), patterns=[
    r"\bwebhook\.site\b",
    r"\brequestbin\b",
    r"\bpipedream\b",
    r"\bhookbin\b",
    r"\bburp(?:suite)?.*collaborator\b",
    r"\binteractsh\b",
    r"\bcanary(?:tokens)?\.com\b",
    r"\bngrok\.io\b",
])
