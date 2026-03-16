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
