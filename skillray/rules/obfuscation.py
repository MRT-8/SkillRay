"""SR-OBFUSC-xxx: Code obfuscation rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-OBFUSC-001: Base64 encoded payload decoded for execution
register(Rule(
    rule_id="SR-OBFUSC-001",
    category=ThreatCategory.OBFUSCATION,
    severity=Severity.CRITICAL,
    title="Base64 encoded payload decoded for execution",
    description="Base64 decoding combined with code execution (eval/exec/sh).",
    recommendation="Avoid encoding code as Base64. Use clear, readable code.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"(?:base64\.b64decode|atob|base64\s+-d)\s*\([^)]*\)\s*.*(?:eval|exec|system|popen|sh\b|bash\b)",
    r"(?:eval|exec)\s*\(\s*(?:base64\.b64decode|atob)\s*\(",
    r"\becho\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash)\b",
])

# SR-OBFUSC-002: Hex encoded strings in execution context
register(Rule(
    rule_id="SR-OBFUSC-002",
    category=ThreatCategory.OBFUSCATION,
    severity=Severity.HIGH,
    title="Hex encoded string in execution context",
    description="Hex-encoded strings being decoded near code execution functions.",
    recommendation="Use readable code instead of hex-encoded payloads.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"bytes\.fromhex\s*\(\s*['\"](?:[0-9a-fA-F]{2}){10,}",
    r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){9,}",
    r"(?:eval|exec)\s*\(.*bytes\.fromhex",
])

# SR-OBFUSC-003: String concatenation building suspicious commands
register(Rule(
    rule_id="SR-OBFUSC-003",
    category=ThreatCategory.OBFUSCATION,
    severity=Severity.MEDIUM,
    title="String concatenation building suspicious command",
    description="Building shell commands via string concatenation to avoid detection.",
    recommendation="Construct commands explicitly without obfuscating via concatenation.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"""(?:['"][a-z]{1,4}['"]\s*\+\s*){3,}""",
    r"""chr\s*\(\s*\d+\s*\)\s*(?:\+\s*chr\s*\(\s*\d+\s*\)){4,}""",
    r"join\s*\(\s*\[\s*(?:chr\s*\(\s*\d+\s*\)\s*,?\s*){5,}\]",
])

# SR-OBFUSC-004: Unicode homoglyph identifiers (handled by prompt_engine)
register(Rule(
    rule_id="SR-OBFUSC-004",
    category=ThreatCategory.OBFUSCATION,
    severity=Severity.HIGH,
    title="Unicode homoglyph characters detected",
    description="Characters that visually resemble ASCII but are different Unicode codepoints.",
    recommendation="Replace homoglyph characters with their ASCII equivalents.",
    targets=(TargetType.ANY,),
    engine="prompt",
))

# SR-OBFUSC-005: Excessive string manipulation before shell execution
register(Rule(
    rule_id="SR-OBFUSC-005",
    category=ThreatCategory.OBFUSCATION,
    severity=Severity.MEDIUM,
    title="Excessive string manipulation before shell execution",
    description="Heavy string processing (replace/split/join) immediately before shell commands.",
    recommendation="Build commands transparently without excessive string manipulation.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"(?:\.replace\s*\([^)]+\)\s*){3,}.*(?:os\.system|subprocess|popen)",
    r"(?:os\.system|subprocess\..*|popen)\s*\(.*(?:\.replace\s*\([^)]+\)\s*){3,}",
])
