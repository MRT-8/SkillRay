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

# SR-OBFUSC-006: ROT13 encoding in execution context
register(Rule(
    rule_id="SR-OBFUSC-006",
    category=ThreatCategory.OBFUSCATION,
    severity=Severity.MEDIUM,
    title="ROT13 encoding in execution context",
    description="ROT13 decoding combined with code execution or command building.",
    recommendation="Use clear, readable code instead of ROT13-encoded payloads.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"codecs\.decode\s*\(.*['\"]rot.13['\"]",
    r"\.translate\s*\(.*maketrans.*13\)",
    r"rot13.*(?:eval|exec|system|popen|subprocess)",
    r"(?:eval|exec)\s*\(.*rot13",
])

# SR-OBFUSC-007: XOR-based payload obfuscation
register(Rule(
    rule_id="SR-OBFUSC-007",
    category=ThreatCategory.OBFUSCATION,
    severity=Severity.HIGH,
    title="XOR-based payload obfuscation",
    description="XOR-encoded payloads combined with code execution.",
    recommendation="Do not use XOR encoding to hide executable payloads.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"chr\s*\(\s*ord\s*\(.*\)\s*\^\s*",
    r"bytes\s*\(\s*\[?\s*(?:b\s*\^\s*k|x\s*\^|c\s*\^).*for\b",
    r"(?:eval|exec)\s*\(.*\bxor\b",
    r"\bxor\b.*(?:eval|exec|system|subprocess)",
])

# SR-OBFUSC-008: Multi-layer encoding chain
register(Rule(
    rule_id="SR-OBFUSC-008",
    category=ThreatCategory.OBFUSCATION,
    severity=Severity.MEDIUM,
    title="Multi-layer encoding chain",
    description="Multiple encoding/decoding layers chained together to hide payloads.",
    recommendation="Remove nested encoding layers used to obfuscate code.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"(?:base64|b64decode|atob).*(?:base32|b32decode).*(?:decode|unhexlify|fromhex)",
    r"(?:decode|unhexlify|fromhex).*(?:base64|b64decode).*(?:eval|exec)",
    r"(?:b64decode|atob)\s*\(.*(?:b64decode|atob)\s*\(",
    r"(?:codecs\.decode.*){2,}",
])
