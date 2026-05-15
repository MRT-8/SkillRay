"""SR-PROMPT-xxx: Prompt injection rules (handled by prompt_engine)."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

_TARGETS = (TargetType.SKILL_MD, TargetType.MARKDOWN)

register(Rule(
    rule_id="SR-PROMPT-001",
    category=ThreatCategory.PROMPT_INJECTION,
    severity=Severity.CRITICAL,
    title="Hidden instruction in HTML comment",
    description="HTML comments containing instructions to ignore/override previous context.",
    recommendation="Remove hidden instructions from markdown comments.",
    targets=_TARGETS,
    engine="prompt",
))

register(Rule(
    rule_id="SR-PROMPT-002",
    category=ThreatCategory.PROMPT_INJECTION,
    severity=Severity.CRITICAL,
    title="Role override / instruction injection attempt",
    description="Attempts to override AI role or inject new system instructions.",
    recommendation="Remove prompt injection attempts that try to override AI behavior.",
    targets=_TARGETS,
    engine="prompt",
))

register(Rule(
    rule_id="SR-PROMPT-003",
    category=ThreatCategory.PROMPT_INJECTION,
    severity=Severity.CRITICAL,
    title="Invisible Unicode characters detected",
    description="Zero-width spaces, RTL overrides, or other invisible Unicode characters.",
    recommendation="Remove invisible/zero-width Unicode characters that could hide instructions.",
    targets=(TargetType.ANY,),
    engine="prompt",
))

register(Rule(
    rule_id="SR-PROMPT-004",
    category=ThreatCategory.PROMPT_INJECTION,
    severity=Severity.HIGH,
    title="Base64-encoded instruction detected",
    description="Base64 encoded content that decodes to prompt injection instructions.",
    recommendation="Remove encoded instructions from skill definitions.",
    targets=(TargetType.ANY,),
    engine="prompt",
))

register(Rule(
    rule_id="SR-PROMPT-005",
    category=ThreatCategory.PROMPT_INJECTION,
    severity=Severity.HIGH,
    title="External content fetch with injection risk",
    description="Fetching external content using user-controlled input without sanitization.",
    recommendation="Validate and sanitize URLs before fetching external content.",
    targets=_TARGETS,
    engine="prompt",
))

# SR-PROMPT-006: Unicode Tags block characters (invisible prompt injection)
register(Rule(
    rule_id="SR-PROMPT-006",
    category=ThreatCategory.PROMPT_INJECTION,
    severity=Severity.CRITICAL,
    title="Unicode Tags block characters detected",
    description="Characters from Unicode Tags block (U+E0001-E007F) used for invisible prompt injection.",
    recommendation="Remove Unicode Tag characters. These are invisible and can hide instructions.",
    targets=(TargetType.ANY,),
    engine="prompt",
))

# SR-PROMPT-007: Emoji Variation Selector payload hiding
register(Rule(
    rule_id="SR-PROMPT-007",
    category=ThreatCategory.PROMPT_INJECTION,
    severity=Severity.HIGH,
    title="Emoji Variation Selector payload hiding",
    description="Variation Selectors (U+FE00-FE0F, U+E0100-E01EF) used to hide payloads in emoji sequences.",
    recommendation="Remove Variation Selector characters used outside normal emoji rendering.",
    targets=(TargetType.ANY,),
    engine="prompt",
))

# SR-PROMPT-008: ANSI escape sequence injection
register(Rule(
    rule_id="SR-PROMPT-008",
    category=ThreatCategory.PROMPT_INJECTION,
    severity=Severity.HIGH,
    title="ANSI escape sequence injection",
    description="ANSI escape sequences that can manipulate terminal output to hide or fake content.",
    recommendation="Remove ANSI escape sequences from skill definitions.",
    targets=(TargetType.ANY,),
    engine="prompt",
))
