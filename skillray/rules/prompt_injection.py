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
