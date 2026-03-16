"""SR-TOOL-xxx: Tool poisoning rules (handled by prompt_engine)."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

_TARGETS = (TargetType.SKILL_MD, TargetType.MARKDOWN)

register(Rule(
    rule_id="SR-TOOL-001",
    category=ThreatCategory.TOOL_POISONING,
    severity=Severity.CRITICAL,
    title="Tool description contains hidden behavior instructions",
    description="Tool descriptions that secretly instruct additional actions beyond stated purpose.",
    recommendation="Tool descriptions should only describe their stated functionality.",
    targets=_TARGETS,
    engine="prompt",
))

register(Rule(
    rule_id="SR-TOOL-002",
    category=ThreatCategory.TOOL_POISONING,
    severity=Severity.HIGH,
    title="Tool parameter suggests unauthorized access level",
    description="Tool parameters requesting admin/root/elevated privileges.",
    recommendation="Tools should not request elevated privileges beyond their scope.",
    targets=_TARGETS,
    engine="prompt",
))

register(Rule(
    rule_id="SR-TOOL-003",
    category=ThreatCategory.TOOL_POISONING,
    severity=Severity.CRITICAL,
    title="MCP tool definition attempts to override security constraints",
    description="Tool definitions that attempt to modify or bypass security policies.",
    recommendation="Tool definitions must not override security policies.",
    targets=_TARGETS,
    engine="prompt",
))
