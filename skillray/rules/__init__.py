"""Rule definitions for SkillRay."""

from . import registry
from .registry import get_all_rules

# Import all rule modules to trigger registration
from . import (
    prompt_injection,
    tool_poisoning,
    credential_theft,
    data_exfiltration,
    supply_chain,
    privilege_escalation,
    obfuscation,
    destructive_ops,
    code_execution,
)

__all__ = ["registry", "get_all_rules"]
