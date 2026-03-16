"""SR-EXEC-xxx: Code execution rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-EXEC-001: eval/exec with user-controllable input (ast engine)
register(Rule(
    rule_id="SR-EXEC-001",
    category=ThreatCategory.CODE_EXECUTION,
    severity=Severity.CRITICAL,
    title="eval/exec with potentially user-controllable input",
    description="eval() or exec() called with dynamic/user-controllable arguments.",
    recommendation="Replace eval/exec with structured parsing or dispatch.",
    targets=(TargetType.SCRIPT,),
    engine="ast",
))

# SR-EXEC-002: shell=True with variable injection (ast engine)
register(Rule(
    rule_id="SR-EXEC-002",
    category=ThreatCategory.CODE_EXECUTION,
    severity=Severity.HIGH,
    title="subprocess with shell=True and dynamic command",
    description="Using subprocess with shell=True and dynamically constructed commands.",
    recommendation="Use argument lists instead of shell=True with string commands.",
    targets=(TargetType.SCRIPT,),
    engine="ast",
))

# SR-EXEC-003: Download and execute pattern (regex engine)
register(Rule(
    rule_id="SR-EXEC-003",
    category=ThreatCategory.CODE_EXECUTION,
    severity=Severity.CRITICAL,
    title="Download-and-execute pattern",
    description="Downloading content from the internet and immediately executing it.",
    recommendation="Avoid piping remote content directly into interpreters.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\bcurl\b[^\n|]{0,200}\|\s*(?:sh|bash|zsh|pwsh|powershell|python)\b",
    r"\bwget\b[^\n|]{0,200}\|\s*(?:sh|bash|zsh|python)\b",
    r"\bInvoke-WebRequest\b[^\n|]{0,200}\|\s*Invoke-Expression\b",
    r"\bIEX\s*\(\s*(?:New-Object\s+Net\.WebClient\)|Invoke-WebRequest)",
    r"(?:requests\.get|urllib\.request\.urlopen|httpx\.get)\s*\([^)]+\).*(?:eval|exec)\s*\(",
    r"(?:eval|exec)\s*\(.*(?:requests\.get|urllib\.request\.urlopen|httpx\.get)\s*\(",
])

# SR-EXEC-004: Dynamic import from untrusted source (ast engine)
register(Rule(
    rule_id="SR-EXEC-004",
    category=ThreatCategory.CODE_EXECUTION,
    severity=Severity.HIGH,
    title="Dynamic import from untrusted source",
    description="Using __import__() or importlib with dynamic/untrusted module names.",
    recommendation="Use static imports or validated importlib.import_module().",
    targets=(TargetType.SCRIPT,),
    engine="ast",
))
