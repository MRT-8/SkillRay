"""SR-MCP-xxx: MCP (Model Context Protocol) specific threat rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-MCP-001: Cross-tool shadowing in tool descriptions
register(Rule(
    rule_id="SR-MCP-001",
    category=ThreatCategory.MCP_THREAT,
    severity=Severity.CRITICAL,
    title="Cross-tool shadowing in tool description",
    description="Tool description attempts to alter behavior of other tools — a tool poisoning attack.",
    recommendation="Tool descriptions must only describe their own functionality.",
    targets=(TargetType.MCP_CONFIG, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="prompt",
))

# SR-MCP-002: Suspicious MCP server URL (non-HTTPS, excluding localhost)
register(Rule(
    rule_id="SR-MCP-002",
    category=ThreatCategory.MCP_THREAT,
    severity=Severity.HIGH,
    title="Non-HTTPS MCP server URL (excluding localhost)",
    description="MCP config uses HTTP instead of HTTPS for a non-local server, risking MITM attacks.",
    recommendation="Use HTTPS for all non-local MCP server connections.",
    targets=(TargetType.MCP_CONFIG, TargetType.CONFIG, TargetType.ANY),
    engine="regex",
), patterns=[
    r"[\"']http://(?!localhost\b|127\.0\.0\.1\b|\[::1\]\b|0\.0\.0\.0\b)[a-zA-Z0-9]",
])

# SR-MCP-003: Dangerous MCP configuration flags
register(Rule(
    rule_id="SR-MCP-003",
    category=ThreatCategory.MCP_THREAT,
    severity=Severity.HIGH,
    title="Dangerous MCP configuration flag",
    description="MCP config enables dangerous flags that bypass security controls.",
    recommendation="Remove overly permissive MCP configuration flags.",
    targets=(TargetType.MCP_CONFIG, TargetType.CONFIG, TargetType.ANY),
    engine="regex",
), patterns=[
    r"\benableAllProjectMcpServers\b",
    r"\ballowAllTools\b",
    r"\bdangerouslyDisableSandbox\b",
    r"\bdangerouslySkipPermissions\b",
    r"\btrust[_-]?all[_-]?tools\b",
])

# SR-MCP-004: Command injection in MCP config
register(Rule(
    rule_id="SR-MCP-004",
    category=ThreatCategory.MCP_THREAT,
    severity=Severity.HIGH,
    title="Potential command injection in MCP configuration",
    description="Shell metacharacters in MCP server command or args fields suggest command injection.",
    recommendation="MCP server commands should not contain shell metacharacters.",
    targets=(TargetType.MCP_CONFIG, TargetType.CONFIG),
    engine="regex",
), patterns=[
    r"\"(?:command|args)\"[^}]*(?:\|\||&&|;\s*\w|\$\(|`[^`]+`)",
    r"\"args\"\s*:\s*\[[^\]]*(?:\|\||&&|;\s*\w|\$\(|`[^`]+`)",
])

# SR-MCP-005: Unpinned MCP server version (rug pull risk)
register(Rule(
    rule_id="SR-MCP-005",
    category=ThreatCategory.MCP_THREAT,
    severity=Severity.MEDIUM,
    title="Unpinned MCP server version (rug pull risk)",
    description="MCP server installed without version pinning, allowing silent malicious updates.",
    recommendation="Pin MCP server versions: use npx package@version or uvx package==version.",
    targets=(TargetType.MCP_CONFIG, TargetType.CONFIG, TargetType.ANY),
    engine="regex",
), patterns=[
    r'"npx".*"-y".*"(?!.*@\d)[a-zA-Z][a-zA-Z0-9._-]+"',
    r'"uvx".*"(?!.*[=><]\d)[a-zA-Z][a-zA-Z0-9._-]+"',
    r"\bnpx\s+-y\s+(?!.*@\d)\S+",
    r"\buvx\s+(?!.*[=><]\d)\S+",
])
