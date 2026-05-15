"""SR-PERSIST-xxx: Persistence and backdoor mechanism rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-PERSIST-001: Agent memory/config poisoning (CLAUDE.md, .claude/ writes)
register(Rule(
    rule_id="SR-PERSIST-001",
    category=ThreatCategory.PERSISTENCE,
    severity=Severity.CRITICAL,
    title="Agent memory or config poisoning",
    description="Writes to CLAUDE.md, .claude/ config, or agent memory files to persist across sessions.",
    recommendation="Skills should not modify agent configuration or memory files.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r"(?:write|append|echo|cat|tee)\s*.*(?:>>|>)\s*.*CLAUDE\.md",
    r">>?\s*.*CLAUDE\.md",
    r"(?:write|modify|append|update).*\.claude/",
    r"(?:write|append|echo).*(?:>>|>)\s*.*\.claude/(?:settings|memory|rules)",
    r"open\s*\(\s*['\"].*CLAUDE\.md['\"].*['\"](?:w|a)",
    r"(?:write|modify|inject|insert|append).*(?:CLAUDE\.md|agent.*memory|\.claude.*config)",
])

# SR-PERSIST-002: SSH authorized_keys injection
register(Rule(
    rule_id="SR-PERSIST-002",
    category=ThreatCategory.PERSISTENCE,
    severity=Severity.CRITICAL,
    title="SSH authorized_keys injection",
    description="Appending SSH public keys to authorized_keys for persistent remote access.",
    recommendation="Do not modify SSH authorized_keys. Use proper access management.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r">>?\s*.*authorized_keys",
    r"\bssh-copy-id\b",
    r"echo\s+.*(?:ssh-rsa|ssh-ed25519|ecdsa).*>>?\s*.*authorized_keys",
    r"(?:append|add|write).*authorized_keys",
])

# SR-PERSIST-003: Cron job / scheduled task creation
# Context-aware: downgrade to MEDIUM in deploy/ops/infra paths
register(Rule(
    rule_id="SR-PERSIST-003",
    category=ThreatCategory.PERSISTENCE,
    severity=Severity.HIGH,
    title="Scheduled task or cron job creation",
    description="Creates cron jobs, systemd services, or scheduled tasks for persistent execution.",
    recommendation="Review scheduled task creation. Ensure it serves a legitimate purpose.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r"\bcrontab\s+(?!-[lr]\b)",
    r"/etc/cron\.(?:d|daily|hourly|weekly|monthly)/",
    r"\bschtasks\s+/create\b",
    r"\bsystemctl\s+(?:enable|start)\b",
    r"\blaunchctl\s+(?:load|submit)\b",
])

# SR-PERSIST-004: Git credential helper manipulation
register(Rule(
    rule_id="SR-PERSIST-004",
    category=ThreatCategory.PERSISTENCE,
    severity=Severity.HIGH,
    title="Git credential helper manipulation",
    description="Modifying git credential helpers to intercept or steal authentication tokens.",
    recommendation="Do not modify git credential configuration programmatically.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"\bgit\s+config\s+.*credential\.helper\b",
    r"\bgit\s+config\s+.*credential\b.*store",
    r"\bgit-credential-\w+",
    r"\.gitconfig.*credential",
])

# SR-PERSIST-005: Shell profile modification
register(Rule(
    rule_id="SR-PERSIST-005",
    category=ThreatCategory.PERSISTENCE,
    severity=Severity.HIGH,
    title="Shell profile modification for persistence",
    description="Appending to shell profile files (.bashrc, .zshrc, .profile) for persistent code execution.",
    recommendation="Do not modify user shell profiles. Use proper installation mechanisms.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD, TargetType.MARKDOWN),
    engine="regex",
), patterns=[
    r">>?\s*.*\.bashrc",
    r">>?\s*.*\.zshrc",
    r">>?\s*.*\.profile",
    r">>?\s*.*\.bash_profile",
    r"(?:echo|cat|tee)\s+.*>>?\s*.*(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)",
])

# SR-PERSIST-006: Startup item / autorun installation
register(Rule(
    rule_id="SR-PERSIST-006",
    category=ThreatCategory.PERSISTENCE,
    severity=Severity.MEDIUM,
    title="Startup item or autorun installation",
    description="Installing startup items, launch agents, or registry autorun entries.",
    recommendation="Review startup item installation for legitimacy.",
    targets=(TargetType.SCRIPT, TargetType.SKILL_MD),
    engine="regex",
), patterns=[
    r"~/\.config/autostart/",
    r"\bLaunchAgents?\b.*\.plist",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"/etc/init\.d/",
    r"/etc/systemd/system/.*\.service",
])
