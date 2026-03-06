from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from .models import Finding, Rule, RuleMatch, TargetType


def _regex_matcher(patterns: Sequence[str]):
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

    def match(_: Path, __: str, lines: Sequence[str]) -> list[RuleMatch]:
        results: list[RuleMatch] = []
        seen_lines: set[int] = set()
        for line_no, line in enumerate(lines, start=1):
            for regex in compiled:
                if regex.search(line):
                    if line_no not in seen_lines:
                        seen_lines.add(line_no)
                        results.append(RuleMatch(line=line_no, evidence=line.strip()[:240]))
                    break
        return results

    return match


_SENSITIVE_DATA_PATTERN = re.compile(
    r"(?:/etc/passwd|id_rsa|\.env|\.ssh|aws_credentials)",
    re.IGNORECASE,
)
_READ_OP_PATTERN = re.compile(r"(?:open\s*\(|\bcat\b|\btype\b)", re.IGNORECASE)
_NETWORK_PATTERN = re.compile(
    r"(?:requests\.(?:post|put|get)|urllib\.request|httpx\.(?:post|put|get)|"
    r"curl\b|wget\b|Invoke-WebRequest|Invoke-RestMethod)",
    re.IGNORECASE,
)


def _sensitive_and_network_matcher(_: Path, __: str, lines: Sequence[str]) -> list[RuleMatch]:
    sensitive_line: int | None = None
    sensitive_evidence = ""
    network_line: int | None = None
    network_evidence = ""

    for line_no, line in enumerate(lines, start=1):
        if sensitive_line is None:
            if _SENSITIVE_DATA_PATTERN.search(line) and _READ_OP_PATTERN.search(line):
                sensitive_line = line_no
                sensitive_evidence = line.strip()
        if network_line is None and _NETWORK_PATTERN.search(line):
            network_line = line_no
            network_evidence = line.strip()

    if sensitive_line is None or network_line is None:
        return []

    evidence = f"{sensitive_evidence} || {network_evidence}"[:240]
    return [RuleMatch(line=network_line, evidence=evidence)]


_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="SR-SKILL-001",
        target="skill_md",
        description="Potentially destructive filesystem command in SKILL.md",
        severity="High",
        recommendation="Avoid destructive commands and require explicit human confirmation paths.",
        matcher=_regex_matcher(
            (
                r"\brm\s+-rf\b",
                r"\bdel\s+/[sqf]",
                r"\bRemove-Item\b[^\n]*-Recurse[^\n]*-Force",
                r"\bmkfs\.",
                r"\bdd\s+if=",
                r"\bformat\s+[A-Za-z]:",
            )
        ),
    ),
    Rule(
        rule_id="SR-SKILL-002",
        target="skill_md",
        description="Download-and-execute command pattern in SKILL.md",
        severity="High",
        recommendation="Avoid piping remote content directly into interpreters.",
        matcher=_regex_matcher(
            (
                r"\bcurl\b[^\n|]{0,200}\|\s*(?:sh|bash|zsh|pwsh|powershell)\b",
                r"\bwget\b[^\n|]{0,200}\|\s*(?:sh|bash|zsh)\b",
                r"\bInvoke-WebRequest\b[^\n|]{0,200}\|\s*Invoke-Expression\b",
                r"\bIEX\s*\(\s*New-Object\s+Net\.WebClient\)\.DownloadString",
            )
        ),
    ),
    Rule(
        rule_id="SR-SKILL-003",
        target="skill_md",
        description="Privilege escalation or security-bypass guidance in SKILL.md",
        severity="High",
        recommendation="Document least-privilege alternatives and avoid bypass instructions.",
        matcher=_regex_matcher(
            (
                r"\bSet-ExecutionPolicy\b[^\n]*\bBypass\b",
                r"\bsudo\s+",
                r"\bRun\s+as\s+Administrator\b",
                r"\bdisable(?:d)?\b[^\n]{0,40}\b(?:defender|firewall|antivirus)\b",
                r"\b--no-sandbox\b",
            )
        ),
    ),
    Rule(
        rule_id="SR-SKILL-004",
        target="skill_md",
        description="Possible sensitive data exfiltration command in SKILL.md",
        severity="High",
        recommendation="Do not include commands that move secrets or local sensitive files externally.",
        matcher=_regex_matcher(
            (
                r"\b(?:cat|type)\b[^\n]*(?:\.env|id_rsa|\.ssh|/etc/passwd)",
                r"\bcurl\b[^\n]*\s(?:--data|-d)\s+@",
                r"\b(?:scp|rsync)\b[^\n]*(?:\.env|id_rsa|\.ssh|/etc/passwd)",
                r"\bInvoke-RestMethod\b[^\n]*(?:\.env|id_rsa|\.ssh|/etc/passwd)",
            )
        ),
    ),
    Rule(
        rule_id="SR-SCRIPT-001",
        target="script",
        description="Potential shell command execution in script",
        severity="High",
        recommendation="Prefer safe argument arrays and avoid shell-mediated execution.",
        matcher=_regex_matcher(
            (
                r"\bos\.system\s*\(",
                r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^\n]*\bshell\s*=\s*True\b",
                r"\bsubprocess\.getoutput\s*\(",
            )
        ),
    ),
    Rule(
        rule_id="SR-SCRIPT-002",
        target="script",
        description="Dynamic code execution primitive in script",
        severity="High",
        recommendation="Replace eval/exec-style constructs with structured parsing or dispatch.",
        matcher=_regex_matcher(
            (
                r"(?<!literal_)eval\s*\(",
                r"\bexec\s*\(",
                r"\bInvoke-Expression\b",
                r"\bIEX\b",
            )
        ),
    ),
    Rule(
        rule_id="SR-SCRIPT-003",
        target="script",
        description="Command built dynamically before execution",
        severity="Medium",
        recommendation="Build command tokens explicitly and avoid runtime string concatenation for commands.",
        matcher=_regex_matcher(
            (
                r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*f[\"']",
                r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^,\n]*\+\s*",
                r"\bos\.system\s*\([^,\n]*\+\s*",
            )
        ),
    ),
    Rule(
        rule_id="SR-SCRIPT-004",
        target="script",
        description="Sensitive file access combined with outbound network call",
        severity="High",
        recommendation="Do not couple secret file reads with outbound requests.",
        matcher=_sensitive_and_network_matcher,
    ),
)


def get_rules_for_target(target: TargetType) -> list[Rule]:
    return [rule for rule in _RULES if rule.target == target]


def run_rules_for_content(target: TargetType, file_path: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []

    for rule in get_rules_for_target(target):
        matches = rule.matcher(Path(file_path), text, lines)
        for match in matches:
            findings.append(
                Finding(
                    id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.description,
                    file=file_path,
                    line=match.line,
                    evidence=match.evidence,
                    recommendation=rule.recommendation,
                )
            )

    return findings
