"""Regex-based pattern matching engine."""

from __future__ import annotations

import re
from pathlib import Path

from .base import BaseEngine
from ..models import Finding, TargetType, Severity, ThreatCategory
from ..rules import registry


class RegexEngine(BaseEngine):
    name = "regex"

    def scan(self, file_path: Path, content: str, target: TargetType) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        rules = registry.get_rules_for_engine(self.name, target)

        for rule in rules:
            patterns = registry.get_patterns(rule.rule_id)
            if not patterns:
                continue
            compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]
            seen_lines: set[int] = set()
            for line_no, line_text in enumerate(lines, start=1):
                for regex in compiled:
                    if regex.search(line_text):
                        if line_no not in seen_lines:
                            seen_lines.add(line_no)
                            findings.append(Finding(
                                rule_id=rule.rule_id,
                                category=rule.category,
                                severity=rule.severity,
                                title=rule.title,
                                file=str(file_path),
                                line=line_no,
                                evidence=line_text.strip()[:240],
                                recommendation=rule.recommendation,
                                engine=self.name,
                            ))
                        break

        # Cross-line pattern: sensitive file read + network send
        self._check_dataflow_patterns(file_path, lines, target, findings)
        return findings

    def _check_dataflow_patterns(
        self, file_path: Path, lines: list[str], target: TargetType, findings: list[Finding]
    ) -> None:
        if target not in (TargetType.SCRIPT, TargetType.ANY):
            return

        sensitive_re = re.compile(
            r"(?:/etc/passwd|id_rsa|\.env|\.ssh|aws_credentials|\.aws/credentials)",
            re.IGNORECASE,
        )
        read_re = re.compile(r"(?:open\s*\(|\bread\s*\(|\bcat\b|\btype\b)", re.IGNORECASE)
        network_re = re.compile(
            r"(?:requests\.(?:post|put|get)|urllib\.request|httpx\.|"
            r"curl\b|wget\b|Invoke-WebRequest|Invoke-RestMethod|"
            r"socket\.connect|aiohttp)",
            re.IGNORECASE,
        )

        sensitive_line = None
        sensitive_evidence = ""
        network_line = None
        network_evidence = ""

        for line_no, line_text in enumerate(lines, start=1):
            if sensitive_line is None:
                if sensitive_re.search(line_text) and read_re.search(line_text):
                    sensitive_line = line_no
                    sensitive_evidence = line_text.strip()
            if network_line is None and network_re.search(line_text):
                network_line = line_no
                network_evidence = line_text.strip()

        if sensitive_line is not None and network_line is not None:
            findings.append(Finding(
                rule_id="SR-EXFIL-001",
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=Severity.CRITICAL,
                title="Sensitive file read combined with network send",
                file=str(file_path),
                line=network_line,
                evidence=f"{sensitive_evidence} || {network_evidence}"[:240],
                recommendation="Do not couple secret file reads with outbound requests.",
                engine=self.name,
            ))
