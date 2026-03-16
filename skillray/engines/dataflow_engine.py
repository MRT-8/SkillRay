"""Lightweight taint tracking engine for data exfiltration detection."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from .base import BaseEngine
from ..models import Finding, TargetType, Severity, ThreatCategory

# Sources: sensitive data reads
_SOURCE_PATTERNS = [
    re.compile(r"""open\s*\(\s*['"].*(?:\.env|id_rsa|\.ssh|passwd|credentials|\.aws|\.config)""", re.IGNORECASE),
    re.compile(r"""\bos\.environ\b"""),
    re.compile(r"""\bos\.getenv\b"""),
    re.compile(r"""subprocess\..*\(\s*['"](?:cat|type)\s+.*(?:\.env|id_rsa|passwd)""", re.IGNORECASE),
    re.compile(r"""\bkeyring\.\w+\b"""),
    re.compile(r"""\bgetpass\.\w+\b"""),
]

# Sinks: network send operations
_SINK_PATTERNS = [
    re.compile(r"""\brequests\.(?:post|put|patch|get)\s*\(""", re.IGNORECASE),
    re.compile(r"""\bhttpx\.(?:post|put|patch|get)\s*\(""", re.IGNORECASE),
    re.compile(r"""\burllib\.request\.urlopen\s*\(""", re.IGNORECASE),
    re.compile(r"""\baiohttp\.\w*\.(?:post|put|get)\s*\(""", re.IGNORECASE),
    re.compile(r"""\bcurl\b""", re.IGNORECASE),
    re.compile(r"""\bwget\b""", re.IGNORECASE),
    re.compile(r"""\bsocket\..*\.(?:send|connect)\b""", re.IGNORECASE),
    re.compile(r"""\bsmtplib\b""", re.IGNORECASE),
]

# Bulk file enumeration patterns
_BULK_ENUM_PATTERNS = [
    re.compile(r"""\bos\.walk\s*\("""),
    re.compile(r"""\bglob\.glob\s*\("""),
    re.compile(r"""\bPath\s*\(.*\)\.rglob\b"""),
    re.compile(r"""\bos\.listdir\s*\("""),
    re.compile(r"""\bfind\s+-type\s+f\b"""),
]

# Archive/pack patterns
_PACK_PATTERNS = [
    re.compile(r"""\btarfile\b"""),
    re.compile(r"""\bzipfile\b"""),
    re.compile(r"""\bshutil\.make_archive\b"""),
    re.compile(r"""\btar\s+(?:czf|cf)\b"""),
    re.compile(r"""\bzip\b.*\b-r\b"""),
]

# DNS exfiltration
_DNS_EXFIL_PATTERNS = [
    re.compile(r"""\bsocket\.getaddrinfo\b"""),
    re.compile(r"""\bdnspython\b"""),
    re.compile(r"""\bnslookup\b"""),
    re.compile(r"""\bdig\s+"""),
    re.compile(r"""\bresolver\.query\b"""),
]

# Clipboard capture
_CLIPBOARD_PATTERNS = [
    re.compile(r"""\bpyperclip\b"""),
    re.compile(r"""\btkinter\..*clipboard_get\b"""),
    re.compile(r"""\bxclip\b"""),
    re.compile(r"""\bpbpaste\b"""),
    re.compile(r"""\bGet-Clipboard\b""", re.IGNORECASE),
]


class DataflowEngine(BaseEngine):
    name = "dataflow"

    def scan(self, file_path: Path, content: str, target: TargetType) -> list[Finding]:
        if target not in (TargetType.SCRIPT, TargetType.ANY):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        sources: list[tuple[int, str]] = []
        sinks: list[tuple[int, str]] = []
        bulk_enum: list[tuple[int, str]] = []
        pack_ops: list[tuple[int, str]] = []
        dns_ops: list[tuple[int, str]] = []
        clipboard_ops: list[tuple[int, str]] = []

        for line_no, line_text in enumerate(lines, start=1):
            for p in _SOURCE_PATTERNS:
                if p.search(line_text):
                    sources.append((line_no, line_text.strip()))
                    break
            for p in _SINK_PATTERNS:
                if p.search(line_text):
                    sinks.append((line_no, line_text.strip()))
                    break
            for p in _BULK_ENUM_PATTERNS:
                if p.search(line_text):
                    bulk_enum.append((line_no, line_text.strip()))
                    break
            for p in _PACK_PATTERNS:
                if p.search(line_text):
                    pack_ops.append((line_no, line_text.strip()))
                    break
            for p in _DNS_EXFIL_PATTERNS:
                if p.search(line_text):
                    dns_ops.append((line_no, line_text.strip()))
                    break
            for p in _CLIPBOARD_PATTERNS:
                if p.search(line_text):
                    clipboard_ops.append((line_no, line_text.strip()))
                    break

        # SR-EXFIL-002: Bulk enumeration + pack + upload
        if bulk_enum and pack_ops and sinks:
            findings.append(Finding(
                rule_id="SR-EXFIL-002",
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=Severity.HIGH,
                title="Bulk file enumeration + archive + network upload",
                file=str(file_path),
                line=sinks[0][0],
                evidence=f"enum@L{bulk_enum[0][0]}, pack@L{pack_ops[0][0]}, send@L{sinks[0][0]}",
                recommendation="Avoid bulk file collection combined with network transmission.",
                engine=self.name,
            ))

        # SR-EXFIL-003: DNS exfiltration
        if sources and dns_ops:
            findings.append(Finding(
                rule_id="SR-EXFIL-003",
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=Severity.HIGH,
                title="Potential DNS exfiltration pattern",
                file=str(file_path),
                line=dns_ops[0][0],
                evidence=f"source@L{sources[0][0]}, dns@L{dns_ops[0][0]}",
                recommendation="DNS-based data exfiltration detected. Review DNS query construction.",
                engine=self.name,
            ))

        # SR-EXFIL-004: Clipboard capture + network send
        if clipboard_ops and sinks:
            findings.append(Finding(
                rule_id="SR-EXFIL-004",
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=Severity.HIGH,
                title="Clipboard/stdin capture with network transmission",
                file=str(file_path),
                line=clipboard_ops[0][0],
                evidence=f"clipboard@L{clipboard_ops[0][0]}, send@L{sinks[0][0]}",
                recommendation="Clipboard access combined with network sends is suspicious.",
                engine=self.name,
            ))

        # Env var bulk collection + send
        env_collect = [s for s in sources if "environ" in s[1].lower() or "getenv" in s[1].lower()]
        if env_collect and sinks:
            findings.append(Finding(
                rule_id="SR-CRED-002",
                category=ThreatCategory.CREDENTIAL_THEFT,
                severity=Severity.HIGH,
                title="Environment variable collection with network transmission",
                file=str(file_path),
                line=env_collect[0][0],
                evidence=f"env@L{env_collect[0][0]}, send@L{sinks[0][0]}",
                recommendation="Avoid collecting environment variables and sending them over the network.",
                engine=self.name,
            ))

        return findings
