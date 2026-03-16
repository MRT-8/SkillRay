"""Prompt injection heuristic detection engine for markdown/skill files."""

from __future__ import annotations

import base64
import re
import unicodedata
from pathlib import Path

from .base import BaseEngine
from ..models import Finding, TargetType, Severity, ThreatCategory

# SR-PROMPT-001: Hidden instructions in HTML comments
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_INJECTION_KEYWORDS = re.compile(
    r"(?:ignore\s+(?:previous|all|above)|forget\s+(?:previous|all|your)|"
    r"disregard|override|new\s+instructions?|system\s+prompt|"
    r"you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you)|"
    r"do\s+not\s+follow|bypass|jailbreak|unlock)",
    re.IGNORECASE,
)

# SR-PROMPT-002: Role override attempts
_ROLE_OVERRIDE_RE = re.compile(
    r"(?:you\s+are\s+now\s+|ignore\s+all\s+previous\s+|forget\s+(?:everything|all)\s+|"
    r"from\s+now\s+on\s+you\s+|new\s+system\s+prompt\s*:|"
    r"SYSTEM:\s*|<\|system\|>|"
    r"\[SYSTEM\]|\[INST\]|<<SYS>>|"
    r"override\s+(?:all\s+)?(?:instructions?|rules?|guidelines?)|"
    r"disregard\s+(?:all\s+)?(?:previous|prior|above))",
    re.IGNORECASE,
)

# SR-PROMPT-003: Invisible Unicode characters
_INVISIBLE_CHARS = {
    "\u200b": "Zero-Width Space",
    "\u200c": "Zero-Width Non-Joiner",
    "\u200d": "Zero-Width Joiner",
    "\u2060": "Word Joiner",
    "\u2061": "Function Application",
    "\u2062": "Invisible Times",
    "\u2063": "Invisible Separator",
    "\u2064": "Invisible Plus",
    "\ufeff": "Zero-Width No-Break Space",
    "\u200e": "LTR Mark",
    "\u200f": "RTL Mark",
    "\u202a": "LTR Embedding",
    "\u202b": "RTL Embedding",
    "\u202c": "Pop Directional",
    "\u202d": "LTR Override",
    "\u202e": "RTL Override",
    "\u2066": "LTR Isolate",
    "\u2067": "RTL Isolate",
    "\u2068": "First Strong Isolate",
    "\u2069": "Pop Directional Isolate",
    "\u00ad": "Soft Hyphen",
    "\u034f": "Combining Grapheme Joiner",
    "\u061c": "Arabic Letter Mark",
    "\u180e": "Mongolian Vowel Separator",
}

# SR-PROMPT-004: Base64 encoded instructions
_BASE64_RE = re.compile(r"(?:base64[_\s]*decode|atob|b64decode)\s*\(\s*['\"]([A-Za-z0-9+/=]{20,})['\"]")
_INLINE_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

# SR-PROMPT-005: External content fetch with injection risk
_FETCH_INJECT_RE = re.compile(
    r"(?:fetch|curl|wget|requests\.get|urllib\.request\.urlopen|httpx\.get)\s*\("
    r"[^)]*(?:user|input|param|query|url|arg)",
    re.IGNORECASE,
)

# SR-TOOL-001: Tool description with hidden behavior
_TOOL_HIDDEN_BEHAVIOR_RE = re.compile(
    r"(?:<!--.*?(?:also|secretly|silently|additionally|before|after)\s+(?:run|execute|send|read|write|delete).*?-->|"
    r"description.*?(?:also|secretly|silently|additionally)\s+(?:run|execute|send|read|write|delete))",
    re.IGNORECASE | re.DOTALL,
)

# SR-TOOL-002: Tool parameters suggesting unauthorized access
_TOOL_OVERREACH_RE = re.compile(
    r"(?:admin|root|sudo|superuser|elevated|bypass|override|unrestricted)\s*(?:access|permission|privilege|mode|role)",
    re.IGNORECASE,
)

# SR-TOOL-003: MCP tool definition override
_MCP_OVERRIDE_RE = re.compile(
    r"(?:override|replace|modify|change)\s+(?:the\s+)?(?:security|safety|permission|access)\s+(?:check|constraint|rule|policy|setting)",
    re.IGNORECASE,
)

# Homoglyph detection
_LATIN_HOMOGLYPHS = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    "\u03bf": "o", "\u03b1": "a",  # Greek
}


class PromptEngine(BaseEngine):
    name = "prompt"

    def scan(self, file_path: Path, content: str, target: TargetType) -> list[Finding]:
        findings: list[Finding] = []
        fname = str(file_path).lower()
        is_md = fname.endswith(".md") or target in (TargetType.SKILL_MD, TargetType.MARKDOWN)

        lines = content.splitlines()

        # SR-PROMPT-001: Hidden instructions in HTML comments
        for match in _HTML_COMMENT_RE.finditer(content):
            comment_text = match.group(1)
            if _INJECTION_KEYWORDS.search(comment_text):
                # Find line number
                line_no = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    rule_id="SR-PROMPT-001",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    title="Hidden instruction in HTML comment",
                    file=str(file_path),
                    line=line_no,
                    evidence=match.group(0)[:240],
                    recommendation="Remove hidden instructions from markdown comments.",
                    engine=self.name,
                ))

        # SR-PROMPT-002: Role override attempts
        for line_no, line_text in enumerate(lines, start=1):
            if _ROLE_OVERRIDE_RE.search(line_text):
                findings.append(Finding(
                    rule_id="SR-PROMPT-002",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    title="Role override / instruction injection attempt",
                    file=str(file_path),
                    line=line_no,
                    evidence=line_text.strip()[:240],
                    recommendation="Remove prompt injection attempts that try to override AI behavior.",
                    engine=self.name,
                ))

        # SR-PROMPT-003: Invisible Unicode characters
        for line_no, line_text in enumerate(lines, start=1):
            found_invisible: list[str] = []
            for char in line_text:
                if char in _INVISIBLE_CHARS:
                    found_invisible.append(f"U+{ord(char):04X} ({_INVISIBLE_CHARS[char]})")
            # Also check for homoglyphs
            found_homoglyphs: list[str] = []
            for char in line_text:
                if char in _LATIN_HOMOGLYPHS:
                    found_homoglyphs.append(
                        f"U+{ord(char):04X}→{_LATIN_HOMOGLYPHS[char]}"
                    )
            if found_invisible:
                findings.append(Finding(
                    rule_id="SR-PROMPT-003",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    title="Invisible Unicode characters detected",
                    file=str(file_path),
                    line=line_no,
                    evidence=", ".join(found_invisible[:5]),
                    recommendation="Remove invisible/zero-width Unicode characters that could hide instructions.",
                    engine=self.name,
                ))
            if found_homoglyphs:
                findings.append(Finding(
                    rule_id="SR-OBFUSC-004",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Unicode homoglyph characters detected",
                    file=str(file_path),
                    line=line_no,
                    evidence=", ".join(found_homoglyphs[:5]),
                    recommendation="Replace homoglyph characters with their ASCII equivalents.",
                    engine=self.name,
                ))

        # SR-PROMPT-004: Base64 encoded instructions
        for line_no, line_text in enumerate(lines, start=1):
            for m in _BASE64_RE.finditer(line_text):
                b64_str = m.group(1)
                try:
                    decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                    if _INJECTION_KEYWORDS.search(decoded):
                        findings.append(Finding(
                            rule_id="SR-PROMPT-004",
                            category=ThreatCategory.PROMPT_INJECTION,
                            severity=Severity.HIGH,
                            title="Base64-encoded instruction detected",
                            file=str(file_path),
                            line=line_no,
                            evidence=f"Decoded: {decoded[:120]}",
                            recommendation="Remove encoded instructions from skill definitions.",
                            engine=self.name,
                        ))
                except Exception:
                    pass

        # SR-PROMPT-005: External content fetch with injection risk (in md files)
        if is_md:
            for line_no, line_text in enumerate(lines, start=1):
                if _FETCH_INJECT_RE.search(line_text):
                    findings.append(Finding(
                        rule_id="SR-PROMPT-005",
                        category=ThreatCategory.PROMPT_INJECTION,
                        severity=Severity.HIGH,
                        title="External content fetch with user-controlled input (injection risk)",
                        file=str(file_path),
                        line=line_no,
                        evidence=line_text.strip()[:240],
                        recommendation="Validate and sanitize URLs before fetching external content.",
                        engine=self.name,
                    ))

        # SR-TOOL-001: Tool description with hidden behavior
        for m in _TOOL_HIDDEN_BEHAVIOR_RE.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            findings.append(Finding(
                rule_id="SR-TOOL-001",
                category=ThreatCategory.TOOL_POISONING,
                severity=Severity.CRITICAL,
                title="Tool description contains hidden behavior instructions",
                file=str(file_path),
                line=line_no,
                evidence=m.group(0)[:240],
                recommendation="Tool descriptions should only describe their stated functionality.",
                engine=self.name,
            ))

        # SR-TOOL-002: Tool parameters suggesting unauthorized access
        if is_md:
            for line_no, line_text in enumerate(lines, start=1):
                if _TOOL_OVERREACH_RE.search(line_text):
                    findings.append(Finding(
                        rule_id="SR-TOOL-002",
                        category=ThreatCategory.TOOL_POISONING,
                        severity=Severity.HIGH,
                        title="Tool parameter suggests unauthorized access level",
                        file=str(file_path),
                        line=line_no,
                        evidence=line_text.strip()[:240],
                        recommendation="Tools should not request elevated privileges beyond their scope.",
                        engine=self.name,
                    ))

        # SR-TOOL-003: MCP tool definition override
        if is_md:
            for line_no, line_text in enumerate(lines, start=1):
                if _MCP_OVERRIDE_RE.search(line_text):
                    findings.append(Finding(
                        rule_id="SR-TOOL-003",
                        category=ThreatCategory.TOOL_POISONING,
                        severity=Severity.CRITICAL,
                        title="MCP tool definition attempts to override security constraints",
                        file=str(file_path),
                        line=line_no,
                        evidence=line_text.strip()[:240],
                        recommendation="Tool definitions must not override security policies.",
                        engine=self.name,
                    ))

        return findings
