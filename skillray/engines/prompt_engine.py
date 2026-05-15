"""Prompt injection heuristic detection engine for markdown/skill files."""

from __future__ import annotations

import base64
import json
import re
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

# SR-PROMPT-008: ANSI escape sequences
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[\d;]*[a-zA-Z]")

# SR-STEALTH-001: Secrecy instructions
_SECRECY_RE = re.compile(
    r"(?:do\s+not\s+(?:tell|inform|show|reveal|mention|display|report)\s+.*(?:user|human|operator|person)|"
    r"keep\s+(?:this|it|the\s+\w+)\s+hidden|"
    r"never\s+(?:reveal|disclose|show|mention)|"
    r"hide\s+(?:this|the|from\s+the\s+user)|"
    r"(?:must|should)\s+not\s+(?:be\s+)?(?:visible|shown|displayed|revealed)\s+to)",
    re.IGNORECASE,
)

# SR-STEALTH-002: Output suppression
_OUTPUT_SUPPRESS_RE = re.compile(
    r"(?:(?:execute|run|perform|do)\s+.*\bsilently\b|"
    r"without\s+(?:informing|telling|notifying|showing|alerting)\s+(?:the\s+)?(?:user|human|operator)|"
    r"suppress\s+(?:the\s+)?(?:output|display|notification)|"
    r"do\s+not\s+(?:display|print|output|log)\s+(?:the\s+)?(?:result|output|action))",
    re.IGNORECASE,
)

# SR-STEALTH-004: Error suppression instructions
_ERROR_SUPPRESS_RE = re.compile(
    r"(?:(?:ignore|suppress|swallow|discard)\s+(?:all\s+)?(?:error|exception|failure)|"
    r"do\s+not\s+(?:report|raise|throw|show)\s+(?:any\s+)?(?:error|exception|failure)|"
    r"(?:silent|quiet)\s+(?:fail|error|mode))",
    re.IGNORECASE,
)

# SR-STEALTH-005: Anti-detection instructions
_ANTI_DETECT_RE = re.compile(
    r"(?:avoid\s+(?:detection|scanning|monitoring|analysis)|"
    r"bypass\s+(?:the\s+)?(?:scan|security|monitor|filter|check)|"
    r"evade\s+(?:the\s+)?(?:monitor|scanner|detection|analysis)|"
    r"disable\s+(?:the\s+)?(?:logging|monitoring|audit|tracking)|"
    r"anti[_\-\s]?(?:virus|forensic|debug|analysis))",
    re.IGNORECASE,
)

# SR-MCP-001: Cross-tool shadowing (bounded to prevent ReDoS)
_TOOL_SHADOW_RE = re.compile(
    r"(?:when\s+(?:using|calling|invoking)\s+\w+.{0,200}(?:instead|also|first|before|after)\s+(?:run|execute|call|send|use)|"
    r"(?:override|replace|intercept|redirect|hijack)\s+(?:the\s+)?(?:behavior|output|result|response)\s+of\s+\w+|"
    r"(?:before|after|instead\s+of)\s+(?:calling|using|invoking)\s+\w+\s*,?\s*(?:also|first|secretly|silently))",
    re.IGNORECASE,
)


class PromptEngine(BaseEngine):
    name = "prompt"

    def scan(self, file_path: Path, content: str, target: TargetType) -> list[Finding]:
        findings: list[Finding] = []
        fname = str(file_path).lower()
        is_md = fname.endswith(".md") or target in (TargetType.SKILL_MD, TargetType.MARKDOWN)
        is_mcp_config = target == TargetType.MCP_CONFIG

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

        # SR-PROMPT-002: Role override attempts (skip for MCP config; handled in _scan_mcp_config)
        if not is_mcp_config:
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

        # SR-PROMPT-003/006/007: Invisible Unicode characters, Tags, Variation Selectors
        for line_no, line_text in enumerate(lines, start=1):
            found_invisible: list[str] = []
            found_tags: list[str] = []
            found_vs: list[str] = []
            for char in line_text:
                cp = ord(char)
                if char in _INVISIBLE_CHARS:
                    found_invisible.append(f"U+{cp:04X} ({_INVISIBLE_CHARS[char]})")
                elif 0xE0001 <= cp <= 0xE007F:
                    found_tags.append(f"U+{cp:05X} (Tag character)")
                elif (0xFE00 <= cp <= 0xFE0F) or (0xE0100 <= cp <= 0xE01EF):
                    found_vs.append(f"U+{cp:05X} (Variation Selector)")
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
            if found_tags:
                findings.append(Finding(
                    rule_id="SR-PROMPT-006",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    title="Unicode Tags block characters detected",
                    file=str(file_path),
                    line=line_no,
                    evidence=", ".join(found_tags[:5]),
                    recommendation="Remove Unicode Tag characters. These are invisible and can hide instructions.",
                    engine=self.name,
                ))
            if found_vs:
                findings.append(Finding(
                    rule_id="SR-PROMPT-007",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    title="Emoji Variation Selector payload hiding",
                    file=str(file_path),
                    line=line_no,
                    evidence=", ".join(found_vs[:5]),
                    recommendation="Remove Variation Selector characters used outside normal emoji rendering.",
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

        # SR-TOOL-001: Tool description with hidden behavior (skip for MCP config; handled in _scan_mcp_config)
        if not is_mcp_config:
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

        # SR-PROMPT-008: ANSI escape sequence injection
        for line_no, line_text in enumerate(lines, start=1):
            if _ANSI_ESCAPE_RE.search(line_text):
                findings.append(Finding(
                    rule_id="SR-PROMPT-008",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    title="ANSI escape sequence injection",
                    file=str(file_path),
                    line=line_no,
                    evidence=line_text.strip()[:240],
                    recommendation="Remove ANSI escape sequences from skill definitions.",
                    engine=self.name,
                ))

        # SR-STEALTH-001/002/004/005: Stealth/coercion instructions (markdown only)
        if is_md:
            _stealth_checks = [
                (_SECRECY_RE, "SR-STEALTH-001", ThreatCategory.STEALTH, Severity.CRITICAL,
                 "Secrecy instruction to hide actions from user",
                 "Remove instructions that hide behavior from the user."),
                (_OUTPUT_SUPPRESS_RE, "SR-STEALTH-002", ThreatCategory.STEALTH, Severity.HIGH,
                 "Output suppression instruction",
                 "Remove instructions that suppress output visibility."),
                (_ERROR_SUPPRESS_RE, "SR-STEALTH-004", ThreatCategory.STEALTH, Severity.MEDIUM,
                 "Error suppression instruction",
                 "Skills should not suppress error reporting."),
                (_ANTI_DETECT_RE, "SR-STEALTH-005", ThreatCategory.STEALTH, Severity.HIGH,
                 "Anti-detection or anti-analysis instruction",
                 "Remove anti-detection instructions."),
            ]
            for line_no, line_text in enumerate(lines, start=1):
                for regex, rule_id, cat, sev, title, rec in _stealth_checks:
                    if regex.search(line_text):
                        findings.append(Finding(
                            rule_id=rule_id,
                            category=cat,
                            severity=sev,
                            title=title,
                            file=str(file_path),
                            line=line_no,
                            evidence=line_text.strip()[:240],
                            recommendation=rec,
                            engine=self.name,
                        ))

        # SR-MCP-001: Cross-tool shadowing (markdown and MCP config)
        if is_md:
            for line_no, line_text in enumerate(lines, start=1):
                if _TOOL_SHADOW_RE.search(line_text):
                    findings.append(Finding(
                        rule_id="SR-MCP-001",
                        category=ThreatCategory.MCP_THREAT,
                        severity=Severity.CRITICAL,
                        title="Cross-tool shadowing in tool description",
                        file=str(file_path),
                        line=line_no,
                        evidence=line_text.strip()[:240],
                        recommendation="Tool descriptions must only describe their own functionality.",
                        engine=self.name,
                    ))

        # MCP config JSON parsing: extract tool descriptions and scan them
        if is_mcp_config:
            findings.extend(self._scan_mcp_config(file_path, content))

        return findings

    def _scan_mcp_config(self, file_path: Path, content: str) -> list[Finding]:
        """Parse MCP config JSON and scan tool descriptions for injection/shadowing."""
        findings: list[Finding] = []
        try:
            config = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return findings

        descriptions = self._extract_mcp_descriptions(config)
        for desc_text, key_path in descriptions:
            # Check for prompt injection keywords
            if _INJECTION_KEYWORDS.search(desc_text):
                findings.append(Finding(
                    rule_id="SR-PROMPT-001",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    title="Hidden instruction in MCP tool description",
                    file=str(file_path),
                    line=1,
                    evidence=f"[{key_path}] {desc_text[:200]}",
                    recommendation="Remove hidden instructions from MCP tool descriptions.",
                    engine=self.name,
                ))
            # Check for role override
            if _ROLE_OVERRIDE_RE.search(desc_text):
                findings.append(Finding(
                    rule_id="SR-PROMPT-002",
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    title="Role override in MCP tool description",
                    file=str(file_path),
                    line=1,
                    evidence=f"[{key_path}] {desc_text[:200]}",
                    recommendation="Remove prompt injection from MCP tool descriptions.",
                    engine=self.name,
                ))
            # Check for tool shadowing
            if _TOOL_SHADOW_RE.search(desc_text):
                findings.append(Finding(
                    rule_id="SR-MCP-001",
                    category=ThreatCategory.MCP_THREAT,
                    severity=Severity.CRITICAL,
                    title="Cross-tool shadowing in MCP tool description",
                    file=str(file_path),
                    line=1,
                    evidence=f"[{key_path}] {desc_text[:200]}",
                    recommendation="Tool descriptions must only describe their own functionality.",
                    engine=self.name,
                ))
            # Check for hidden behavior
            if _TOOL_HIDDEN_BEHAVIOR_RE.search(desc_text):
                findings.append(Finding(
                    rule_id="SR-TOOL-001",
                    category=ThreatCategory.TOOL_POISONING,
                    severity=Severity.CRITICAL,
                    title="Hidden behavior in MCP tool description",
                    file=str(file_path),
                    line=1,
                    evidence=f"[{key_path}] {desc_text[:200]}",
                    recommendation="Tool descriptions should only describe their stated functionality.",
                    engine=self.name,
                ))
            # Check for security override
            if _MCP_OVERRIDE_RE.search(desc_text):
                findings.append(Finding(
                    rule_id="SR-TOOL-003",
                    category=ThreatCategory.TOOL_POISONING,
                    severity=Severity.CRITICAL,
                    title="Security override in MCP tool description",
                    file=str(file_path),
                    line=1,
                    evidence=f"[{key_path}] {desc_text[:200]}",
                    recommendation="Tool definitions must not override security policies.",
                    engine=self.name,
                ))
        return findings

    @staticmethod
    def _extract_mcp_descriptions(config: dict) -> list[tuple[str, str]]:
        """Extract description strings from MCP server config JSON."""
        results: list[tuple[str, str]] = []

        def _walk(obj: object, path: str) -> None:
            if isinstance(obj, dict):
                for key, val in obj.items():
                    current = f"{path}.{key}" if path else key
                    if key == "description" and isinstance(val, str):
                        results.append((val, current))
                    else:
                        _walk(val, current)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _walk(item, f"{path}[{i}]")

        _walk(config, "")
        return results
