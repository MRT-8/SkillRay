"""Shannon entropy + known key format detection engine."""

from __future__ import annotations

import math
import re
from pathlib import Path

from .base import BaseEngine
from ..models import Finding, TargetType, Severity, ThreatCategory

# Known secret key patterns (prefix + min length)
_KNOWN_KEY_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "SR-CRED-005"),
    ("AWS Secret Key", re.compile(r"(?:aws_secret_access_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "SR-CRED-005"),
    ("GitHub Token", re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"), "SR-CRED-005"),
    ("GitHub OAuth", re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"), "SR-CRED-005"),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"), "SR-CRED-005"),
    ("OpenAI Key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "SR-CRED-005"),
    ("Anthropic Key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "SR-CRED-005"),
    ("Slack Token", re.compile(r"\bxox[bpoas]-[A-Za-z0-9\-]{10,}\b"), "SR-CRED-005"),
    ("Stripe Key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b"), "SR-CRED-005"),
    ("Google API Key", re.compile(r"\bAIza[A-Za-z0-9\-_]{35}\b"), "SR-CRED-005"),
    ("Twilio Key", re.compile(r"\bSK[a-f0-9]{32}\b"), "SR-CRED-005"),
    ("npm Token", re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"), "SR-CRED-005"),
    ("Heroku API Key", re.compile(r"(?:heroku.*api.*key|HEROKU_API_KEY)\s*[=:]\s*['\"]?([a-f0-9\-]{36})['\"]?"), "SR-CRED-005"),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "SR-CRED-001"),
    ("Generic Bearer Token", re.compile(r"(?:bearer|token|auth)\s*[=:]\s*['\"][A-Za-z0-9\-_.]{30,}['\"]", re.IGNORECASE), "SR-CRED-001"),
]

# Minimum entropy threshold for a string to be considered a potential secret
_ENTROPY_THRESHOLD = 4.5
_MIN_SECRET_LENGTH = 20
_MAX_SECRET_LENGTH = 200

# Patterns to extract quoted strings and assignments
_STRING_EXTRACT = re.compile(
    r"""(?:(?:key|token|secret|password|api_key|apikey|auth|credential|passwd)"""
    r"""\s*[=:]\s*['"]([A-Za-z0-9+/=\-_.]{16,})['"])""",
    re.IGNORECASE,
)


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


class EntropyEngine(BaseEngine):
    name = "entropy"

    def scan(self, file_path: Path, content: str, target: TargetType) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for line_no, line_text in enumerate(lines, start=1):
            # Check known key formats first
            for key_name, pattern, rule_id in _KNOWN_KEY_PATTERNS:
                match = pattern.search(line_text)
                if match:
                    # Mask the evidence
                    matched = match.group(0)
                    masked = matched[:8] + "*" * min(len(matched) - 12, 20) + matched[-4:] if len(matched) > 16 else matched[:4] + "****"
                    findings.append(Finding(
                        rule_id=rule_id,
                        category=ThreatCategory.CREDENTIAL_THEFT,
                        severity=Severity.CRITICAL,
                        title=f"Hardcoded {key_name} detected",
                        file=str(file_path),
                        line=line_no,
                        evidence=masked,
                        recommendation="Use environment variables or a secrets manager.",
                        engine=self.name,
                    ))
                    break  # One finding per line for known formats
            else:
                # Fall back to entropy analysis for generic secrets
                for m in _STRING_EXTRACT.finditer(line_text):
                    value = m.group(1)
                    if _MIN_SECRET_LENGTH <= len(value) <= _MAX_SECRET_LENGTH:
                        entropy = _shannon_entropy(value)
                        if entropy >= _ENTROPY_THRESHOLD:
                            masked = value[:6] + "*" * min(len(value) - 10, 20) + value[-4:]
                            findings.append(Finding(
                                rule_id="SR-CRED-001",
                                category=ThreatCategory.CREDENTIAL_THEFT,
                                severity=Severity.HIGH,
                                title="High-entropy string in secret context (possible hardcoded credential)",
                                file=str(file_path),
                                line=line_no,
                                evidence=f"entropy={entropy:.2f}: {masked}",
                                recommendation="Use environment variables or a secrets manager instead of hardcoding secrets.",
                                engine=self.name,
                            ))

        return findings
