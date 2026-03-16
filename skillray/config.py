"""Configuration and ignore file handling."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding


@dataclass(frozen=True)
class ScopedIgnore:
    rule_id: str
    pattern: str


@dataclass
class IgnoreConfig:
    global_rule_ids: set[str] = field(default_factory=set)
    scoped: list[ScopedIgnore] = field(default_factory=list)


def _normalize_path(value: str) -> str:
    return value.replace("\\", "/").strip().lower()


def load_ignore_file(path: Path) -> IgnoreConfig:
    config = IgnoreConfig()
    if not path.exists() or not path.is_file():
        return config

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = raw_line.lstrip("\ufeff").strip()
        if not entry or entry.startswith("#"):
            continue

        if ":" in entry:
            rule_id, pattern = entry.split(":", 1)
            rule_id = rule_id.strip()
            pattern = pattern.strip()
            if rule_id and pattern:
                config.scoped.append(
                    ScopedIgnore(rule_id=rule_id, pattern=_normalize_path(pattern))
                )
            continue

        config.global_rule_ids.add(entry)

    return config


def match_ignore(finding: Finding, config: IgnoreConfig) -> str | None:
    if finding.rule_id in config.global_rule_ids:
        return "globally ignored rule"

    normalized_file = _normalize_path(finding.file)
    for entry in config.scoped:
        if entry.rule_id != finding.rule_id:
            continue
        if fnmatch.fnmatch(normalized_file, entry.pattern):
            return f"ignored by pattern: {entry.pattern}"

    return None
