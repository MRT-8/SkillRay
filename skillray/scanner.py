"""Multi-engine scan orchestrator."""

from __future__ import annotations

import time
from pathlib import Path

from .config import IgnoreConfig, load_ignore_file, match_ignore
from .models import (
    Finding, IgnoredFinding, ScanResult, TargetType, finding_sort_key,
)
from .engines.regex_engine import RegexEngine
from .engines.ast_engine import ASTEngine
from .engines.entropy_engine import EntropyEngine
from .engines.dataflow_engine import DataflowEngine
from .engines.prompt_engine import PromptEngine

_SCRIPT_EXTENSIONS = {
    ".py", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".cmd", ".bat",
}

_ALL_ENGINES = [
    RegexEngine(),
    ASTEngine(),
    EntropyEngine(),
    DataflowEngine(),
    PromptEngine(),
]


def _classify_target(file_path: Path) -> TargetType | None:
    name_lower = file_path.name.lower()
    if name_lower == "skill.md":
        return TargetType.SKILL_MD
    if name_lower.endswith(".md"):
        return TargetType.MARKDOWN
    if name_lower in ("package.json", "pyproject.toml", "setup.py", "setup.cfg", "Cargo.toml"):
        return TargetType.CONFIG

    in_scripts_dir = any(part.lower() == "scripts" for part in file_path.parts)
    if in_scripts_dir or file_path.suffix.lower() in _SCRIPT_EXTENSIONS:
        return TargetType.SCRIPT

    # Scan other text files with ANY target
    if file_path.suffix.lower() in (".txt", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf"):
        return TargetType.ANY

    return None


def discover_files(scan_root: Path) -> list[tuple[Path, TargetType, str]]:
    discovered: list[tuple[Path, TargetType, str]] = []
    for file_path in sorted(scan_root.rglob("*")):
        if not file_path.is_file():
            continue
        # Skip hidden directories and common non-scan directories
        parts = file_path.relative_to(scan_root).parts
        if any(p.startswith(".") or p in ("node_modules", "__pycache__", ".git", "venv", ".venv") for p in parts):
            continue
        target = _classify_target(file_path)
        if target is None:
            continue
        relative = file_path.relative_to(scan_root).as_posix()
        discovered.append((file_path, target, relative))
    return discovered


def scan_path(
    scan_root: Path,
    ignore_config: IgnoreConfig | None = None,
    engine_names: list[str] | None = None,
    rule_filters: list[str] | None = None,
) -> ScanResult:
    """Scan a directory for security issues."""
    ignore_config = ignore_config or IgnoreConfig()
    resolved_root = scan_root.resolve()
    result = ScanResult(scan_root=resolved_root)

    if not scan_root.exists() or not scan_root.is_dir():
        result.warnings.append(f"Scan path not found or not a directory: {scan_root}")
        return result

    # Select engines
    engines = _ALL_ENGINES
    if engine_names:
        engines = [e for e in _ALL_ENGINES if e.name in engine_names]

    start = time.monotonic()

    for file_path, target, relative in discover_files(scan_root):
        result.scanned_files.append(relative)
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            result.warnings.append(f"Failed to read {relative}: {exc}")
            continue

        for engine in engines:
            try:
                findings = engine.scan(Path(relative), text, target)
            except Exception as exc:
                result.warnings.append(f"Engine {engine.name} error on {relative}: {exc}")
                continue

            for finding in findings:
                # Apply rule filters
                if rule_filters and not _matches_filter(finding.rule_id, rule_filters):
                    continue

                ignore_reason = match_ignore(finding, ignore_config)
                if ignore_reason is None:
                    result.findings.append(finding)
                else:
                    result.ignored.append(IgnoredFinding(
                        rule_id=finding.rule_id,
                        severity=finding.severity,
                        file=finding.file,
                        line=finding.line,
                        reason=ignore_reason,
                    ))

    result.duration_ms = (time.monotonic() - start) * 1000
    result.scanned_files.sort()
    result.findings.sort(key=finding_sort_key)
    return result


def _matches_filter(rule_id: str, filters: list[str]) -> bool:
    for f in filters:
        if f.endswith("*"):
            if rule_id.startswith(f[:-1]):
                return True
        elif rule_id == f:
            return True
    return False
