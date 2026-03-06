from __future__ import annotations

from pathlib import Path

from .ignore import IgnoreConfig, match_ignore
from .models import IgnoredFinding, ScanResult, TargetType, finding_sort_key
from .rules import run_rules_for_content

_SCRIPT_EXTENSIONS = {
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".psm1",
    ".cmd",
    ".bat",
}


def _classify_target(file_path: Path) -> TargetType | None:
    if file_path.name.lower() == "skill.md":
        return "skill_md"

    in_scripts_dir = any(part.lower() == "scripts" for part in file_path.parts)
    if in_scripts_dir or file_path.suffix.lower() in _SCRIPT_EXTENSIONS:
        return "script"

    return None


def discover_files(scan_root: Path) -> list[tuple[Path, TargetType, str]]:
    discovered: list[tuple[Path, TargetType, str]] = []
    for file_path in sorted(scan_root.rglob("*")):
        if not file_path.is_file():
            continue
        target = _classify_target(file_path)
        if target is None:
            continue
        relative = file_path.relative_to(scan_root).as_posix()
        discovered.append((file_path, target, relative))
    return discovered


def scan_skills(scan_root: Path, ignore_config: IgnoreConfig | None = None) -> ScanResult:
    ignore_config = ignore_config or IgnoreConfig()
    resolved_root = scan_root.resolve()
    result = ScanResult(scan_root=resolved_root)

    if not scan_root.exists() or not scan_root.is_dir():
        result.warnings.append(f"Scan path not found or not a directory: {scan_root}")
        return result

    for file_path, target, relative in discover_files(scan_root):
        result.scanned_files.append(relative)
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            result.warnings.append(f"Failed to read {relative}: {exc}")
            continue

        findings = run_rules_for_content(target=target, file_path=relative, text=text)
        for finding in findings:
            ignore_reason = match_ignore(finding, ignore_config)
            if ignore_reason is None:
                result.findings.append(finding)
                continue
            result.ignored.append(
                IgnoredFinding(
                    id=finding.id,
                    severity=finding.severity,
                    file=finding.file,
                    line=finding.line,
                    reason=ignore_reason,
                )
            )

    result.scanned_files.sort()
    result.findings.sort(key=finding_sort_key)
    result.ignored.sort(key=lambda item: (item.file, item.line, item.id))
    return result
