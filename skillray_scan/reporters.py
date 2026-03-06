from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanResult


def build_summary(result: ScanResult) -> dict[str, object]:
    high = sum(1 for item in result.findings if item.severity == "High")
    medium = sum(1 for item in result.findings if item.severity == "Medium")
    low = sum(1 for item in result.findings if item.severity == "Low")

    return {
        "total_findings": len(result.findings),
        "severity": {
            "High": high,
            "Medium": medium,
            "Low": low,
        },
        "ignored": len(result.ignored),
        "scanned_files": len(result.scanned_files),
    }


def build_json_report(result: ScanResult) -> dict[str, object]:
    payload: dict[str, object] = {
        "summary": build_summary(result),
        "findings": [asdict(item) for item in result.findings],
        "scanned_files": result.scanned_files,
        "ignored": [asdict(item) for item in result.ignored],
        "generated_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    if result.warnings:
        payload["warnings"] = result.warnings
    return payload


def render_text_report(result: ScanResult) -> str:
    summary = build_summary(result)
    severity = summary["severity"]

    lines = [
        f"Scan root: {result.scan_root}",
        f"Scanned files: {summary['scanned_files']}",
        (
            "Findings: "
            f"{summary['total_findings']} "
            f"(High: {severity['High']}, Medium: {severity['Medium']}, Low: {severity['Low']})"
        ),
        f"Ignored findings: {summary['ignored']}",
    ]

    if result.warnings:
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"- {warning}")

    if not result.findings:
        lines.append("No findings detected.")
        return "\n".join(lines)

    lines.append("Findings detail:")
    for item in result.findings:
        lines.append(f"- [{item.severity}] {item.id} {item.file}:{item.line} {item.title}")
        if item.evidence:
            lines.append(f"  evidence: {item.evidence}")
        lines.append(f"  recommendation: {item.recommendation}")

    return "\n".join(lines)


def write_json_report(report: dict[str, object], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
