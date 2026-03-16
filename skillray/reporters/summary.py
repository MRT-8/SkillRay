"""Summary statistics generation."""

from __future__ import annotations

from ..models import ScanResult, Severity


def build_summary(result: ScanResult) -> dict[str, object]:
    severity_counts = {s.label: 0 for s in Severity}
    for f in result.findings:
        severity_counts[f.severity.label] += 1

    return {
        "total_findings": len(result.findings),
        "severity": severity_counts,
        "ignored": len(result.ignored),
        "scanned_files": len(result.scanned_files),
        "duration_ms": round(result.duration_ms, 1),
    }
