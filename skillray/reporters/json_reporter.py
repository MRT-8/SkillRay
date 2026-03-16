"""JSON and SARIF output reporters."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import ScanResult, Severity
from .summary import build_summary


class JSONReporter:
    def render(self, result: ScanResult) -> str:
        return json.dumps(self._build_report(result), ensure_ascii=False, indent=2)

    def write(self, result: ScanResult, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.render(result), encoding="utf-8")

    def _build_report(self, result: ScanResult) -> dict:
        return {
            "tool": "skillray",
            "version": "2.0.0",
            "summary": build_summary(result),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category.value,
                    "severity": f.severity.label.lower(),
                    "title": f.title,
                    "file": f.file,
                    "line": f.line,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "engine": f.engine,
                }
                for f in result.findings
            ],
            "scanned_files": result.scanned_files,
            "ignored_count": len(result.ignored),
            "generated_at": datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
        }

    def render_sarif(self, result: ScanResult) -> str:
        rules = {}
        results = []
        for f in result.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "defaultConfiguration": {
                        "level": _sarif_level(f.severity),
                    },
                }
            results.append({
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.evidence},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }],
            })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SkillRay",
                        "version": "2.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }
        return json.dumps(sarif, ensure_ascii=False, indent=2)


def _sarif_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }[severity]
