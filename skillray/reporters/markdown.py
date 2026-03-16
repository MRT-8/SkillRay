"""Markdown output reporter (for PR comments)."""

from __future__ import annotations

from ..models import ScanResult, Severity
from .summary import build_summary


class MarkdownReporter:
    def render(self, result: ScanResult) -> str:
        summary = build_summary(result)
        lines: list[str] = []

        lines.append("## SkillRay Security Scan Results")
        lines.append("")

        # Summary table
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        sev = summary["severity"]
        icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"}
        for level_name in ("Critical", "High", "Medium", "Low", "Info"):
            count = sev.get(level_name, 0)
            if count > 0:
                lines.append(f"| {icons.get(level_name, '')} {level_name} | {count} |")
        lines.append("")
        lines.append(f"**Total: {summary['total_findings']} findings** in {summary['scanned_files']} files ({summary['duration_ms']}ms)")
        lines.append("")

        if not result.findings:
            lines.append("> ✅ No security issues found.")
            return "\n".join(lines)

        # Findings
        lines.append("### Findings")
        lines.append("")
        for f in result.findings:
            icon = icons.get(f.severity.label, "")
            lines.append(f"#### {icon} {f.severity.label.upper()} — {f.rule_id}")
            lines.append(f"**{f.title}** — `{f.file}:{f.line}`")
            lines.append(f"```")
            lines.append(f"{f.evidence}")
            lines.append(f"```")
            lines.append(f"> 💡 {f.recommendation}")
            lines.append("")

        return "\n".join(lines)
