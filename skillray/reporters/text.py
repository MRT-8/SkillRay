"""Rich terminal output reporter."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from ..models import ScanResult, Severity
from ..i18n import t, Lang
from .summary import build_summary

_BANNER = r"""
  ____  _    _ _ _ ____
 / ___|| | _(_) | |  _ \ __ _ _   _
 \___ \| |/ / | | | |_) / _` | | | |
  ___) |   <| | | |  _ < (_| | |_| |
 |____/|_|\_\_|_|_|_| \_\__,_|\__, |
                                |___/"""

_SEV_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class TextReporter:
    def __init__(self, lang: Lang = "en", no_color: bool = False):
        self.lang = lang
        self.console = Console(force_terminal=not no_color, no_color=no_color)

    def render(self, result: ScanResult) -> None:
        self._print_banner()
        self._print_scan_info(result)
        self._print_severity_table(result)

        if result.findings:
            self._print_findings(result)
            self._print_footer(result)
        else:
            self.console.print(
                f"\n  ✅ {t('no_findings', self.lang)}",
                style="bold green",
            )

    def render_to_string(self, result: ScanResult) -> str:
        console = Console(record=True, no_color=True)
        self._render_to(console, result)
        return console.export_text()

    def _render_to(self, console: Console, result: ScanResult) -> None:
        old_console = self.console
        self.console = console
        self.render(result)
        self.console = old_console

    def _print_banner(self) -> None:
        self.console.print(_BANNER, style="bold cyan")
        self.console.print("  v2.0.0", style="dim")
        self.console.print()

    def _print_scan_info(self, result: ScanResult) -> None:
        self.console.print(
            f"  ⚡ {t('scanning', self.lang)}: {result.scan_root}",
            style="bold",
        )
        duration = f"{result.duration_ms:.0f}ms" if result.duration_ms else ""
        self.console.print(
            f"  📁 {t('files_scanned', self.lang)}: {len(result.scanned_files)} {duration}",
        )
        self.console.print()

    def _print_severity_table(self, result: ScanResult) -> None:
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold",
            padding=(0, 2),
        )
        table.add_column(t("severity", self.lang), justify="left")
        table.add_column(t("count", self.lang), justify="center")

        counts = result.severity_counts
        for sev in Severity:
            count = counts.get(sev, 0)
            if count > 0:
                icon = _SEV_ICONS[sev]
                label = t(sev.name.lower(), self.lang)
                table.add_row(
                    f" {icon} {label}",
                    str(count),
                    style=sev.color,
                )

        total = len(result.findings)
        table.add_section()
        table.add_row(f"  {t('total_findings', self.lang)}", str(total), style="bold")

        self.console.print(table)
        self.console.print()

    def _print_findings(self, result: ScanResult) -> None:
        for finding in result.findings:
            sev = finding.severity
            icon = _SEV_ICONS[sev]
            label = t(sev.name.lower(), self.lang).upper()

            header = Text()
            header.append(f" {icon} {label}", style=sev.color)
            header.append(f"  {finding.rule_id}", style="bold")
            header.append(f"  {finding.file}:{finding.line}", style="dim")
            self.console.print(header)

            self.console.print(f"    {finding.title}", style="bold")
            self.console.print(
                f"    {t('evidence', self.lang)}: {finding.evidence}",
                style="dim",
            )
            self.console.print(
                f"    {t('fix', self.lang)}: {finding.recommendation}",
                style="green",
            )
            self.console.print()

    def _print_footer(self, result: ScanResult) -> None:
        critical_count = result.severity_counts.get(Severity.CRITICAL, 0)
        self.console.print("─" * 40)
        if critical_count > 0:
            self.console.print(
                f" ⚠  {t('critical_attention', self.lang, n=critical_count)}",
                style="bold red",
            )

        if result.ignored:
            self.console.print(
                f" ℹ  {t('ignored', self.lang)}: {len(result.ignored)}",
                style="dim",
            )

        if result.warnings:
            for w in result.warnings:
                self.console.print(f" ⚠  {w}", style="yellow")
