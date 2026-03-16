"""Rich CLI entry point for SkillRay."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import load_ignore_file
from .scanner import scan_path
from .reporters.text import TextReporter
from .reporters.json_reporter import JSONReporter
from .reporters.markdown import MarkdownReporter
from .models import Severity


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillray",
        description="SkillRay — AI Skill Security Scanner",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif", "md"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write report to file",
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low"),
        default=None,
        help="Exit with code 1 if findings at this severity or above",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output (findings only)",
    )
    parser.add_argument(
        "--lang",
        choices=("en", "zh"),
        default="en",
        help="Output language",
    )
    parser.add_argument(
        "--ignore-file",
        default=".skillrayignore",
        help="Ignore configuration file path",
    )
    parser.add_argument(
        "--engines",
        default=None,
        help="Comma-separated engine names to use (e.g., regex,ast,entropy)",
    )
    parser.add_argument(
        "--rules",
        default=None,
        help="Comma-separated rule filters (e.g., SR-PROMPT-*,SR-CRED-*)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version="skillray 2.0.0",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        scan_root = Path(args.path)
        ignore_config = load_ignore_file(Path(args.ignore_file))

        engine_names = args.engines.split(",") if args.engines else None
        rule_filters = args.rules.split(",") if args.rules else None

        result = scan_path(
            scan_root=scan_root,
            ignore_config=ignore_config,
            engine_names=engine_names,
            rule_filters=rule_filters,
        )

        # Output
        if args.format == "text":
            reporter = TextReporter(lang=args.lang, no_color=args.no_color)
            if args.quiet:
                # Quiet mode: just findings count
                for f in result.findings:
                    print(f"[{f.severity.label}] {f.rule_id} {f.file}:{f.line} {f.title}")
            else:
                reporter.render(result)

            if args.output:
                Path(args.output).write_text(
                    reporter.render_to_string(result), encoding="utf-8"
                )

        elif args.format == "json":
            jr = JSONReporter()
            output = jr.render(result)
            if args.quiet:
                pass
            else:
                print(output)
            if args.output:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                Path(args.output).write_text(output, encoding="utf-8")

        elif args.format == "sarif":
            jr = JSONReporter()
            output = jr.render_sarif(result)
            if not args.quiet:
                print(output)
            if args.output:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                Path(args.output).write_text(output, encoding="utf-8")

        elif args.format == "md":
            mr = MarkdownReporter()
            output = mr.render(result)
            if not args.quiet:
                print(output)
            if args.output:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                Path(args.output).write_text(output, encoding="utf-8")

        # Exit code based on --fail-on
        if args.fail_on:
            threshold = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }[args.fail_on]
            for f in result.findings:
                if f.severity <= threshold:  # IntEnum: lower value = higher severity
                    return 1

        return 0

    except Exception as exc:
        print(f"skillray: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
