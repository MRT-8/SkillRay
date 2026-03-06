from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .ignore import load_ignore_file
from .reporters import build_json_report, render_text_report, write_json_report
from .scanner import scan_skills


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillray_scan",
        description="Lightweight static security scanner for newly added skills.",
    )
    parser.add_argument(
        "--path",
        default="skills",
        help="Root directory to scan. Defaults to ./skills",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "both"),
        default="both",
        help="Output format. Defaults to both.",
    )
    parser.add_argument(
        "--json-out",
        default="skillray-report.json",
        help="JSON report output path when --format is json or both.",
    )
    parser.add_argument(
        "--ignore-file",
        default=".skillrayignore",
        help="Ignore configuration file path. Defaults to ./.skillrayignore",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        scan_root = Path(args.path)
        ignore_file = Path(args.ignore_file)
        ignore_config = load_ignore_file(ignore_file)

        result = scan_skills(scan_root=scan_root, ignore_config=ignore_config)

        if args.format in {"text", "both"}:
            print(render_text_report(result))

        if args.format in {"json", "both"}:
            json_report = build_json_report(result)
            output_path = Path(args.json_out)
            write_json_report(json_report, output_path)
            print(f"JSON report written to: {output_path}")

        return 0
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"skillray_scan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
