"""Command-line interface for RepoRisk Scanner."""

from __future__ import annotations

import argparse
from pathlib import Path

from reporisk.reporting.json_report import write_json_report
from reporisk.reporting.markdown import write_markdown_report
from reporisk.scanner import scan_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reporisk",
        description="Defensively scan a local source-code repository for possible cyber risks.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Local directory to scan. Defaults to the current directory.",
    )
    parser.add_argument(
        "--reports-dir",
        default="reports",
        help="Directory where report.md and report.json will be written. Defaults to reports/.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    result = scan_repository(args.path)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    markdown_path = reports_dir / "report.md"
    json_path = reports_dir / "report.json"
    write_markdown_report(result, str(markdown_path))
    write_json_report(result, str(json_path))

    print("RepoRisk Scanner completed")
    print(f"Scanned path: {result.scanned_path}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Findings: {len(result.findings)}")
    print(f"Markdown report: {markdown_path}")
    print(f"JSON report: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
