"""Command-line interface for RepoRisk Scanner."""

from __future__ import annotations

import argparse
from pathlib import Path

from reporisk.reporting.json_report import write_json_report
from reporisk.reporting.markdown import write_markdown_report
from reporisk.reporting.sarif import write_sarif_report
from reporisk.scanner import filter_result_by_severity, has_findings_at_or_above, scan_repository
from reporisk.severity import SEVERITY_ORDER


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
    parser.add_argument(
        "--min-severity",
        choices=tuple(SEVERITY_ORDER),
        help="Only include findings at or above this severity in normal reports.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER),
        help="Return exit code 1 if visible findings exist at or above this severity.",
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Also write reports/report.sarif for code-scanning style workflows.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    raw_result = scan_repository(args.path)
    result = filter_result_by_severity(raw_result, args.min_severity)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    markdown_path = reports_dir / "report.md"
    json_path = reports_dir / "report.json"
    write_markdown_report(result, str(markdown_path))
    write_json_report(result, str(json_path))

    sarif_path = reports_dir / "report.sarif"
    if args.sarif:
        write_sarif_report(result, str(sarif_path))

    print("RepoRisk Scanner completed")
    print(f"Scanned path: {result.scanned_path}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Findings: {len(result.findings)}")
    print(f"Suppressed findings: {len(result.suppressed_findings)}")
    print(f"Markdown report: {markdown_path}")
    print(f"JSON report: {json_path}")
    if args.sarif:
        print(f"SARIF report: {sarif_path}")

    if args.fail_on and has_findings_at_or_above(result, args.fail_on):
        print(f"Failing because findings at or above {args.fail_on} were detected")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
