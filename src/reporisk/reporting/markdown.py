"""Markdown report generation."""

from __future__ import annotations

from datetime import UTC, datetime

from reporisk import __version__
from reporisk.reporting.json_report import SEVERITIES, severity_summary
from reporisk.scanner import ScanResult


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|")


def build_markdown_report(result: ScanResult) -> str:
    """Build a clear human-readable Markdown report."""
    counts = severity_summary(result)
    lines = [
        "# RepoRisk Scanner Report",
        "",
        f"- Tool version: `{__version__}`",
        f"- Generated at: `{datetime.now(UTC).isoformat()}`",
        f"- Scanned path: `{result.scanned_path}`",
        f"- Files scanned: `{result.files_scanned}`",
        f"- Total findings: `{len(result.findings)}`",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity.title()} | {counts.get(severity, 0)} |")

    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings detected by the enabled rules.")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(result.findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- Severity: `{finding.severity}`",
                f"- Rule ID: `{finding.rule_id}`",
                f"- Category: `{finding.category}`",
                f"- File: `{finding.file_path}`",
                f"- Line: `{finding.line_number}`",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Explanation | {_escape_table(finding.description)} |",
                f"| Remediation | {_escape_table(finding.remediation)} |",
                f"| Line snippet | `{_escape_table(finding.line_snippet)}` |",
                "",
            ]
        )
    return "\n".join(lines)


def write_markdown_report(result: ScanResult, output_path: str) -> None:
    """Write the Markdown report to disk."""
    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write(build_markdown_report(result))
