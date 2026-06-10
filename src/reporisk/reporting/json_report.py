"""JSON report generation."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime

from reporisk import __version__
from reporisk.scanner import ScanResult
from reporisk.severity import REPORT_SEVERITIES


def severity_summary(result: ScanResult) -> dict[str, int]:
    counts = {severity: 0 for severity in REPORT_SEVERITIES}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def suppression_summary(result: ScanResult) -> dict[str, object]:
    by_rule: dict[str, int] = {}
    for suppressed in result.suppressed_findings:
        rule_id = suppressed.finding.rule_id
        by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
    return {
        "total_suppressed": len(result.suppressed_findings),
        "by_rule": dict(sorted(by_rule.items())),
    }


def build_json_report(result: ScanResult) -> dict[str, object]:
    """Build a machine-readable report dictionary."""
    return {
        "tool": "RepoRisk Scanner",
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "scanned_path": result.scanned_path,
        "files_scanned": result.files_scanned,
        "summary": {
            "total_findings": len(result.findings),
            "by_severity": severity_summary(result),
        },
        "suppression_summary": suppression_summary(result),
        "findings": [asdict(finding) for finding in result.findings],
        "suppressed_findings": [
            {
                "suppression": suppressed.suppression,
                "finding": asdict(suppressed.finding),
            }
            for suppressed in result.suppressed_findings
        ],
    }


def write_json_report(result: ScanResult, output_path: str) -> None:
    """Write the JSON report to disk."""
    with open(output_path, "w", encoding="utf-8") as report_file:
        json.dump(build_json_report(result), report_file, indent=2)
        report_file.write("\n")
