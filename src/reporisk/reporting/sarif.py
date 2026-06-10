"""Minimal SARIF report generation for RepoRisk findings."""

from __future__ import annotations

import json

from reporisk import __version__
from reporisk.scanner import ScanResult

SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def build_sarif_report(result: ScanResult) -> dict[str, object]:
    """Build a simple SARIF 2.1.0 report."""
    rules_by_id = {finding.rule_id: finding for finding in result.findings}
    rules = [
        {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.remediation},
            "properties": {"security-severity": _security_severity(finding.severity)},
        }
        for rule_id, finding in sorted(rules_by_id.items())
    ]
    sarif_results = [
        {
            "ruleId": finding.rule_id,
            "level": SARIF_LEVELS.get(finding.severity, "warning"),
            "message": {"text": f"{finding.title}: {finding.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {"startLine": finding.line_number},
                    }
                }
            ],
            "properties": {"severity": finding.severity, "category": finding.category},
        }
        for finding in result.findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoRisk Scanner",
                        "informationUri": "https://github.com/pantagram1031/RepoRisk",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif_report(result: ScanResult, output_path: str) -> None:
    """Write the SARIF report to disk."""
    with open(output_path, "w", encoding="utf-8") as report_file:
        json.dump(build_sarif_report(result), report_file, indent=2)
        report_file.write("\n")


def _security_severity(severity: str) -> str:
    return {
        "critical": "9.0",
        "high": "7.0",
        "medium": "5.0",
        "low": "2.0",
        "info": "0.0",
    }.get(severity, "0.0")
