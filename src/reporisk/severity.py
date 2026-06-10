"""Severity ordering and filtering helpers."""

from __future__ import annotations

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
REPORT_SEVERITIES = ("critical", "high", "medium", "low", "info")


def severity_at_or_above(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]
