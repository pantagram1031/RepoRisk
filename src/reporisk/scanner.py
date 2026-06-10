"""Local repository scanner orchestration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from reporisk.rules.engine import RuleEngine
from reporisk.rules.schema import Finding, SuppressedFinding
from reporisk.severity import severity_at_or_above
from reporisk.utils.file_utils import iter_supported_files, read_text_lines

SUPPRESSION_RE = re.compile(r"#\s*reporisk:\s*ignore(?:\s+(?P<rules>[A-Z0-9_-]+(?:\s*,?\s*[A-Z0-9_-]+)*))?\b")


@dataclass(frozen=True)
class ScanResult:
    scanned_path: str
    files_scanned: int
    findings: list[Finding]
    suppressed_findings: list[SuppressedFinding]


def scan_repository(root: str | Path, engine: RuleEngine | None = None) -> ScanResult:
    """Scan only local supported text files under the user-provided directory."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Scan path must be a directory: {root_path}")

    rule_engine = engine or RuleEngine()
    findings: list[Finding] = []
    suppressed_findings: list[SuppressedFinding] = []
    files_scanned = 0

    for file_path in sorted(iter_supported_files(root_path)):
        lines = read_text_lines(file_path)
        if lines is None:
            continue
        files_scanned += 1
        relative_path = str(file_path.relative_to(root_path))

        file_findings: list[Finding] = []
        if file_path.suffix.lower() == ".py":
            file_findings.extend(_scan_python_ast(rule_engine, file_path, relative_path, lines))
        file_findings.extend(rule_engine.scan_lines(file_path, relative_path, lines))

        active, suppressed = apply_suppressions(file_findings, lines)
        findings.extend(active)
        suppressed_findings.extend(suppressed)

    return ScanResult(
        scanned_path=str(root_path),
        files_scanned=files_scanned,
        findings=findings,
        suppressed_findings=suppressed_findings,
    )


def filter_result_by_severity(result: ScanResult, min_severity: str | None) -> ScanResult:
    """Return a copy with visible findings filtered by severity."""
    if min_severity is None:
        return result
    return ScanResult(
        scanned_path=result.scanned_path,
        files_scanned=result.files_scanned,
        findings=[finding for finding in result.findings if severity_at_or_above(finding.severity, min_severity)],
        suppressed_findings=result.suppressed_findings,
    )


def has_findings_at_or_above(result: ScanResult, severity: str) -> bool:
    """Return True if visible findings meet or exceed a failure threshold."""
    return any(severity_at_or_above(finding.severity, severity) for finding in result.findings)


def apply_suppressions(findings: list[Finding], lines: list[str]) -> tuple[list[Finding], list[SuppressedFinding]]:
    """Split findings into active and inline-suppressed findings."""
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    for finding in findings:
        suppression = _suppression_for_line(lines[finding.line_number - 1], finding.rule_id)
        if suppression:
            suppressed.append(SuppressedFinding(finding=finding, suppression=suppression))
        else:
            active.append(finding)
    return active, suppressed


def _scan_python_ast(rule_engine: RuleEngine, file_path: Path, relative_path: str, lines: list[str]) -> list[Finding]:
    source = "\n".join(lines)
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return []
    return rule_engine.scan_ast(tree, file_path, relative_path, lines)


def _suppression_for_line(line: str, rule_id: str) -> str | None:
    match = SUPPRESSION_RE.search(line)
    if not match:
        return None
    rules = match.group("rules")
    if rules is None:
        return "reporisk: ignore"
    rule_ids = {part.strip() for part in re.split(r"[\s,]+", rules) if part.strip()}
    if rule_id in rule_ids:
        return f"reporisk: ignore {rule_id}"
    return None
