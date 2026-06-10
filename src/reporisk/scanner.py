"""Local repository scanner orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reporisk.rules.engine import RuleEngine
from reporisk.rules.schema import Finding
from reporisk.utils.file_utils import iter_supported_files, read_text_lines


@dataclass(frozen=True)
class ScanResult:
    scanned_path: str
    files_scanned: int
    findings: list[Finding]


def scan_repository(root: str | Path, engine: RuleEngine | None = None) -> ScanResult:
    """Scan only local supported text files under the user-provided directory."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Scan path must be a directory: {root_path}")

    rule_engine = engine or RuleEngine()
    findings: list[Finding] = []
    files_scanned = 0

    for file_path in sorted(iter_supported_files(root_path)):
        lines = read_text_lines(file_path)
        if lines is None:
            continue
        files_scanned += 1
        relative_path = str(file_path.relative_to(root_path))
        findings.extend(rule_engine.scan_lines(file_path, relative_path, lines))

    return ScanResult(scanned_path=str(root_path), files_scanned=files_scanned, findings=findings)
