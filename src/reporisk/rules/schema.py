"""Schema objects for RepoRisk rules and findings."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from re import Pattern
from typing import Callable

Severity = str
Detector = Callable[[str, Path, int], bool]
AstDetector = Callable[[ast.AST], list[int]]


@dataclass(frozen=True)
class Rule:
    """A single local-only detection rule.

    Rules are intentionally passive: each rule evaluates text that has already
    been read from local files and never performs network activity or execution.
    """

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    pattern: Pattern[str] | None = None
    detector: Detector | None = None
    ast_detector: AstDetector | None = None
    extensions: tuple[str, ...] | None = None

    def matches(self, line: str, path: Path, line_number: int) -> bool:
        """Return True when this line-oriented rule matches local source text."""
        if self.ast_detector is not None:
            return False
        if self.extensions and path.suffix.lower() not in self.extensions:
            return False
        if self.detector is not None:
            return self.detector(line, path, line_number)
        if self.pattern is not None:
            return bool(self.pattern.search(line))
        return False


@dataclass(frozen=True)
class Finding:
    """A normalized scanner finding for reports."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    file_path: str
    line_number: int
    line_snippet: str
    description: str
    remediation: str


@dataclass(frozen=True)
class SuppressedFinding:
    """A finding hidden by an inline reporisk suppression comment."""

    finding: Finding
    suppression: str
