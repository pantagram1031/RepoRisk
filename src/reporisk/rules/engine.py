"""Small rule engine used by the local scanner."""

from __future__ import annotations

import ast
from pathlib import Path

from reporisk.rules.builtin_rules import get_builtin_rules
from reporisk.rules.schema import Finding, Rule


class RuleEngine:
    """Apply rules to local file contents and return normalized findings."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else get_builtin_rules()

    def scan_ast(self, tree: ast.AST, path: Path, relative_path: str, lines: list[str]) -> list[Finding]:
        """Apply AST-backed rules to a parsed Python syntax tree."""
        findings: list[Finding] = []
        for rule in self.rules:
            if rule.ast_detector is None:
                continue
            if rule.extensions and path.suffix.lower() not in rule.extensions:
                continue
            for line_number in rule.ast_detector(tree):
                findings.append(self._finding_for(rule, relative_path, line_number, lines))
        return findings

    def scan_lines(self, path: Path, relative_path: str, lines: list[str]) -> list[Finding]:
        """Apply line-oriented rules to local file text."""
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule.matches(line, path, line_number):
                    findings.append(self._finding_for(rule, relative_path, line_number, lines))
        return findings

    @staticmethod
    def _finding_for(rule: Rule, relative_path: str, line_number: int, lines: list[str]) -> Finding:
        line = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            category=rule.category,
            file_path=relative_path,
            line_number=line_number,
            line_snippet=line.strip()[:240],
            description=rule.description,
            remediation=rule.remediation,
        )
