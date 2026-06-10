"""Small rule engine used by the local scanner."""

from __future__ import annotations

from pathlib import Path

from reporisk.rules.builtin_rules import get_builtin_rules
from reporisk.rules.schema import Finding, Rule


class RuleEngine:
    """Apply rules to local file contents and return normalized findings."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else get_builtin_rules()

    def scan_lines(self, path: Path, relative_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule.matches(line, path, line_number):
                    findings.append(
                        Finding(
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
                    )
        return findings
