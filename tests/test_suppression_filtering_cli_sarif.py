import json
from pathlib import Path

from reporisk.cli import main
from reporisk.reporting.sarif import build_sarif_report
from reporisk.scanner import filter_result_by_severity, scan_repository


def test_inline_suppression_all_rules(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)  # reporisk: ignore\n", encoding="utf-8")

    result = scan_repository(tmp_path)

    assert result.findings == []
    assert len(result.suppressed_findings) == 1
    assert result.suppressed_findings[0].finding.rule_id == "PY-EVAL-001"


def test_inline_suppression_specific_rule(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "eval(user_input)  # reporisk: ignore PY-EVAL-001\n"
        "exec(dynamic_code)  # reporisk: ignore PY-EVAL-001\n",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)

    assert [finding.rule_id for finding in result.findings] == ["PY-EXEC-001"]
    assert len(result.suppressed_findings) == 1


def test_min_severity_filters_visible_findings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("hashlib.md5(b'demo')\neval(user_input)\n", encoding="utf-8")
    result = scan_repository(tmp_path)

    filtered = filter_result_by_severity(result, "high")

    assert {finding.rule_id for finding in filtered.findings} == {"PY-EVAL-001"}


def test_cli_fail_on_returns_nonzero(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")

    assert main([str(tmp_path), "--fail-on", "high", "--reports-dir", str(tmp_path / "reports")]) == 1


def test_cli_writes_sarif(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    reports = tmp_path / "reports"

    assert main([str(tmp_path), "--reports-dir", str(reports), "--sarif"]) == 0
    sarif = json.loads((reports / "report.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "PY-EVAL-001"


def test_sarif_report_generation(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    result = scan_repository(tmp_path)

    sarif = build_sarif_report(result)

    assert sarif["runs"][0]["tool"]["driver"]["name"] == "RepoRisk Scanner"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
