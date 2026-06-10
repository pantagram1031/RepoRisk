import json
from pathlib import Path

from reporisk.cli import main
from reporisk.reporting.json_report import build_json_report
from reporisk.reporting.markdown import build_markdown_report
from reporisk.scanner import scan_repository


def test_scanner_ignores_common_directories(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    ignored = tmp_path / ".git"
    ignored.mkdir()
    (ignored / "ignored.py").write_text("exec(user_input)\n", encoding="utf-8")

    result = scan_repository(tmp_path)

    assert result.files_scanned == 1
    assert {finding.rule_id for finding in result.findings} == {"PY-EVAL-001"}


def test_scanner_supports_env_files(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text('API_KEY="abcd1234secret"\n', encoding="utf-8")

    result = scan_repository(tmp_path)

    assert result.files_scanned == 1
    assert any(finding.rule_id == "SECRET-GENERIC-001" for finding in result.findings)


def test_markdown_and_json_reports_include_findings(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")
    result = scan_repository(tmp_path)

    markdown = build_markdown_report(result)
    json_report = build_json_report(result)

    assert "RepoRisk Scanner Report" in markdown
    assert "CONFIG-DEBUG-TRUE-001" in markdown
    assert json_report["summary"]["total_findings"] == 1


def test_cli_writes_reports(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    reports = tmp_path / "reports"

    exit_code = main([str(project), "--reports-dir", str(reports)])

    assert exit_code == 0
    assert (reports / "report.md").exists()
    assert (reports / "report.json").exists()
    data = json.loads((reports / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["total_findings"] == 1


def test_reports_include_suppression_summary(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)  # reporisk: ignore PY-EVAL-001\n", encoding="utf-8")
    result = scan_repository(tmp_path)

    markdown = build_markdown_report(result)
    json_report = build_json_report(result)

    assert "Suppressed findings" in markdown
    assert "PY-EVAL-001" in markdown
    assert json_report["suppression_summary"]["total_suppressed"] == 1
    assert json_report["suppressed_findings"][0]["finding"]["rule_id"] == "PY-EVAL-001"
