from pathlib import Path

from reporisk.rules.engine import RuleEngine
from reporisk.scanner import scan_repository


def _rule_ids_for_line_rule(line: str, filename: str = "app.py") -> set[str]:
    engine = RuleEngine()
    findings = engine.scan_lines(Path(filename), filename, [line])
    return {finding.rule_id for finding in findings}


def _rule_ids_for_python(tmp_path: Path, source: str) -> set[str]:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return {finding.rule_id for finding in scan_repository(tmp_path).findings}


def test_detects_eval_and_exec(tmp_path: Path) -> None:
    ids = _rule_ids_for_python(tmp_path, "result = eval(user_input)\nexec(dynamic_code)\n")
    assert "PY-EVAL-001" in ids
    assert "PY-EXEC-001" in ids


def test_detects_subprocess_shell_true(tmp_path: Path) -> None:
    assert "PY-SUBPROCESS-SHELL-TRUE-001" in _rule_ids_for_python(
        tmp_path, 'import subprocess\nsubprocess.run("echo hi", shell=True)\n'
    )


def test_detects_unsafe_yaml_load_but_not_safe_loader(tmp_path: Path) -> None:
    assert "PY-YAML-LOAD-001" in _rule_ids_for_python(tmp_path, "import yaml\nyaml.load(config_text)\n")
    assert "PY-YAML-LOAD-001" not in _rule_ids_for_python(
        tmp_path, "import yaml\nyaml.load(config_text, Loader=yaml.SafeLoader)\n"
    )


def test_detects_pickle_requests_and_weak_hash(tmp_path: Path) -> None:
    ids = _rule_ids_for_python(
        tmp_path,
        "import hashlib\nimport pickle\nimport requests\n"
        "pickle.loads(blob)\nrequests.get('https://example.invalid', verify=False)\nhashlib.sha1(b'demo')\n",
    )
    assert "PY-PICKLE-001" in ids
    assert "PY-REQUESTS-VERIFY-FALSE-001" in ids
    assert "PY-WEAK-HASH-001" in ids


def test_detects_sql_string_concatenation() -> None:
    assert "SQL-CONCAT-001" in _rule_ids_for_line_rule('query = "SELECT * FROM users WHERE id=" + user_id')
