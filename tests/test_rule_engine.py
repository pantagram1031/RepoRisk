from pathlib import Path

from reporisk.rules.engine import RuleEngine


def _rule_ids_for_line(line: str, filename: str = "app.py") -> set[str]:
    engine = RuleEngine()
    findings = engine.scan_lines(Path(filename), filename, [line])
    return {finding.rule_id for finding in findings}


def test_detects_eval_and_exec() -> None:
    assert "PY-EVAL-001" in _rule_ids_for_line("result = eval(user_input)")
    assert "PY-EXEC-001" in _rule_ids_for_line("exec(dynamic_code)")


def test_detects_subprocess_shell_true() -> None:
    assert "PY-SUBPROCESS-SHELL-TRUE-001" in _rule_ids_for_line('subprocess.run("echo hi", shell=True)')


def test_detects_unsafe_yaml_load_but_not_safe_loader() -> None:
    assert "PY-YAML-LOAD-001" in _rule_ids_for_line("yaml.load(config_text)")
    assert "PY-YAML-LOAD-001" not in _rule_ids_for_line("yaml.load(config_text, Loader=yaml.SafeLoader)")


def test_detects_pickle_requests_and_weak_hash() -> None:
    assert "PY-PICKLE-001" in _rule_ids_for_line("pickle.loads(blob)")
    assert "PY-REQUESTS-VERIFY-FALSE-001" in _rule_ids_for_line('requests.get("https://example.invalid", verify=False)')
    assert "PY-WEAK-HASH-001" in _rule_ids_for_line('hashlib.sha1(b"demo")')


def test_detects_sql_string_concatenation() -> None:
    assert "SQL-CONCAT-001" in _rule_ids_for_line('query = "SELECT * FROM users WHERE id=" + user_id')
