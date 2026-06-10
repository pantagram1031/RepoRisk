from pathlib import Path

from reporisk.scanner import scan_repository


def _ids_for_source(tmp_path: Path, source: str) -> set[str]:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return {finding.rule_id for finding in scan_repository(tmp_path).findings}


def test_ast_detects_eval_and_exec(tmp_path: Path) -> None:
    ids = _ids_for_source(tmp_path, "eval(user_input)\nexec(dynamic_code)\n")
    assert "PY-EVAL-001" in ids
    assert "PY-EXEC-001" in ids


def test_ast_detects_subprocess_alias_shell_true(tmp_path: Path) -> None:
    ids = _ids_for_source(
        tmp_path,
        "import subprocess as sp\nsp.run('echo demo', shell=True)\n",
    )
    assert "PY-SUBPROCESS-SHELL-TRUE-001" in ids


def test_ast_detects_requests_alias_verify_false(tmp_path: Path) -> None:
    ids = _ids_for_source(
        tmp_path,
        "from requests import get\nget('https://example.invalid', verify=False)\n",
    )
    assert "PY-REQUESTS-VERIFY-FALSE-001" in ids


def test_ast_detects_hashlib_aliases(tmp_path: Path) -> None:
    ids = _ids_for_source(tmp_path, "from hashlib import md5\nmd5(b'demo')\n")
    assert "PY-WEAK-HASH-001" in ids


def test_ast_detects_yaml_load_without_safeloader(tmp_path: Path) -> None:
    ids = _ids_for_source(tmp_path, "import yaml as y\ny.load(config_text)\n")
    assert "PY-YAML-LOAD-001" in ids


def test_ast_allows_yaml_load_with_safeloader(tmp_path: Path) -> None:
    ids = _ids_for_source(tmp_path, "import yaml\nyaml.load(config_text, Loader=yaml.SafeLoader)\n")
    assert "PY-YAML-LOAD-001" not in ids


def test_ast_allows_yaml_load_with_imported_safeloader(tmp_path: Path) -> None:
    ids = _ids_for_source(
        tmp_path,
        "import yaml\nfrom yaml import SafeLoader\nyaml.load(config_text, Loader=SafeLoader)\n",
    )
    assert "PY-YAML-LOAD-001" not in ids


def test_ast_allows_subprocess_shell_false(tmp_path: Path) -> None:
    ids = _ids_for_source(
        tmp_path,
        "import subprocess\nsubprocess.run(['echo', 'demo'], shell=False)\n",
    )
    assert "PY-SUBPROCESS-SHELL-TRUE-001" not in ids


def test_ast_allows_requests_verify_true(tmp_path: Path) -> None:
    ids = _ids_for_source(
        tmp_path,
        "import requests\nrequests.get('https://example.invalid', verify=True)\n",
    )
    assert "PY-REQUESTS-VERIFY-FALSE-001" not in ids


def test_ast_allows_sha256(tmp_path: Path) -> None:
    ids = _ids_for_source(tmp_path, "import hashlib\nhashlib.sha256(b'demo').hexdigest()\n")
    assert "PY-WEAK-HASH-001" not in ids


def test_ast_detects_pickle_aliases(tmp_path: Path) -> None:
    ids = _ids_for_source(tmp_path, "from pickle import loads\nloads(blob)\n")
    assert "PY-PICKLE-001" in ids
