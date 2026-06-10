from pathlib import Path

from reporisk.rules.engine import RuleEngine


def _ids(line: str, filename: str = "settings.py") -> set[str]:
    return {finding.rule_id for finding in RuleEngine().scan_lines(Path(filename), filename, [line])}


def test_detects_private_key_and_cloud_tokens() -> None:
    assert "SECRET-PRIVATE-KEY-001" in _ids("-----BEGIN PRIVATE KEY-----", "key.txt")
    assert "SECRET-AWS-KEY-001" in _ids('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')
    assert "SECRET-GITHUB-TOKEN-001" in _ids('token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"')


def test_detects_generic_secret_and_password() -> None:
    assert "SECRET-GENERIC-001" in _ids('api_key = "abcd1234secret"')
    assert "SECRET-PASSWORD-001" in _ids('password = "changeme"')


def test_detects_debug_and_wildcard_cors() -> None:
    assert "CONFIG-DEBUG-TRUE-001" in _ids("DEBUG = True")
    assert "CONFIG-CORS-WILDCARD-001" in _ids('CORS_ALLOWED_ORIGINS = ["*"]')
