"""Built-in defensive detection rules for RepoRisk Scanner."""

from __future__ import annotations

import re
from pathlib import Path

from reporisk.rules import python_ast
from reporisk.rules.schema import Rule

PY_EXTENSIONS = (".py",)


def _regex(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def _possible_sql_concat(line: str, _path: Path, _line_number: int) -> bool:
    sql_words = r"(SELECT|INSERT|UPDATE|DELETE)"
    quoted_sql = rf"[\"'][^\"']*\b{sql_words}\b[^\"']*[\"']"
    return bool(
        re.search(quoted_sql + r"\s*\+", line, re.IGNORECASE)
        or re.search(r"\+\s*" + quoted_sql, line, re.IGNORECASE)
        or re.search(r"\b(query|execute)\s*\([^)]*\+[^)]*\)", line, re.IGNORECASE)
    )


def get_builtin_rules() -> list[Rule]:
    """Return the built-in local-only detection rules."""
    return [
        Rule(
            id="SECRET-PRIVATE-KEY-001",
            title="Possible private key material",
            severity="critical",
            category="secrets",
            description="A private key block appears to be stored in the repository.",
            remediation="Remove the key from version control, rotate it, and use a secret manager or environment variable.",
            pattern=_regex(r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", re.IGNORECASE),
        ),
        Rule(
            id="SECRET-AWS-KEY-001",
            title="Possible AWS access key ID",
            severity="critical",
            category="secrets",
            description="An AWS-style access key identifier appears to be hardcoded.",
            remediation="Remove the key, rotate the credential in AWS, and load it from an approved secret store.",
            pattern=_regex(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", 0),
        ),
        Rule(
            id="SECRET-GITHUB-TOKEN-001",
            title="Possible GitHub token",
            severity="critical",
            category="secrets",
            description="A GitHub token-like value appears to be hardcoded.",
            remediation="Revoke and rotate the token, remove it from history, and use environment-based secrets.",
            pattern=_regex(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b", 0),
        ),
        Rule(
            id="SECRET-GENERIC-001",
            title="Possible hardcoded secret",
            severity="high",
            category="secrets",
            description="A variable with a secret-like name appears to contain a literal value.",
            remediation="Move secrets to a secret manager or environment variable and rotate exposed values.",
            pattern=_regex(r"\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|client[_-]?secret)\b\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"),
        ),
        Rule(
            id="SECRET-PASSWORD-001",
            title="Possible hardcoded password",
            severity="high",
            category="secrets",
            description="A password-like variable appears to contain a literal value.",
            remediation="Use environment variables or a secret manager instead of hardcoding passwords.",
            pattern=_regex(r"\b(password|passwd|pwd)\b\s*[:=]\s*[\"'][^\"']{4,}[\"']"),
        ),
        Rule(
            id="PY-WEAK-HASH-001",
            title="Weak hash algorithm",
            severity="medium",
            category="risky-code",
            description="MD5 or SHA1 hashing is present; these algorithms are weak for security-sensitive uses.",
            remediation="Use SHA-256 or stronger algorithms, and use password hashing functions for passwords.",
            ast_detector=python_ast.detect_weak_hash,
            extensions=PY_EXTENSIONS,
        ),
        Rule(
            id="PY-EVAL-001",
            title="Use of eval",
            severity="high",
            category="risky-code",
            description="eval() can execute arbitrary Python code if data is attacker-controlled.",
            remediation="Avoid eval(); use explicit parsing such as json.loads or safer control flow.",
            ast_detector=python_ast.detect_eval,
            extensions=PY_EXTENSIONS,
        ),
        Rule(
            id="PY-EXEC-001",
            title="Use of exec",
            severity="high",
            category="risky-code",
            description="exec() can execute arbitrary Python code if data is attacker-controlled.",
            remediation="Avoid exec(); replace dynamic execution with explicit functions or dispatch tables.",
            ast_detector=python_ast.detect_exec,
            extensions=PY_EXTENSIONS,
        ),
        Rule(
            id="PY-SUBPROCESS-SHELL-TRUE-001",
            title="Subprocess shell=True",
            severity="high",
            category="risky-code",
            description="subprocess with shell=True can introduce command injection risks.",
            remediation="Pass commands as argument lists and keep shell=False unless a shell is strictly required.",
            ast_detector=python_ast.detect_subprocess_shell_true,
            extensions=PY_EXTENSIONS,
        ),
        Rule(
            id="PY-YAML-LOAD-001",
            title="Unsafe YAML loading",
            severity="high",
            category="risky-code",
            description="yaml.load() without SafeLoader can deserialize unsafe objects.",
            remediation="Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
            ast_detector=python_ast.detect_yaml_load_without_safe_loader,
            extensions=PY_EXTENSIONS,
        ),
        Rule(
            id="PY-PICKLE-001",
            title="Pickle deserialization",
            severity="high",
            category="risky-code",
            description="pickle deserialization can execute code when reading untrusted data.",
            remediation="Avoid pickle for untrusted data; use safer formats such as JSON where possible.",
            ast_detector=python_ast.detect_pickle_load,
            extensions=PY_EXTENSIONS,
        ),
        Rule(
            id="PY-REQUESTS-VERIFY-FALSE-001",
            title="TLS verification disabled",
            severity="medium",
            category="risky-code",
            description="requests verify=False disables certificate validation.",
            remediation="Remove verify=False and fix certificate trust configuration instead.",
            ast_detector=python_ast.detect_requests_verify_false,
            extensions=PY_EXTENSIONS,
        ),
        Rule(
            id="CONFIG-DEBUG-TRUE-001",
            title="Debug mode enabled",
            severity="medium",
            category="configuration",
            description="Debug mode appears to be enabled in configuration.",
            remediation="Disable debug mode in shared, staging, and production configuration.",
            pattern=_regex(r"\b(DEBUG|debug)\b\s*[:=]\s*(True|true|1|yes|on)\b"),
        ),
        Rule(
            id="CONFIG-CORS-WILDCARD-001",
            title="Wildcard CORS configuration",
            severity="medium",
            category="configuration",
            description="CORS appears to allow wildcard origins.",
            remediation="Restrict allowed origins to the exact trusted domains required by the application.",
            pattern=_regex(r"\b(CORS[_A-Z0-9]*|cors[_a-z0-9]*|allowed_origins|origins)\b[^\n]*(\*|all_origins|allow_all)"),
        ),
        Rule(
            id="SQL-CONCAT-001",
            title="Possible SQL string concatenation",
            severity="medium",
            category="risky-code",
            description="SQL appears to be built using string concatenation, which can lead to injection if inputs are untrusted.",
            remediation="Use parameterized queries or an ORM query builder instead of concatenating SQL strings.",
            detector=_possible_sql_concat,
        ),
    ]
