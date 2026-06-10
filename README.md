# RepoRisk Scanner

RepoRisk Scanner is a small Python CLI for defensive local code review. It scans files in a local repository and reports possible cyber-risk patterns such as fake-or-real looking secrets, risky Python APIs, weak hashes and insecure configuration.

This project is intentionally narrow. It is a learning-focused static scanner, not a vulnerability scanner for live systems and not a replacement for mature SAST or secret-scanning tools.

## Scope and authorized use

Use RepoRisk only on local repositories that you own or have permission to review.

RepoRisk only reads local files from the path you provide. It does **not**:

- scan networks, websites, GitHub organizations or cloud accounts;
- validate whether credentials are real;
- exploit vulnerabilities;
- include payloads, malware behavior, brute forcing or credential harvesting.

## Features

- Local recursive file scanning.
- Ignores common directories such as `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `dist` and `build`.
- Supports common code/text files such as `.py`, `.js`, `.ts`, `.json`, `.env`, `.yml`, `.yaml`, `.toml`, `.ini`, `.md` and `.txt`.
- Regex rules for possible secrets and configuration issues.
- AST-based Python detectors for selected risky API usage.
- Inline suppression comments for reviewed findings.
- Severity filtering and optional fail-on threshold for local or CI use.
- Markdown and JSON reports by default.
- Optional SARIF report for code-scanning style workflows.

## Installation

RepoRisk requires Python 3.11 or newer.

```bash
python -m pip install -e ".[dev]"
```

The package installs the `reporisk` command. You can also run it with `python -m reporisk`.

## Basic usage

Run a local scan against the included fake insecure sample:

```bash
python -m reporisk examples/insecure_sample --reports-dir reports --sarif
```

Short example output:

```text
RepoRisk Scanner completed
Scanned path: /path/to/RepoRisk/examples/insecure_sample
Files scanned: 3
Findings: 14
Suppressed findings: 0
Markdown report: reports/report.md
JSON report: reports/report.json
SARIF report: reports/report.sarif
```

Other useful options:

```bash
# Hide findings below high severity in normal reports
reporisk examples/insecure_sample --min-severity high --reports-dir reports-high

# Return exit code 1 if high or critical findings are present
reporisk examples/insecure_sample --fail-on high

# Scan another local repository
reporisk /path/to/local/repository --reports-dir reports
```

## Example Markdown report output

```markdown
# RepoRisk Scanner Report

- Tool version: `0.1.0`
- Files scanned: `3`
- Total findings: `2`
- Suppressed findings: `1`

## Severity Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 1 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

## Suppression Summary

| Rule ID | Suppressed Count |
|---|---:|
| `PY-EVAL-001` | 1 |

## Findings

### 1. Possible private key material

- Severity: `critical`
- Rule ID: `SECRET-PRIVATE-KEY-001`
- Category: `secrets`
- File: `private_key.txt`
- Line: `1`

| Field | Value |
|---|---|
| Explanation | A private key block appears to be stored in the repository. |
| Remediation | Remove the key from version control, rotate it, and use a secret manager or environment variable. |
| Line snippet | `-----BEGIN PRIVATE KEY-----` |
```

## Rule list

Severity is a triage hint. It does not prove exploitability.

| Rule ID | Severity | Detection style | Notes |
|---|---|---|---|
| `SECRET-PRIVATE-KEY-001` | Critical | Regex | Private key block markers. |
| `SECRET-AWS-KEY-001` | Critical | Regex | AWS-style access key IDs. |
| `SECRET-GITHUB-TOKEN-001` | Critical | Regex | GitHub token-like values. |
| `SECRET-GENERIC-001` | High | Regex | Secret-like variable names with literal values. |
| `SECRET-PASSWORD-001` | High | Regex | Password-like variable names with literal values. |
| `PY-EVAL-001` | High | Python AST | Calls to `eval()`. |
| `PY-EXEC-001` | High | Python AST | Calls to `exec()`. |
| `PY-SUBPROCESS-SHELL-TRUE-001` | High | Python AST | `subprocess` calls using `shell=True`. |
| `PY-YAML-LOAD-001` | High | Python AST | `yaml.load()` without an obvious SafeLoader. |
| `PY-PICKLE-001` | High | Python AST | `pickle.load()` or `pickle.loads()`. |
| `PY-REQUESTS-VERIFY-FALSE-001` | Medium | Python AST | `requests` calls with `verify=False`. |
| `PY-WEAK-HASH-001` | Medium | Python AST | `hashlib.md5()` or `hashlib.sha1()`. |
| `CONFIG-DEBUG-TRUE-001` | Medium | Regex | Debug settings enabled. |
| `CONFIG-CORS-WILDCARD-001` | Medium | Regex | Wildcard or broad CORS settings. |
| `SQL-CONCAT-001` | Medium | Heuristic line detector | Possible SQL string concatenation. |

## Suppressions

Suppress all RepoRisk findings on a line:

```python
eval(user_input)  # reporisk: ignore
```

Suppress one rule on a line:

```python
eval(user_input)  # reporisk: ignore PY-EVAL-001
```

Suppressed findings are removed from the normal findings list. Markdown and JSON reports still include suppression counts so reviewers can see that suppressions were used.

## Design tradeoffs

- Python risky API rules use AST matching because call syntax and import aliases matter.
- Secret and config rules use regex because many secrets/config files are not Python and do not have a shared syntax tree.
- The scanner is intentionally local-only to keep the project focused on defensive code review.
- The rule engine is kept small and readable instead of trying to implement full program analysis.
- Reports favor clear evidence and remediation text over high-confidence claims.

## False-positive limitations

RepoRisk findings are review prompts. They may be wrong or incomplete.

Known limitations:

- Fake sample secrets, tests and documentation can look like real secrets.
- Real secrets may not match the current patterns.
- AST detectors do not perform taint tracking, reachability analysis or data-flow analysis.
- Multi-line or dynamically generated code may be missed.
- The tool does not check dependency CVEs.
- The tool does not verify whether credentials are live.

## What this does not do

RepoRisk does not find all vulnerabilities. It does not replace code review, threat modeling, dependency scanning, secret scanning services or professional security testing. It also does not interact with remote targets or running applications.

## Why I built this

I built RepoRisk as a defensive cybersecurity portfolio project to practice secure code review and learn how static analysis tools work. I wanted the project to stay realistic: local files in, findings and reports out, with no exploitation or target scanning. The goal is to recognize common repository risks, understand the tradeoffs behind rule design and produce evidence that another developer could review.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Validation notes](docs/VALIDATION.md)
- [Changelog](CHANGELOG.md)

## Running tests

```bash
pytest
```
