# RepoRisk Scanner

RepoRisk Scanner is a Python command-line tool for defensive repository review. It statically scans a local source-code directory for common cyber-risk indicators such as hardcoded secrets, risky Python APIs, weak cryptographic primitives and insecure configuration patterns.

The project is designed for portfolio and learning use, but the implementation aims to be practical and auditable: rules are small, reports are explicit and findings include remediation guidance. RepoRisk is not a replacement for professional SAST, secret-scanning or dependency-scanning platforms.

## Authorized Local Code Review Only

RepoRisk Scanner is intended only for **authorized local code review**. Use it on repositories that you own, maintain or have explicit permission to assess.

The tool is passive and local-only:

- It reads files from a user-provided local directory.
- It does not attack systems, exploit vulnerabilities or validate credentials.
- It does not scan public targets, URLs, networks, cloud accounts or GitHub organizations.
- It does not include offensive payloads, malware behavior, brute forcing or credential harvesting.

## Features

- Recursive local directory scanning.
- Safe handling for common text and code extensions: `.py`, `.js`, `.ts`, `.json`, `.env`, `.yml`, `.yaml`, `.toml`, `.ini`, `.md` and `.txt`.
- Ignore rules for common generated, dependency and cache directories such as `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `dist` and `build`.
- Rule engine where each rule has an ID, title, severity, description, remediation and either a regex pattern or detector function.
- Built-in rules for possible secrets, private keys, weak hashes, unsafe deserialization, command execution risks, disabled TLS verification, debug mode, wildcard CORS and possible SQL string concatenation.
- Markdown report for human review.
- JSON report for automation and future CI integration.
- Pytest coverage for major detector categories.
- Safe intentionally insecure sample files under `examples/insecure_sample/` for demonstrations.

## Installation

RepoRisk Scanner requires Python 3.11 or newer.

Install locally from the repository root:

```bash
python -m pip install -e .
```

Install development test dependencies:

```bash
python -m pip install -e '.[dev]'
```

The package installs a CLI command named `reporisk`.

## CLI Usage Examples

Scan the current directory and write reports to `reports/`:

```bash
reporisk .
```

Scan a specific local repository:

```bash
reporisk /path/to/local/repository
```

Scan the included demonstration sample:

```bash
reporisk ./examples/insecure_sample
```

Write reports to a custom reports directory:

```bash
reporisk ./examples/insecure_sample --reports-dir ./security-reports
```

Run as a Python module during development:

```bash
python -m reporisk ./examples/insecure_sample --reports-dir reports
```

RepoRisk writes two report files by default:

- `reports/report.md`
- `reports/report.json`

Example terminal output:

```text
RepoRisk Scanner completed
Scanned path: /path/to/repository
Files scanned: 3
Findings: 14
Markdown report: reports/report.md
JSON report: reports/report.json
```

## Example Markdown Report Output

A Markdown finding includes severity, file path, line number, rule ID, explanation, remediation and a short line snippet.

```markdown
# RepoRisk Scanner Report

- Tool version: `0.1.0`
- Scanned path: `/path/to/repository`
- Files scanned: `3`
- Total findings: `2`

## Severity Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 1 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

## Findings

### 1. Possible private key material

- Severity: `critical`
- Rule ID: `SECRET-PRIVATE-KEY-001`
- Category: `secrets`
- File: `config/dev.key`
- Line: `1`

| Field | Value |
|---|---|
| Explanation | A private key block appears to be stored in the repository. |
| Remediation | Remove the key from version control, rotate it, and use a secret manager or environment variable. |
| Line snippet | `-----BEGIN PRIVATE KEY-----` |

### 2. Use of eval

- Severity: `high`
- Rule ID: `PY-EVAL-001`
- Category: `risky-code`
- File: `app.py`
- Line: `42`
```

The JSON report contains the same findings in a machine-readable structure with summary counts by severity.

## Rule List and Severity Levels

Severity is a triage aid, not a guarantee of exploitability. Findings should be reviewed in context.

| Rule ID | Severity | Category | What it flags |
|---|---|---|---|
| `SECRET-PRIVATE-KEY-001` | Critical | Secrets | Private key block markers in repository files. |
| `SECRET-AWS-KEY-001` | Critical | Secrets | AWS-style access key IDs. |
| `SECRET-GITHUB-TOKEN-001` | Critical | Secrets | GitHub token-like values. |
| `SECRET-GENERIC-001` | High | Secrets | Literal values assigned to secret-like variable names such as API keys or access tokens. |
| `SECRET-PASSWORD-001` | High | Secrets | Literal values assigned to password-like variable names. |
| `PY-EVAL-001` | High | Risky code | Python `eval()` usage. |
| `PY-EXEC-001` | High | Risky code | Python `exec()` usage. |
| `PY-SUBPROCESS-SHELL-TRUE-001` | High | Risky code | `subprocess` calls using `shell=True`. |
| `PY-YAML-LOAD-001` | High | Risky code | `yaml.load()` calls without an obvious SafeLoader. |
| `PY-PICKLE-001` | High | Risky code | `pickle.load()` or `pickle.loads()` usage. |
| `PY-REQUESTS-VERIFY-FALSE-001` | Medium | Risky code | `requests` calls with TLS certificate verification disabled. |
| `PY-WEAK-HASH-001` | Medium | Risky code | `hashlib.md5()` or `hashlib.sha1()` usage. |
| `CONFIG-DEBUG-TRUE-001` | Medium | Configuration | Debug mode enabled in config-like files. |
| `CONFIG-CORS-WILDCARD-001` | Medium | Configuration | Wildcard or overly broad CORS settings. |
| `SQL-CONCAT-001` | Medium | Risky code | Possible SQL string concatenation. |

## False-Positive Limitations

RepoRisk uses lightweight static heuristics and line-oriented matching. It is useful for surfacing review candidates, but it does not prove that code is exploitable and it does not find every vulnerability.

Important limitations:

- Secret detection can flag placeholders, examples, tests or intentionally fake values.
- Some true secrets may not match the built-in patterns.
- Risky APIs such as `eval`, `pickle` or `shell=True` may be safe in limited contexts, but they deserve review.
- The scanner does not perform full AST parsing, data-flow analysis, taint tracking or framework-specific reasoning.
- Multi-line calls and dynamically constructed code may be missed.
- The scanner does not check dependencies for known CVEs.
- The scanner does not verify whether a credential is live or whether a finding is reachable at runtime.

Treat results as prompts for manual secure-code review, not as final vulnerability determinations.

## Defensive Cybersecurity Context

RepoRisk Scanner relates to defensive cybersecurity and secure software development in several ways:

- **Secure code review:** It highlights patterns that reviewers commonly investigate during application security assessments.
- **Secret hygiene:** It helps identify possible credentials or private key material that should not be committed to source control.
- **Risk detection:** It provides structured findings with severity, evidence and remediation guidance so teams can triage potential issues.
- **Shift-left security:** It can be run locally before code is shared, helping developers catch obvious issues earlier in the software development lifecycle.
- **Security education:** The included sample files and small rule engine make it easier to understand how static detection works and where heuristic analysis has limits.

The project is intentionally scoped to local, defensive analysis. Its purpose is to help developers recognize and reduce common repository risks, not to exploit applications or assess systems without authorization.

## Future Improvements

Planned or potential improvements include:

- AST-based Python detectors to reduce false positives for selected rules.
- External YAML or JSON rule loading so users can add custom rules without editing Python code.
- Inline suppression comments for reviewed false positives.
- SARIF output for code-scanning integrations.
- Severity filtering and non-zero exit codes for CI workflows.
- Better multi-line detection for function calls and configuration blocks.
- Additional framework-aware checks for Django, Flask, FastAPI, Node.js and common infrastructure-as-code formats.
- Baseline support so teams can track only new findings over time.

## Demonstration Sample

The `examples/insecure_sample/` directory contains intentionally insecure-looking local files so the scanner can demonstrate findings safely. These samples are placeholders for static-analysis demonstrations only and are not exploit code.

Run:

```bash
reporisk ./examples/insecure_sample
```

Then inspect:

```bash
cat reports/report.md
cat reports/report.json
```

## Running Tests

```bash
pytest
```
