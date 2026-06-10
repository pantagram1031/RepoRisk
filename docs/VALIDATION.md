# RepoRisk Validation Notes

This document records simple commands for validating the project locally. Commands should be run from the repository root.

## Install

```bash
python -m pip install -e ".[dev]"
```

Expected result: the package installs in editable mode and exposes the `reporisk` command.

## Tests

```bash
pytest
```

Expected result: all unit tests pass.

The tests cover:

- AST-backed Python detectors;
- secret and configuration regex rules;
- suppression comments;
- severity filtering;
- fail-on exit code behavior;
- Markdown, JSON and SARIF report generation;
- local file traversal behavior.

## Insecure sample scan

```bash
python -m reporisk examples/insecure_sample --reports-dir reports --sarif
```

Expected result:

- exit code `0`;
- Markdown report at `reports/report.md`;
- JSON report at `reports/report.json`;
- SARIF report at `reports/report.sarif`;
- findings for the intentionally fake sample issues.

The sample intentionally triggers possible findings for fake credentials, a placeholder private key marker, debug/CORS settings, weak hashing, unsafe Python APIs and SQL concatenation.

## Safe sample scan

```bash
python -m reporisk examples/safe_sample --reports-dir reports-safe --sarif
```

Expected result:

- exit code `0`;
- Markdown report at `reports-safe/report.md`;
- JSON report at `reports-safe/report.json`;
- SARIF report at `reports-safe/report.sarif`;
- 0 findings;
- 0 suppressed findings.

The safe sample uses fake local placeholders only. It demonstrates safer patterns for the current rules, including `yaml.load(..., Loader=SafeLoader)`, `subprocess.run(..., shell=False)`, `requests.get(..., verify=True)`, `hashlib.sha256(...)`, `debug: false` and restricted CORS origins.

## Fail-on behavior

```bash
python -m reporisk examples/insecure_sample --fail-on high
```

Expected result: exit code `1`, because the sample intentionally contains high and critical severity findings.

## Severity filtering

```bash
python -m reporisk examples/insecure_sample --min-severity high --reports-dir reports-high
```

Expected result: report files are written under `reports-high/`, and medium-severity findings are excluded from the normal findings list.

## Known limitations

- The scanner uses heuristics and can produce false positives and false negatives.
- AST detectors do not perform taint tracking or reachability analysis.
- Regex secret detection can match intentionally fake values in examples or tests.
- RepoRisk does not validate credentials or test whether a finding is exploitable.
- RepoRisk does not scan remote systems, networks, cloud accounts or GitHub organizations.
