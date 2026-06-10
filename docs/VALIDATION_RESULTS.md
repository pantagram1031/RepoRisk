# Validation Results

This file records one local validation run from the repository root on 2026-06-10.

Environment used:

- Windows PowerShell
- Python 3.11.9
- RepoRisk Scanner 0.1.0 in editable install mode

## Commands and Results

| Command | Result |
|---|---|
| `python -m pip install -e ".[dev]"` | Passed with exit code 0. Editable install completed. PowerShell reported that script entry points were installed outside `PATH`, so validation used `python -m ...` commands. |
| `python -m pytest` | Passed with exit code 0. Pytest collected 26 tests and all 26 passed. |
| `python -m reporisk examples/insecure_sample --reports-dir reports --sarif` | Passed with exit code 0. Scanned 3 files and reported 14 findings with 0 suppressed findings. |
| `python -m reporisk examples/insecure_sample --fail-on high` | Returned exit code 1. This is expected because the insecure sample intentionally contains high and critical severity findings. |
| `python -m reporisk examples/insecure_sample --min-severity high --reports-dir reports-high` | Passed with exit code 0. Scanned 3 files and reported 9 visible findings after medium severity findings were filtered out. |

## Generated Report Files

The full insecure sample scan generated:

- `reports/report.md`
- `reports/report.json`
- `reports/report.sarif`

The high-and-above severity scan generated:

- `reports-high/report.md`
- `reports-high/report.json`

These report directories are ignored by Git and should not be committed.

## Insecure Sample Finding Counts

The full sample scan found 14 visible findings:

| Severity | Count |
|---|---:|
| Critical | 3 |
| High | 6 |
| Medium | 5 |
| Low | 0 |
| Info | 0 |

The `--min-severity high` scan found 9 visible findings:

| Severity | Count |
|---|---:|
| Critical | 3 |
| High | 6 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

The sample has 0 suppressed findings in both scans.

## Expected Non-Zero Fail-On Behavior

`python -m reporisk examples/insecure_sample --fail-on high` is expected to return exit code 1. The command is meant for local or CI checks where high or critical findings should fail the run. Because `examples/insecure_sample` intentionally contains high and critical examples, the non-zero exit code confirms the threshold behavior is working.

## Remaining Limitations

- Findings are review prompts, not proof that a vulnerability is exploitable.
- Regex secret and configuration rules can match fake placeholders in examples, tests or documentation.
- Current Python AST rules do not perform taint tracking, reachability analysis or full data-flow analysis.
- Multi-line and dynamically generated code may be missed.
- RepoRisk does not validate credentials, scan dependencies for CVEs, scan networks, test web targets, inspect GitHub organizations or check cloud accounts.
