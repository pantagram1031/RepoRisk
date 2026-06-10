# Changelog

## 0.1.0 - Initial local scanner

- Added a Python 3.11+ local repository scanner with a `reporisk` CLI.
- Added regex-based rules for possible secrets and insecure configuration.
- Added AST-backed detectors for selected risky Python API usage.
- Added Markdown, JSON and optional SARIF reports.
- Added inline suppression comments, severity filtering and fail-on exit behavior.
- Added tests, local insecure sample files, architecture notes and validation notes.

This release is intentionally limited. Findings are heuristic review prompts, not proof that a vulnerability is exploitable.
