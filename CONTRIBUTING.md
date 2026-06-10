# Contributing

Thanks for helping improve RepoRisk. Keep contributions defensive, local-only and easy to review.

## Local Setup

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Use `python -m reporisk` if the `reporisk` console script is not on your `PATH`.

## Running Sample Scans

```bash
python -m reporisk examples/insecure_sample --reports-dir reports --sarif
python -m reporisk examples/safe_sample --reports-dir reports-safe --sarif
```

The insecure sample should produce findings. The safe sample should produce zero findings.

## Adding a Rule

1. Decide whether the rule belongs in AST detection or line-oriented detection.
2. Use AST detection for Python call patterns where imports, aliases or keyword arguments matter.
3. Use regex or a line detector for simple text, secret-like or configuration patterns across file types.
4. Add the rule in `src/reporisk/rules/builtin_rules.py`.
5. Keep the title, description and remediation specific and modest.
6. Add tests that cover both a finding and a safe non-finding when possible.
7. Run `python -m pytest`.

## Adding a Test

- Put detector tests near the existing tests in `tests/`.
- Use fake placeholders only.
- Do not add real credentials, live tokens, payloads or exploit examples.
- Prefer small samples that show one behavior at a time.
- If a test writes reports, write them under a temporary directory or an ignored report directory.

## Safety and Scope Rules

RepoRisk must stay defensive and local-only. Contributions should not add:

- exploit code or payloads;
- malware behavior;
- brute forcing;
- credential validation;
- network scanning;
- web scanning;
- GitHub organization scanning;
- cloud scanning;
- external target testing.

Only analyze local files provided by the user. Do not include real secrets in tests, examples, documentation or issue reports.
