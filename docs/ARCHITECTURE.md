# RepoRisk Architecture

RepoRisk is a local-only static scanner. It reads files from a directory supplied by the user, applies a small set of rules and writes reports. It does not execute project code, contact external services or validate credentials.

## Scanner flow

1. The CLI parses a local path and report options.
2. `scan_repository()` resolves and validates the path as a directory.
3. File traversal skips common generated and dependency directories such as `.git`, `node_modules`, virtual environments, `dist` and `build`.
4. Supported text/code files are read as UTF-8 text where possible; binary files are skipped.
5. Python files are parsed with `ast.parse()` for selected Python-specific rules.
6. Line-oriented rules scan file contents for secrets, config patterns and simple cross-language patterns.
7. Inline suppression comments are applied after findings are created.
8. Optional severity filtering hides lower-severity visible findings from reports.
9. Markdown, JSON and optional SARIF reports are written under the chosen reports directory.

## Rule engine design

Rules are small Python dataclasses. Each rule includes:

- `id`
- `title`
- `severity`
- `category`
- `description`
- `remediation`
- either a regex pattern, a line detector callback or an AST detector callback

The engine intentionally stays simple so a student maintainer can inspect how a finding was generated.

## AST rules vs regex rules

Some Python rules are better handled with AST matching because syntax matters. RepoRisk uses AST detectors for:

- `eval()`
- `exec()`
- `subprocess` calls with `shell=True`
- `requests` calls with `verify=False`
- `hashlib.md5()` and `hashlib.sha1()`
- `yaml.load()` without an obvious SafeLoader
- `pickle.load()` and `pickle.loads()`

These detectors understand basic import aliases, such as `import subprocess as sp` or `from hashlib import md5`.

Regex remains appropriate for several rules:

- secret-like values and private key headers
- simple configuration patterns such as `DEBUG = True`
- wildcard CORS strings
- simple SQL string concatenation heuristics

Regex-based rules are intentionally described as possible findings because they can match examples, tests and placeholders.

## Suppression model

RepoRisk supports inline suppressions on the same line as a finding:

```python
eval(user_input)  # reporisk: ignore PY-EVAL-001
```

or all RepoRisk rules on that line:

```python
eval(user_input)  # reporisk: ignore
```

Suppressed findings are removed from the normal finding list, but reports include suppression counts so suppression usage is visible.

## False-positive tradeoffs

RepoRisk favors readable rules over complex analysis. This means:

- findings should be manually reviewed;
- some findings may be safe in context;
- multi-line or dynamic code may be missed;
- AST detectors do not perform taint tracking or full data-flow analysis;
- secret rules do not verify whether credentials are real or active.

## Why local-only

The project is scoped to defensive code review. Local-only scanning reduces risk and keeps the tool focused on source review rather than target assessment. RepoRisk does not scan networks, public URLs, GitHub organizations, cloud accounts or running services.
