# Roadmap

RepoRisk is intentionally small. These are realistic next steps that would make it more useful without changing the local-only defensive scope.

## Near Term

- Improve multi-line detection for simple patterns that currently fit poorly into line-by-line rules.
- Add a documented custom rule loading format for local experiments.
- Polish SARIF output so rule metadata, locations and help text are easier to inspect in code-scanning viewers.
- Add baseline support so a repository can track only new findings after an initial review.
- Expand tests around malformed files, ignored directories and suppression edge cases.

## Later

- Add more framework-aware Python checks where AST matching is enough to keep rules understandable.
- Improve report summaries with clearer counts by rule and category.
- Add optional config for include and exclude paths.
- Compare output against dedicated SAST, secret-scanning and dependency-scanning tools in documentation.
- Explore future integration points with dependency scanning without building a dependency scanner into RepoRisk.

## Out of Scope

- Network scanning.
- Web application scanning.
- GitHub organization scanning.
- Cloud account scanning.
- Credential validation.
- Exploit code, payloads, brute forcing or malware behavior.
