# Review Checklist

Use this checklist when reviewing RepoRisk output. Findings should be treated as leads for manual review, not as final proof of a security issue.

## Finding Review

- Confirm the file and line number match the evidence shown in the report.
- Read the surrounding code or configuration before deciding severity in context.
- Check whether the sample, test or documentation file is intentionally demonstrating a risky pattern.
- Separate real application code from fixtures, generated files and teaching examples.
- Record the decision for each finding: fix, suppress with reason, accept as test/example data or investigate further.

## False-Positive Checks

- For secret-like findings, verify whether the value is a fake placeholder before escalating.
- Do not paste suspicious values into external services to test them.
- For config findings, check whether the file is used in local development only or shared deployment settings.
- For Python AST findings, check whether the risky API is reachable and whether the input is trusted.
- For suppression comments, confirm the comment is on the same line as the finding and that a rule-specific suppression is used when possible.

## Remediation Review

- Prefer removing hardcoded secret-like values instead of only suppressing them.
- Replace `eval()` and `exec()` with explicit parsing or dispatch logic.
- Keep subprocess calls as argument lists with `shell=False` unless there is a documented local reason.
- Use `yaml.safe_load()` or `yaml.load(..., Loader=yaml.SafeLoader)` for YAML parsing.
- Keep TLS verification enabled for `requests` calls.
- Use SHA-256 or stronger general-purpose hashes, and use password-hashing functions for passwords.
- Restrict debug and CORS settings in shared or deployment-like configuration.
- Re-run RepoRisk after changes and confirm the finding count changed for the expected reason.

## When to Use Other Tools

Use mature SAST tools when you need deeper language support, taint tracking, data-flow analysis, framework-aware rules or policy enforcement.

Use dedicated secret scanners when you need stronger secret pattern coverage, entropy checks, allowlists, history scanning or integration with provider-specific revocation workflows.

Use dependency scanners when you need package vulnerability data, license review, software bill of materials output or transitive dependency analysis.

RepoRisk is a small local static-analysis learning project. It can support review, but it should not be the only security control for a real repository.
