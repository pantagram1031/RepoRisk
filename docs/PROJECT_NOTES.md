# Project Notes

I built RepoRisk as a defensive cybersecurity student project. I wanted a small tool that accepts a local folder, checks a few common repository risks and writes reports that another person can review. I kept the project local-only because the goal is source review practice, not testing external targets.

The main thing I learned is that static analysis is mostly about tradeoffs. A simple rule can be useful when it points a reviewer to real evidence, but it can also be noisy when it sees examples, tests or fake placeholder values. That is why RepoRisk describes findings as possible risks and includes line snippets instead of claiming certainty.

For Python risky API detection, I used the Python `ast` module because call syntax matters. A line-based pattern can miss aliases or confuse comments with code. AST matching can recognize calls like `subprocess.run(..., shell=True)` or `yaml.load(...)` in a more structured way while still staying readable.

For secrets and configuration checks, I used regular expressions because those patterns can appear in Python, YAML, environment files, Markdown and plain text. There is no shared syntax tree for all of those files. Regex is not perfect, but it is a practical fit for simple local review prompts.

False positives mean the scanner reported something that is not actually a problem in context. For example, a fake token in a training sample may look like a real secret. RepoRisk cannot decide that by itself, so the report is meant to start a review conversation rather than end it.

If I kept improving the project, I would work on better multi-line detection, clearer SARIF output, custom rule loading, baseline support and more framework-aware Python rules. I would also like to compare RepoRisk output with mature SAST and secret-scanning tools to understand where this small project is useful and where it falls short.

RepoRisk intentionally does not scan networks, websites, GitHub organizations or cloud accounts. It does not validate credentials, exploit findings, brute force anything, test live applications or check dependency CVEs. Those are different jobs and should be handled by tools and processes designed for them.
