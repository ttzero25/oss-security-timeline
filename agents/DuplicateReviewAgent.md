# DuplicateReviewAgent

Input: a research hypothesis and a fresh local public-context snapshot. Output: structured advisory, variant, and possible prior-fix matches that must be resolved before a private draft can be generated.

The agent compares CVE/GHSA aliases, CWE, vulnerability-class terms, code path and function tokens, referenced commits, advisories attached to the repository, advisories attached to the same ecosystem/package name in another tracked repository, and previously collected security-change signals. A change signal is never treated as a confirmed disclosure: it blocks automatic novelty only when both vulnerability semantics and code-path evidence match, and records `possible_prior_fix` for human review. No external report is submitted.
