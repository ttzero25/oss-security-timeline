# ResearchOrchestrator

Input: an audited checkout pinned to an exact commit. Output: `orchestration.json`, isolated PoC evidence for supported candidates, and private GHSA/CVE drafts when every automated gate passes.

The orchestrator ranks code hypotheses, resolves a network-disabled read-only runtime, and generates only allowlisted harmless marker-based reproductions. Automatic reproduction currently supports Python command/code-execution paths. Unsupported candidates remain blocked with a reason instead of being reported as vulnerabilities.

The default verifier uses a temporary workspace, a reduced environment, timeout/output bounds, and additional OS resource limits on Linux. It is not a full file/network sandbox; `--container` remains available for stronger isolation. A successful contrast is not proof of novelty: the collected GitHub/OSV snapshot is checked for likely duplicates and every generated draft states that broader human review is required. External submission is disabled and must be performed by a person.
