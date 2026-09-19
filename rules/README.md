# Rules

- [source-scan.md](source-scan.md): what the code scanner treats as a hypothesis and its known limits.
- [orchestration.md](orchestration.md): allowlisted automatic reproduction and manual-only submission boundaries.
- [verification.md](verification.md): checks required before a PoC result can support a report.
- [disclosure.md](disclosure.md): minimum evidence for the private GHSA/CVE draft.
- [aggregation.md](aggregation.md): privacy, authentication, deduplication, and publication boundaries for team totals.

The executable checks are implemented in `oss_timeline/research.py`. Changes to these rules should be accompanied by corresponding code and regression checks.
