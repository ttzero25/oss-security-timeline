# Rules

- [source-scan.md](source-scan.md): what the code scanner treats as a hypothesis and its known limits.
- [verification.md](verification.md): checks required before a PoC result can support a report.
- [disclosure.md](disclosure.md): minimum evidence for the private GHSA/CVE draft.

The executable checks are implemented in `oss_timeline/research.py`. Changes to these rules should be accompanied by corresponding code and regression checks.
