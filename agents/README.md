# Agent roles

`registry.json` is the role index used by the local web view. Runtime classes live in the `oss_timeline` Python package so the installed CLI keeps its imports stable.

Each role has its own file: [InventoryAgent](InventoryAgent.md), [ChangeAgent](ChangeAgent.md), [AdvisoryAgent](AdvisoryAgent.md), [CandidateAgent](CandidateAgent.md), [RepositoryProfilerAgent](RepositoryProfilerAgent.md), [SourceScanAgent](SourceScanAgent.md), [ReachabilityGateAgent](ReachabilityGateAgent.md), [ResearchOrchestrator](ResearchOrchestrator.md), [PocValidatorAgent](PocValidatorAgent.md), [EvidenceGateAgent](EvidenceGateAgent.md), and [DisclosureAgent](DisclosureAgent.md).

Timeline flow: `InventoryAgent` → (`ChangeAgent` + `AdvisoryAgent` concurrently) → `CandidateAgent` → database/report. Research flow: `RepositoryProfilerAgent` → `SourceScanAgent` → `ReachabilityGateAgent` → `ResearchOrchestrator` → bounded PoC preparation → `PocValidatorAgent` → `EvidenceGateAgent` → `DisclosureAgent` → research timeline events.

These are deterministic Python roles. Concurrent execution currently applies only to the change and advisory collectors; the research gates are sequential because each needs the preceding evidence.
