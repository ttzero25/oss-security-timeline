# ReachabilityGateAgent

Input: a source-to-sink hypothesis with a cited trace and the repository profile. Output: a mechanical default-reachability decision with the external entry kind and supporting code location.

The gate accepts supported HTTP, CLI, message, workflow, modeled request, and explicit argv/environment/socket input entry points. Repository profiling ranks production entry points ahead of tooling, examples, and tests, records nearby handler names, and prevents a large test tree from consuming the complete entry-point ledger. CLI command handlers are accepted only when a default CLI entry point exists in the same file. If the gate cannot connect an entry point to the trace, it records `REVIEW_REQUIRED` and stops automatic PoC generation. It does not infer deployment configuration that is absent from the checkout.
