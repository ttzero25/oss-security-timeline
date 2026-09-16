# RepositoryProfilerAgent

Input: a checkout pinned to an exact commit. Output: a bounded coverage ledger containing file and language counts, package/build manifests, lockfiles, and likely HTTP, CLI, or message entry points.

The profile does not claim that every file has a supported vulnerability rule. Unsupported language files remain counted and are reported separately so a zero-finding scan cannot be mistaken for complete security coverage. Generated, dependency, and vendor directories are excluded and the chosen scope is recorded.
