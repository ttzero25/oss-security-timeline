# Scanner benchmark

`corpus.json` is a versioned, local and non-executing benchmark for static candidate detection. Each case is labeled `vulnerable` with expected vulnerability kinds or `clean` with no expected finding. The runner records case-level recall, precision, clean specificity, top expected rank, individual findings, the manifest hash, and scan coverage.

Run it from the repository root:

```sh
python3 -m oss_timeline benchmark
```

The default result is `data/benchmarks/latest.json` and appears in the web summary. A CI-style regression gate can require a minimum recall and maximum number of clean cases flagged:

```sh
python3 -m oss_timeline benchmark --min-recall 1 --max-false-positive-cases 1
```

The bundled synthetic cases include fixed-command allowlists, imported Python class-method paths, JavaScript cross-module calls and scope isolation, Go local-package and RPC-request calls, shell-free argv execution, explicit JWT signature-verification bypass, check-then-use filesystem races, GitHub Actions pull-request trust boundaries, destructive object access without owner scoping, untrusted privilege assignment, unsynchronized rate-limit and replay state, and regression cases for SSRF, SQL/template injection, and filesystem paths. Each newer high-impact class includes a paired clean control, such as verified JWT decoding, atomic exclusive file creation, a non-privileged pull-request workflow, an owner-scoped lookup, an administrator-only role update, or a lock covering the security-state check and mutation. The `real/` directory adds focused source excerpts from public vulnerable/fixed refs. The historical set currently covers JavaScript and Go command injection, Python unsafe deserialization and SQL injection, and Go SSRF. Every historical case must record an advisory, repository, immutable ref, source path, snapshot type, source URL, and vulnerable/fixed `pair_id`; it is not accepted as anonymous synthetic code. Focused excerpts retain only data-flow-relevant declarations and statements, so they measure detector regressions rather than full-repository accuracy.

Historical excerpts are intentionally minimal and remain regression fixtures rather than a claim that the scanner understands the entire upstream repository. Dynamic build/PoC metrics and a much larger multi-project corpus are still required before making broader accuracy claims.
