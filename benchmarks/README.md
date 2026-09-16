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

The bundled cases are synthetic and include fixed-command allowlists, imported Python class-method paths, JavaScript cross-module calls and scope isolation, plus Go local-package calls and shell-free argv execution. They measure deterministic regressions, not real-world zero-day performance. Historical vulnerable/fixed commits and dynamic build/PoC metrics must be added before making broader accuracy claims.
