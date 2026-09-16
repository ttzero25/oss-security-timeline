# Tools

The main command line is `python3 -m oss_timeline`. It provides `sync`, `watch`, `report`, `audit`, `research-run`, `poc-init`, `poc-verify` and `disclosure`.

`python3 tools/web.py --port 8765` starts the loopback-only dashboard. Home shows cumulative counts and agent roles; the lab accepts a public GitHub repository URL and runs advisory collection, repository profiling, static code research, and supported bounded PoC contrasts; summary compares results by repository and package; the relationship graph connects repositories, packages, advisories, CVEs, CWEs, referenced fix commits and code hypotheses; reports reads generated evidence and private drafts. It writes local `data/timeline.sqlite3` and `data/research/`. The web may run only allowlisted local PoC contrasts; it never modifies a completed draft or submits a disclosure. Only one web research job runs at a time. Its results are bounded by 100 API pages and 100 manifests, so review coverage warnings before treating them as complete.

`python3 -m oss_timeline research-run TARGET` refreshes the public advisory snapshot, then coordinates recent-change-aware ranking, a cited reachability gate, a supported bounded PoC, resource-limited local-process contrast, collected-advisory duplicate review, the five-part evidence gate, and draft generation. Python traces can cross bounded top-level calls in multiple modules; every hop is stored in the audit and timeline database. A local checkout needs a previously synchronized `--db` snapshot or the draft stage stops. Add `--container` only when stronger read-only and network isolation is needed. External submission is always disabled; a person reviews and submits any draft.

For GitHub API calls the web process uses `GITHUB_TOKEN` first, then the logged-in GitHub CLI token if available. Neither is written to disk or the HTTP response. When the limit is exhausted, the collector waits briefly if the reset is near and otherwise returns a retry message; authentication increases the quota but does not remove GitHub's limits.

After the first observation, commit collection requests only the interval since the stored `last_sync`. This reduces rate-limit pressure without relabeling an incomplete historical backfill as complete.

The lab's before/after section compares advisory-linked vulnerable and patched package versions. It also displays removed and added lines from at most five commit URLs explicitly cited by advisories and belonging to the selected GitHub repository. These referenced diffs are evidence to review, not an automatic claim that a commit fully fixes a vulnerability.

Web job status is saved under `data/web-jobs.json`. On restart, a job that was still running is marked interrupted rather than silently disappearing; it is not automatically resumed.
