# Tools

The main command line is `python3 -m oss_timeline`. It provides `sync`, `watch`, `report`, `audit`, `poc-init`, `poc-verify` and `disclosure`.

`python3 tools/web.py --port 8765` starts the loopback-only dashboard. Home shows cumulative counts and agent roles; the lab accepts a public GitHub repository URL and runs advisory collection plus static code research; summary compares results by repository and package; the relationship graph connects repositories, packages, advisories, CVEs, CWEs, referenced fix commits and code hypotheses. It writes local `data/timeline.sqlite3` and `data/research/`, but never runs a PoC or submits a disclosure automatically. Only one web research job runs at a time. Its results are bounded by 100 API pages and 100 manifests, so review coverage warnings before treating them as complete.

For GitHub API calls the web process uses `GITHUB_TOKEN` first, then the logged-in GitHub CLI token if available. Neither is written to disk or the HTTP response. When the limit is exhausted, the collector waits briefly if the reset is near and otherwise returns a retry message; authentication increases the quota but does not remove GitHub's limits.

After the first observation, commit collection requests only the interval since the stored `last_sync`. This reduces rate-limit pressure without relabeling an incomplete historical backfill as complete.

The lab's before/after section compares advisory-linked vulnerable and patched package versions. It also displays removed and added lines from at most five commit URLs explicitly cited by advisories and belonging to the selected GitHub repository. These referenced diffs are evidence to review, not an automatic claim that a commit fully fixes a vulnerability.

Web job status is saved under `data/web-jobs.json`. On restart, a job that was still running is marked interrupted rather than silently disappearing; it is not automatically resumed.
