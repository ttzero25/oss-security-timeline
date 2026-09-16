# Troubleshooting

| Symptom | Check | Action |
| --- | --- | --- |
| GitHub HTTP 403 or incomplete collection | `sync` coverage and warnings | Supply a read-only `GITHUB_TOKEN`; retry after the API limit resets. Existing DB records are retained. |
| Commit collection says incomplete | `--max-pages` and repo history size | Raise the page cap and run again. |
| Package list is missing or partial | Manifest and Git tree coverage | Check the default branch's package manifests; raise `--max-manifests` if needed. |
| `audit` has no findings | Supported languages and source/sink patterns | Inspect the checkout manually; an empty scan is not evidence that the code is safe. |
| `poc-verify` cannot start | Docker daemon and local image | Start the daemon and prepare the configured image. Use `--local` only for trusted test code. |
| `disclosure` rejects a claim | Claim fields, file citations, PoC hashes | Fill the missing evidence or rerun PoC verification after editing its files. |
| Local web page is unavailable | `tools/web.py` process and port | Start the server again or choose another `--port`; it binds only to `127.0.0.1`. |
