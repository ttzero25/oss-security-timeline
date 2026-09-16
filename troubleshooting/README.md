# Troubleshooting

## 심층 조사가 미실행으로 표시됨

웹은 심층 조사 상태를 SQLite의 `research_runs`와 `data/research/` 산출물을 함께 사용해 구분합니다. `audit.json`만 있으면 `정적 조사만 완료`, `orchestration.json`도 있으면 서버 시작 시 DB로 이관됩니다. 두 파일이 모두 없을 때만 `미실행`입니다. 서버를 재시작해도 결과 파일이 DB에 들어오지 않으면 두 JSON의 `repo`와 `commit` 값이 서로 같은지 확인하세요. 대상 코드는 이관 과정에서 실행되지 않습니다.

| Symptom | Check | Action |
| --- | --- | --- |
| GitHub HTTP 403 or incomplete collection | `sync` coverage and warnings; web startup authentication label | Supply a read-only `GITHUB_TOKEN`, or log in with `gh auth login` for the web. Restart the web process after changing authentication, then retry after any active API limit resets. Existing DB records are retained. |
| CWE or referenced-commit comparison is missing | Advisory source fields and last collection time | Recollect the repository with authentication. These fields were not stored by older collection runs; a missing CWE is shown as `미기재`, not inferred. |
| A web investigation stopped during a server restart | Lab status, retry counter, and repository's last sync | A saved running job is queued and resumed when the loopback server starts. Transient API, OS, or runtime failures retry up to three times with a bounded delay; deterministic input errors stop immediately. Completed DB and audit records remain. |
| Commit collection says incomplete | `--max-pages` and repo history size | Raise the page cap and run again. |
| Package list is missing or partial | Manifest and Git tree coverage | Check the default branch's package manifests; raise `--max-manifests` if needed. |
| `audit` has no findings | Supported languages and source/sink patterns | Inspect the checkout manually; an empty scan is not evidence that the code is safe. |
| `poc-verify` cannot start | Runtime executable and manifest commands | Confirm the command exists on `PATH` and dependencies are already available. Docker is needed only with `--container`. |
| `disclosure` rejects a claim | Claim fields, file citations, PoC hashes | Fill the missing evidence or rerun PoC verification after editing its files. |
| Local web page is unavailable | `tools/web.py` process and port | Start the server again or choose another `--port`; it binds only to `127.0.0.1`. |
