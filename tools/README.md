# Tools

The main command line is `python3 -m oss_timeline`. It provides `sync`, `watch`, `report`, `audit`, `poc-init`, `poc-verify` and `disclosure`.

`python3 tools/web.py --port 8765` starts the read-only local dashboard. It reads `data/timeline.sqlite3` and summarizes `data/research/` without modifying findings or publishing draft reports.
