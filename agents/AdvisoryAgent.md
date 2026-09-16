# AdvisoryAgent

Input: repository and package mappings. Output: repository advisories, reviewed/unreviewed GitHub advisories and OSV records. CVE/GHSA aliases are reconciled when stored. Runs concurrently with `ChangeAgent`. Runtime: `oss_timeline/core.py`.
