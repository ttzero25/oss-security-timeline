# PocValidatorAgent

Input: a completed PoC manifest and script. Output: separate benign/attack run evidence and a mechanical contrast result. The default execution path is a resource-limited local process; `--container` opts into network-disabled, read-only Docker execution. Apply [verification rules](../rules/verification.md). Runtime: `oss_timeline/research.py`.
