"""Bounded, evidence-linked comparisons of advisory-referenced commits."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .core import ApiError, HttpClient, repo_name

SHA = re.compile(r"[0-9a-fA-F]{7,40}")


def referenced_commit(url: str, repo: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 4 or parts[2] != "commit" or not SHA.fullmatch(parts[3]):
        return None
    if "/".join(parts[:2]).casefold() != repo_name(repo).casefold():
        return None
    return parts[3].lower()


def changed_lines(patch: str, max_chars: int = 2400) -> tuple[str, str]:
    before = []
    after = []
    for line in patch.splitlines():
        if line.startswith(("---", "+++", "@@")):
            continue
        if line.startswith("-"):
            before.append(line[1:])
        elif line.startswith("+"):
            after.append(line[1:])
    return "\n".join(before)[:max_chars], "\n".join(after)[:max_chars]


def collect_reference_diffs(client: HttpClient, repo: str, advisories: list[dict], output_root: Path, max_commits: int = 5, max_files: int = 8) -> Path:
    canonical = repo_name(repo)
    references: dict[str, set[str]] = {}
    for advisory in advisories:
        for url in advisory.get("references", []):
            sha = referenced_commit(url, canonical)
            if sha:
                references.setdefault(sha, set()).add(advisory["id"])
    records = []
    for sha, advisory_ids in list(references.items())[:max_commits]:
        record = {"advisory_ids": sorted(advisory_ids), "commit": sha, "url": f"https://github.com/{canonical}/commit/{sha}", "files": [], "warning": None}
        try:
            data = client.github(f"/repos/{canonical}/commits/{sha}")
            if not isinstance(data, dict):
                raise ApiError("커밋 응답 형식이 올바르지 않습니다")
            for item in data.get("files", [])[:max_files]:
                before, after = changed_lines(item.get("patch") or "")
                record["files"].append({"path": item.get("filename") or "", "status": item.get("status") or "", "before": before, "after": after, "patch_available": bool(item.get("patch"))})
            if len(data.get("files", [])) > max_files:
                record["warning"] = f"변경 파일은 처음 {max_files}개만 표시합니다"
        except (ApiError, ValueError, TypeError) as exc:
            record["warning"] = str(exc)[-300:]
        records.append(record)
    output_root.mkdir(parents=True, exist_ok=True)
    destination = output_root / (canonical.replace("/", "_") + ".json")
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(json.dumps({"repo": canonical, "comparisons": records, "reference_count": len(references), "truncated": len(references) > max_commits}, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(destination)
    return destination
