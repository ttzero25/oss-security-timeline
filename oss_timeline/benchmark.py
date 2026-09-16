from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .research import RepositoryProfilerAgent, SemanticAnalysisAgent, SourceScanAgent


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def run_benchmark(manifest_file: Path, output_file: Path | None = None) -> dict:
    """Evaluate static candidate detection against labeled local cases."""
    manifest_file = manifest_file.resolve()
    data = json.loads(manifest_file.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("cases"), list) or not data["cases"]:
        raise ValueError("벤치마크 매니페스트 형식이 올바르지 않습니다")
    corpus_root = manifest_file.parent
    seen_ids: set[str] = set()
    cases = []
    started = time.monotonic()
    for raw in data["cases"]:
        case_id = str(raw.get("id") or "")
        expectation = raw.get("expectation")
        origin = raw.get("origin", "synthetic")
        expected_kinds = set(raw.get("expected_kinds") or [])
        if not case_id or case_id in seen_ids or expectation not in {"vulnerable", "clean"} or origin not in {"synthetic", "historical"}:
            raise ValueError("벤치마크 사례 ID 또는 expectation이 올바르지 않습니다")
        provenance = raw.get("provenance") or {}
        if origin == "historical":
            required = ("advisory", "repository", "ref", "source_path", "snapshot_type", "url")
            if not raw.get("pair_id") or any(not provenance.get(key) for key in required):
                raise ValueError(f"{case_id}: 실제 공개 사례에는 pair_id와 provenance가 필요합니다")
            if not re.fullmatch(r"GHSA-[23456789cfghjmpqrvwxy]{4}-[23456789cfghjmpqrvwxy]{4}-[23456789cfghjmpqrvwxy]{4}", str(provenance["advisory"])):
                raise ValueError(f"{case_id}: GHSA 식별자가 올바르지 않습니다")
            if not re.fullmatch(r"[^/\s]+/[^/\s]+", str(provenance["repository"])):
                raise ValueError(f"{case_id}: 저장소 식별자가 올바르지 않습니다")
            if not re.search(r"[0-9a-f]{40}", str(provenance["ref"])):
                raise ValueError(f"{case_id}: provenance ref에는 불변 커밋 SHA가 필요합니다")
            if not str(provenance["url"]).startswith("https://github.com/"):
                raise ValueError(f"{case_id}: provenance URL은 GitHub 원본이어야 합니다")
        if expectation == "vulnerable" and not expected_kinds:
            raise ValueError(f"{case_id}: 취약 사례에는 expected_kinds가 필요합니다")
        seen_ids.add(case_id)
        case_root = (corpus_root / str(raw.get("path") or "")).resolve()
        if not case_root.is_relative_to(corpus_root) or not case_root.is_dir():
            raise ValueError(f"{case_id}: 코퍼스 내부 디렉터리가 아닙니다")
        findings, coverage = SourceScanAgent().run(case_root, f"benchmark/{case_id}", "benchmark")
        profile = RepositoryProfilerAgent().run(case_root, max_files=5_000)
        ranked = SemanticAnalysisAgent().run([item.__dict__ for item in findings], profile)
        found_kinds = {item["kind"] for item in ranked}
        matched_kinds = sorted(expected_kinds & found_kinds)
        kind_ranks = {kind: next((index for index, item in enumerate(ranked, 1) if item["kind"] == kind), None) for kind in sorted(expected_kinds)}
        present_ranks = [rank for rank in kind_ranks.values() if rank is not None]
        top_rank = min(present_ranks) if present_ranks else None
        max_rank = int(raw.get("max_rank", 10))
        if max_rank < 1:
            raise ValueError(f"{case_id}: max_rank는 1 이상이어야 합니다")
        passed = not ranked if expectation == "clean" else expected_kinds <= found_kinds and all(rank is not None and rank <= max_rank for rank in kind_ranks.values())
        cases.append({
            "id": case_id,
            "description": str(raw.get("description") or ""),
            "origin": origin,
            "pair_id": str(raw.get("pair_id") or ""),
            "provenance": provenance,
            "expectation": expectation,
            "expected_kinds": sorted(expected_kinds),
            "found_kinds": sorted(found_kinds),
            "matched_kinds": matched_kinds,
            "finding_count": len(ranked),
            "top_expected_rank": top_rank,
            "expected_kind_ranks": kind_ranks,
            "max_rank": max_rank,
            "passed": passed,
            "coverage": coverage,
            "findings": [{"id": item["id"], "kind": item["kind"], "path": item["path"], "source_line": item["source_line"], "sink_line": item["sink_line"], "priority": item["priority"]} for item in ranked[:20]],
        })
    vulnerable = [case for case in cases if case["expectation"] == "vulnerable"]
    clean = [case for case in cases if case["expectation"] == "clean"]
    true_positive = sum(case["passed"] for case in vulnerable)
    false_negative = len(vulnerable) - true_positive
    true_negative = sum(case["passed"] for case in clean)
    false_positive = len(clean) - true_negative
    by_origin = {}
    for origin in ("synthetic", "historical"):
        selected = [case for case in cases if case["origin"] == origin]
        by_origin[origin] = {"cases": len(selected), "passed": sum(case["passed"] for case in selected), "pass_rate": _ratio(sum(case["passed"] for case in selected), len(selected))}
    historical_pairs: dict[str, list[dict]] = {}
    for case in cases:
        if case["origin"] == "historical":
            historical_pairs.setdefault(case["pair_id"], []).append(case)
    for pair_id, pair in historical_pairs.items():
        if len(pair) != 2 or {case["expectation"] for case in pair} != {"vulnerable", "clean"}:
            raise ValueError(f"{pair_id}: 공개 사례는 취약/수정 사례가 정확히 하나씩 필요합니다")
        identities = {(case["provenance"]["advisory"], case["provenance"]["repository"]) for case in pair}
        if len(identities) != 1:
            raise ValueError(f"{pair_id}: 취약/수정 사례의 advisory와 repository가 일치해야 합니다")
    complete_pairs = list(historical_pairs.values())
    metrics = {
        "total_cases": len(cases),
        "vulnerable_cases": len(vulnerable),
        "clean_cases": len(clean),
        "true_positive_cases": true_positive,
        "false_negative_cases": false_negative,
        "true_negative_cases": true_negative,
        "false_positive_cases": false_positive,
        "recall_at_case_limit": _ratio(true_positive, len(vulnerable)),
        "case_precision": _ratio(true_positive, true_positive + false_positive),
        "clean_specificity": _ratio(true_negative, len(clean)),
        "pass_rate": _ratio(true_positive + true_negative, len(cases)),
        "by_origin": by_origin,
        "historical_pairs_total": len(complete_pairs),
        "historical_pairs_passed": sum(all(case["passed"] for case in pair) for pair in complete_pairs),
    }
    result = {
        "schema_version": 1,
        "corpus": data.get("name", manifest_file.stem),
        "corpus_version": data.get("version", "unversioned"),
        "manifest": str(manifest_file),
        "manifest_sha256": hashlib.sha256(manifest_file.read_bytes()).hexdigest(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 4),
        "scope": "static candidate detection; dynamic build and PoC metrics are not included",
        "metrics": metrics,
        "cases": cases,
    }
    if output_file:
        output_file = output_file.resolve()
        output_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_file.with_suffix(output_file.suffix + ".tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(output_file)
    return result


def benchmark_passes(result: dict, minimum_recall: float, maximum_false_positive_cases: int) -> bool:
    recall = result.get("metrics", {}).get("recall_at_case_limit")
    false_positives = result.get("metrics", {}).get("false_positive_cases")
    return recall is not None and recall >= minimum_recall and isinstance(false_positives, int) and false_positives <= maximum_false_positive_cases


def _historical_manifest_cases(manifest_file: Path) -> tuple[dict, list[dict]]:
    manifest_file = manifest_file.resolve()
    data = json.loads(manifest_file.read_text(encoding="utf-8"))
    historical = [case for case in data.get("cases", []) if case.get("origin") == "historical"]
    if data.get("schema_version") != 1 or not historical:
        raise ValueError("전체 저장소 평가에 사용할 공개 취약/수정 사례가 없습니다")
    pairs: dict[str, list[dict]] = {}
    for case in historical:
        provenance = case.get("provenance") or {}
        required = ("advisory", "repository", "ref", "source_path", "url")
        if not case.get("pair_id") or any(not provenance.get(key) for key in required):
            raise ValueError(f'{case.get("id", "unknown")}: provenance가 불완전합니다')
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", str(provenance["repository"])) or not re.search(r"[0-9a-f]{40}", str(provenance["ref"])):
            raise ValueError(f'{case.get("id", "unknown")}: 저장소 또는 커밋이 올바르지 않습니다')
        pairs.setdefault(str(case["pair_id"]), []).append(case)
    for pair_id, pair in pairs.items():
        if len(pair) != 2 or {item.get("expectation") for item in pair} != {"vulnerable", "clean"}:
            raise ValueError(f"{pair_id}: 취약/수정 사례가 정확히 하나씩 필요합니다")
    return data, historical


def _git(command: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(["git", *command], cwd=cwd, capture_output=True, text=True, timeout=180)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-500:]
        raise RuntimeError(f"git {' '.join(command[:2])} 실패: {detail}")
    return result.stdout.strip()


def run_upstream_benchmark(manifest_file: Path, output_file: Path | None = None, max_files: int = 20_000, checkout_roots: dict[tuple[str, str], Path] | None = None) -> dict:
    """Scan immutable full upstream checkouts without building or executing target code."""
    if max_files < 1:
        raise ValueError("파일 조사 상한은 1 이상이어야 합니다")
    started = time.monotonic()
    data, historical = _historical_manifest_cases(manifest_file)
    pair_expected = {str(case["pair_id"]): set(case.get("expected_kinds") or []) for case in historical if case.get("expectation") == "vulnerable"}
    results = []
    with tempfile.TemporaryDirectory(prefix="oss-upstream-benchmark-") as temp:
        temp_root = Path(temp)
        repositories: dict[str, Path] = {}
        for case in historical:
            provenance = case["provenance"]
            repository = str(provenance["repository"])
            sha_match = re.search(r"[0-9a-f]{40}", str(provenance["ref"]))
            if not sha_match:
                raise ValueError(f'{case["id"]}: 불변 커밋 SHA가 없습니다')
            commit = sha_match.group(0)
            override = (checkout_roots or {}).get((repository, commit))
            if override:
                root = override.resolve()
            else:
                root = repositories.get(repository)
                if root is None:
                    root = temp_root / hashlib.sha256(repository.encode()).hexdigest()[:16]
                    root.mkdir()
                    _git(["init", "-q"], root)
                    _git(["remote", "add", "origin", f"https://github.com/{repository}.git"], root)
                    repositories[repository] = root
                _git(["fetch", "-q", "--depth", "1", "origin", commit], root)
                resolved_commit = _git(["rev-parse", "FETCH_HEAD^{commit}"], root)
                _git(["-c", "core.hooksPath=/dev/null", "checkout", "--detach", "-q", "--force", "FETCH_HEAD"], root)
                actual = _git(["rev-parse", "HEAD"], root)
                if actual != resolved_commit:
                    raise RuntimeError(f'{case["id"]}: 체크아웃 커밋 불일치')
                commit = actual
            paths = {item.strip() for item in str(provenance["source_path"]).split(";") if item.strip()}
            focus_function = str(provenance.get("focus_function") or "")
            focus_sink_contains = str(provenance.get("focus_sink_contains") or "")
            findings, coverage = SourceScanAgent().run(root, repository, commit, max_files=max_files, priority_paths=paths)
            relevant = [item for item in findings if {item.path, item.source_path, item.sink_path} & paths and (not focus_function or item.function == focus_function) and (not focus_sink_contains or focus_sink_contains in item.sink_code)]
            found = {item.kind for item in relevant}
            expected = pair_expected[str(case["pair_id"])]
            passed = expected <= found if case["expectation"] == "vulnerable" else False
            results.append({
                "id": case["id"], "pair_id": case["pair_id"], "expectation": case["expectation"], "repository": repository,
                "requested_ref": sha_match.group(0), "commit": commit, "source_paths": sorted(paths), "focus_function": focus_function or None, "focus_sink_contains": focus_sink_contains or None, "expected_kinds": sorted(expected), "found_kinds": sorted(found),
                "relevant_findings": len(relevant), "finding_signatures": [{"kind": item.kind, "function": item.function, "source_path": item.source_path, "sink_path": item.sink_path} for item in relevant], "passed": passed, "coverage": coverage,
            })
    pairs = {}
    for case in results:
        pairs.setdefault(case["pair_id"], []).append(case)
    for pair in pairs.values():
        vulnerable = next(item for item in pair if item["expectation"] == "vulnerable")
        fixed = next(item for item in pair if item["expectation"] == "clean")
        vulnerable_signatures = {(item["kind"], item["function"], item["source_path"]) for item in vulnerable["finding_signatures"] if item["kind"] in vulnerable["expected_kinds"]}
        fixed_signatures = {(item["kind"], item["function"], item["source_path"]) for item in fixed["finding_signatures"] if item["kind"] in fixed["expected_kinds"]}
        regressions = vulnerable_signatures & fixed_signatures
        fixed["regression_signatures"] = [{"kind": kind, "function": function, "source_path": source_path} for kind, function, source_path in sorted(regressions)]
        fixed["passed"] = not regressions
    pair_results = [{"pair_id": pair_id, "passed": all(item["passed"] for item in pair), "cases": [item["id"] for item in pair]} for pair_id, pair in sorted(pairs.items())]
    passed_pairs = sum(item["passed"] for item in pair_results)
    result = {
        "schema_version": 1, "corpus_version": data.get("version", "unversioned"), "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 4), "scope": "immutable full upstream checkout; static scan only; target code is not built or executed",
        "max_files_per_checkout": max_files, "metrics": {"cases": len(results), "pairs_total": len(pair_results), "pairs_passed": passed_pairs, "pair_pass_rate": _ratio(passed_pairs, len(pair_results)), "cases_passed": sum(item["passed"] for item in results)},
        "pairs": pair_results, "cases": results,
    }
    if output_file:
        output_file = output_file.resolve()
        output_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_file.with_suffix(output_file.suffix + ".tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(output_file)
    return result
