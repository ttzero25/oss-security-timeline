from __future__ import annotations

import hashlib
import json
import re
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
