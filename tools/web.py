"""Loopback-only OSS security dashboard."""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oss_timeline.core import ApiError, HttpClient, Store, repo_name, synchronize  # noqa: E402
from oss_timeline.fix import collect_reference_diffs  # noqa: E402
from oss_timeline.research import ResearchOrchestrator, audit, checkout  # noqa: E402

CSS = Path(__file__).with_name("web.css").read_text(encoding="utf-8")
GRAPH_JS = Path(__file__).with_name("graph.js").read_text(encoding="utf-8")
THEME_JS = Path(__file__).with_name("theme.js").read_text(encoding="utf-8")
AGENT_DESCRIPTIONS = {
    "InventoryAgent": "저장소 매니페스트에서 배포 가능한 패키지 식별",
    "ChangeAgent": "릴리스와 커밋 변경 기록 수집",
    "AdvisoryAgent": "GitHub·OSV 공개 보안 공지 수집",
    "CandidateAgent": "보안 관련 공개 변경의 검토 후보 선별",
    "RepositoryProfilerAgent": "언어·패키지 파일·lockfile·외부 엔트리포인트 조사 범위 기록",
    "SourceScanAgent": "코드의 입력 경로와 위험 동작 연결 가설 탐색",
    "ReachabilityGateAgent": "기본 설정의 외부 엔트리포인트에서 후보 경로 도달 여부 검증",
    "ResearchOrchestrator": "후보 우선순위화와 제한된 격리 재현 단계 조율",
    "PocValidatorAgent": "정상·공격 입력의 격리 PoC 결과 대조",
    "EvidenceGateAgent": "도달성·기본 설정·입력 통제·영향·중복의 5개 근거 판정",
    "DisclosureAgent": "검증 근거에 기반한 비공개 제보 초안 생성",
}


def esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def safe_link(url: str | None, label: str) -> str:
    if not url or not url.startswith("https://"):
        return esc(label)
    return f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(label)}</a>'


def research_index(root: Path) -> list[dict]:
    items = []
    if not root.is_dir():
        return items
    for path in root.rglob("audit.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            hypotheses = data.get("hypotheses", [])
            contrasts = 0
            drafts = 0
            for finding in hypotheses:
                folder = path.parent / finding["id"]
                evidence = folder / "evidence.json"
                if evidence.is_file():
                    contrasts += json.loads(evidence.read_text(encoding="utf-8")).get("mechanical_result") == "contrast_matched"
                drafts += (folder / "GHSA_CANDIDATE.md").is_file() and (folder / "CVE_REQUEST_BRIEF.md").is_file()
            coverage = data.get("coverage", {})
            try:
                orchestration = json.loads((path.parent / "orchestration.json").read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                orchestration = {}
            for result in orchestration.get("results", []):
                evidence_path = path.parent / str(result.get("finding_id", "")) / "evidence.json"
                try:
                    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                    result["web_evidence"] = {key: evidence.get(key) for key in ("generator", "proof_scope", "mode", "mechanical_result")}
                except (OSError, ValueError, TypeError):
                    result["web_evidence"] = {}
            items.append({"repo": data.get("repo", ""), "commit": data.get("commit", ""), "generated_at": data.get("generated_at"), "hypotheses": hypotheses, "poc_contrasts": contrasts, "draft_pairs": drafts, "coverage": coverage, "scan_cache": data.get("scan_cache", {}), "profile": data.get("profile", {}), "orchestration": orchestration, "truncated": bool(coverage.get("truncated"))})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(items, key=lambda x: x.get("generated_at") or "", reverse=True)


def reconcile_research_runs(db_path: Path, research_root: Path) -> dict:
    """Import completed legacy orchestration files into the timeline database."""
    result = {"imported": 0, "already_present": 0, "invalid": 0}
    store = Store(db_path)
    try:
        for audit_path in research_root.rglob("audit.json") if research_root.is_dir() else []:
            orchestration_path = audit_path.parent / "orchestration.json"
            if not orchestration_path.is_file():
                continue
            try:
                audit_data = json.loads(audit_path.read_text(encoding="utf-8"))
                orchestration = json.loads(orchestration_path.read_text(encoding="utf-8"))
                repo = repo_name(audit_data["repo"])
                commit = str(audit_data["commit"])
                if orchestration.get("repo") != repo or str(orchestration.get("commit")) != commit:
                    raise ValueError("audit/orchestration mismatch")
                exists = store.db.execute("SELECT 1 FROM research_runs WHERE repo=? AND commit_hash=?", (repo, commit)).fetchone()
                if exists:
                    result["already_present"] += 1
                    continue
                store.save_research(audit_data, orchestration, orchestration_path)
                result["imported"] += 1
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                result["invalid"] += 1
    finally:
        store.db.close()
    return result


def research_status(audit: dict | None, run: dict | None) -> str:
    if run:
        return {
            "no_candidates": "완료 · 후보 없음",
            "candidates": "완료 · 검토 후보 있음",
            "draft_ready": "완료 · 초안 준비",
        }.get(run.get("status"), "완료 · " + str(run.get("status") or "상태 미확인"))
    if audit and audit.get("orchestration"):
        return "결과 파일 있음 · DB 미연동"
    if audit:
        return "정적 조사만 완료"
    return "미실행"


def disclosure_index(root: Path) -> list[dict]:
    """Read CLI evidence and report drafts without executing any artifact."""
    items = []
    if not root.is_dir():
        return items
    for audit_path in root.rglob("audit.json"):
        try:
            audit_data = json.loads(audit_path.read_text(encoding="utf-8"))
            repo = repo_name(audit_data["repo"])
            commit = str(audit_data["commit"])
            hypotheses = {item["id"]: item for item in audit_data.get("hypotheses", [])}
        except (OSError, ValueError, KeyError, TypeError):
            continue
        for finding_id, finding in hypotheses.items():
            folder = audit_path.parent / finding_id
            evidence_path = folder / "evidence.json"
            ghsa_path = folder / "GHSA_CANDIDATE.md"
            cve_path = folder / "CVE_REQUEST_BRIEF.md"
            if not any(path.is_file() for path in (evidence_path, ghsa_path, cve_path)):
                continue
            evidence = {}
            if evidence_path.is_file():
                try:
                    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                except (OSError, ValueError, TypeError):
                    evidence = {"mechanical_result": "invalid_evidence"}
            evidence_matches = evidence.get("finding_id") == finding_id and evidence.get("commit") == commit
            verified = evidence_matches and evidence.get("mechanical_result") == "contrast_matched"
            try:
                ghsa_text = ghsa_path.read_text(encoding="utf-8") if ghsa_path.is_file() else ""
                cve_text = cve_path.read_text(encoding="utf-8") if cve_path.is_file() else ""
            except (OSError, UnicodeError):
                ghsa_text = cve_text = ""
            drafts_ready = verified and bool(ghsa_text and cve_text)
            submission = {"status": "draft_ready", "external_action": "none", "reference": "", "history": []}
            submission_path = folder / "submission.json"
            if drafts_ready and submission_path.is_file():
                try:
                    saved = json.loads(submission_path.read_text(encoding="utf-8"))
                    if saved.get("finding_id") == finding_id and saved.get("commit") == commit:
                        submission = saved
                except (OSError, ValueError, TypeError):
                    submission = {"status": "invalid", "external_action": "none", "reference": "", "history": []}
            title = finding_id
            if ghsa_text.startswith("# "):
                title = ghsa_text.splitlines()[0][2:].strip() or finding_id
            items.append({"key": f"{repo}|{commit}|{finding_id}", "repo": repo, "commit": commit, "finding_id": finding_id, "kind": finding.get("kind", ""), "path": finding.get("path", ""), "sink_line": finding.get("sink_line", ""), "title": title, "mechanical_result": evidence.get("mechanical_result", "not_run"), "validated_at": evidence.get("validated_at"), "verification_mode": evidence.get("mode"), "generator": evidence.get("generator"), "proof_scope": evidence.get("proof_scope"), "verified": verified, "drafts_ready": drafts_ready, "submission": submission, "ghsa_text": ghsa_text, "cve_text": cve_text})
    return sorted(items, key=lambda item: (item.get("validated_at") or "", item["repo"], item["finding_id"]), reverse=True)


def agent_registry(path: Path) -> list[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def fix_index(root: Path, repo: str | None) -> dict:
    if not repo:
        return {"comparisons": [], "reference_count": 0, "truncated": False}
    try:
        data = json.loads((root / (repo.replace("/", "_") + ".json")).read_text(encoding="utf-8"))
        return data if data.get("repo") == repo else {"comparisons": [], "reference_count": 0, "truncated": False}
    except (OSError, ValueError):
        return {"comparisons": [], "reference_count": 0, "truncated": False}


def load_jobs(path: Path) -> dict[str, dict]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    jobs = {}
    for repo, job in raw.items():
        try:
            valid = repo_name(repo) == repo
        except (ValueError, TypeError):
            continue
        if valid and isinstance(job, dict) and job.get("status") in {"running", "complete", "failed"}:
            jobs[repo] = job
    for job in jobs.values():
        if job["status"] == "running":
            job.update(status="failed", step="중단됨", error="서버 재시작으로 조사가 중단됐습니다. 다시 시작하세요.")
    return jobs


def github_token() -> tuple[str | None, str]:
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return token, "GITHUB_TOKEN"
    try:
        result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None, "비인증"
    return (result.stdout.strip(), "GitHub CLI") if result.returncode == 0 and result.stdout.strip() else (None, "비인증")


def snapshot(path: Path, repo: str | None = None) -> tuple[dict, dict]:
    store = Store(path)
    try:
        report = store.report(repo, 300)
        if repo:
            return report, {}
        db = store.db
        stats = {
            "repos": db.execute("SELECT COUNT(*) FROM repositories").fetchone()[0],
            "advisories": db.execute("SELECT COUNT(*) FROM advisories").fetchone()[0],
            "events": db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "change_candidates": db.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "research_events": db.execute("SELECT COUNT(*) FROM research_events").fetchone()[0],
        }
        return report, stats
    finally:
        store.db.close()


def benchmark_snapshot(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if data.get("schema_version") == 1 and isinstance(data.get("metrics"), dict) else None
    except (OSError, ValueError, TypeError):
        return None


def graph_snapshot(db_path: Path, research_root: Path, fix_root: Path, repo: str | None = None) -> dict:
    store = Store(db_path)
    try:
        db = store.db
        params = [repo] if repo else []
        where = " WHERE ar.repo=?" if repo else ""
        advisory_rows = [dict(x) for x in db.execute(
            "SELECT a.id,a.ghsa,a.cve,a.summary,a.severity,a.cwe_ids,a.cwe_names,ar.repo "
            "FROM advisories a JOIN advisory_repos ar ON ar.advisory_id=a.id" + where,
            params,
        )]
        package_rows = [dict(x) for x in db.execute(
            "SELECT advisory_id,repo,ecosystem,name,version_range,patched FROM advisory_packages"
            + (" WHERE repo=?" if repo else ""),
            params,
        )]
        finding_rows = [dict(x) for x in db.execute(
            "SELECT repo,id,title,status FROM findings" + (" WHERE repo=?" if repo else ""),
            params,
        )]
        repositories = [x["repo"] for x in advisory_rows] + [x["repo"] for x in package_rows] + [x["repo"] for x in finding_rows]
        if repo:
            repositories.append(repo)
        else:
            repositories.extend(x[0] for x in db.execute("SELECT name FROM repositories"))
    finally:
        store.db.close()

    nodes: dict[str, dict] = {}
    edges: set[tuple[str, str, str]] = set()

    def add_node(node_id: str, label: str, kind: str, detail: str = "") -> None:
        nodes.setdefault(node_id, {"id": node_id, "label": label, "kind": kind, "detail": detail})

    def add_edge(source: str, target: str, relation: str) -> None:
        if source != target:
            edges.add((source, target, relation))

    for name in sorted(set(repositories)):
        add_node("repo:" + name, name, "repository", "GitHub 저장소")
    for item in advisory_rows:
        advisory_id = "advisory:" + item["id"]
        add_node(advisory_id, item["ghsa"] or item["id"], "advisory", f'{item["severity"] or "unknown"} · {item["summary"] or ""}')
        add_edge("repo:" + item["repo"], advisory_id, "보안 공지")
        if item["cve"]:
            cve_id = "cve:" + item["cve"]
            add_node(cve_id, item["cve"], "cve", "CVE 식별자")
            add_edge(advisory_id, cve_id, "별칭")
        try:
            cwes = json.loads(item["cwe_ids"] or "[]")
            names = json.loads(item["cwe_names"] or "{}")
        except (TypeError, ValueError):
            cwes, names = [], {}
        for cwe in cwes:
            cwe_id = "cwe:" + cwe
            add_node(cwe_id, cwe, "cwe", names.get(cwe, "취약점 유형"))
            add_edge(advisory_id, cwe_id, "유형")
    for item in package_rows:
        package_id = f'package:{item["repo"]}:{item["ecosystem"]}:{item["name"]}'
        add_node(package_id, item["name"], "package", f'{item["ecosystem"]} · 영향 {item["version_range"] or "미기재"} · 패치 {item["patched"] or "미기재"}')
        add_edge("repo:" + item["repo"], package_id, "패키지")
        add_edge("advisory:" + item["advisory_id"], package_id, "영향")
    for item in finding_rows:
        finding_id = "change:" + item["repo"] + ":" + item["id"]
        add_node(finding_id, item["title"] or item["id"], "change", item["status"] or "공개 변경 검토 후보")
        add_edge("repo:" + item["repo"], finding_id, "변경 후보")
    audits = research_index(research_root)
    for audit_item in audits:
        if repo and audit_item["repo"] != repo:
            continue
        for finding in audit_item["hypotheses"]:
            finding_id = "finding:" + finding["id"]
            add_node(finding_id, finding["id"], "finding", f'{finding.get("kind", "")} · {finding.get("path", "")}:{finding.get("sink_line", "")}')
            add_edge("repo:" + audit_item["repo"], finding_id, "코드 후보")
            kind_id = "weakness:" + finding.get("kind", "unknown")
            add_node(kind_id, finding.get("kind", "unknown"), "weakness", "정적 분석 가설 유형")
            add_edge(finding_id, kind_id, "가설 유형")
    for name in sorted(set(repositories)):
        comparison_data = fix_index(fix_root, name)
        for comparison in comparison_data.get("comparisons", []):
            commit = comparison.get("commit")
            if not commit:
                continue
            commit_id = "commit:" + name + ":" + commit
            changed = ", ".join(x.get("path", "") for x in comparison.get("files", [])[:4])
            add_node(commit_id, commit[:12], "commit", changed or "공지 참조 커밋")
            add_edge("repo:" + name, commit_id, "커밋")
            for advisory_id in comparison.get("advisory_ids", []):
                add_edge("advisory:" + advisory_id, commit_id, "fix 참조")
    return {
        "nodes": list(nodes.values()),
        "edges": [{"source": source, "target": target, "relation": relation} for source, target, relation in sorted(edges)],
        "repositories": sorted(set(repositories)),
        "selected_repo": repo,
    }


def graph_page(repositories: list[str], selected: str | None = None) -> str:
    options = '<option value="">전체 저장소</option>' + "".join(f'<option value="{esc(name)}"{" selected" if name == selected else ""}>{esc(name)}</option>' for name in repositories)
    body = f'''<section class="page-head graph-head"><span class="eyebrow">KNOWLEDGE GRAPH</span><h1>보안 관계망</h1><p>저장소, 패키지, GHSA·CVE, CWE, fix 참조 커밋과 코드 후보 사이의 연결을 탐색합니다.</p></section>
    <section class="graph-toolbar" aria-label="관계망 도구"><label for="graph-repo">저장소</label><select id="graph-repo">{options}</select><label for="graph-density">표시 밀도</label><select id="graph-density"><option value="80">간단히 · 80</option><option value="200">표준 · 200</option><option value="all">전체</option></select><label for="graph-search">노드 찾기</label><input id="graph-search" type="search" placeholder="CVE, GHSA, CWE, 패키지"><button id="graph-reset" type="button">화면 맞춤</button><span id="graph-count" aria-live="polite"></span></section>
    <section class="graph-workspace"><div class="graph-stage"><canvas id="security-graph" role="img" aria-label="오픈소스 보안 데이터 관계 그래프"></canvas><div class="graph-legend" aria-label="노드 범례"><span data-kind="repository">저장소</span><span data-kind="package">패키지</span><span data-kind="advisory">GHSA</span><span data-kind="cve">CVE</span><span data-kind="cwe">CWE</span><span data-kind="commit">fix 커밋</span><span data-kind="change">공개 변경 후보</span><span data-kind="finding">코드 가설</span></div></div><aside id="graph-detail" class="graph-detail" aria-live="polite"><span class="eyebrow">SELECT A NODE</span><h2>노드를 선택하세요</h2><p>드래그로 이동하고, 휠로 확대·축소할 수 있습니다. 노드를 선택하면 직접 연결된 관계가 강조됩니다.</p></aside></section>
    <noscript><div class="empty">관계망을 보려면 브라우저에서 JavaScript를 활성화하세요.</div></noscript><script src="/graph.js" defer></script>'''
    return page("관계망", "graph", body)


def reports_page(reports: list[dict], selected_key: str | None = None, document: str = "ghsa") -> str:
    ready = sum(item["drafts_ready"] for item in reports)
    verified = sum(item["verified"] for item in reports)
    submitted = sum(item.get("submission", {}).get("status") in {"submitted", "accepted"} for item in reports)
    selected = next((item for item in reports if item["key"] == selected_key), None)
    cards = ""
    for item in reports:
        submission = item.get("submission", {})
        submission_status = submission.get("status", "draft_ready")
        state_labels = {"reviewed": "사람 검토 완료", "submitted": "사람이 제출함", "accepted": "접수/승인", "rejected": "종료/거절", "invalid": "상태 파일 오류"}
        if submission_status in state_labels:
            state, state_class = state_labels[submission_status], "ready" if submission_status in {"submitted", "accepted"} else "verified" if submission_status == "reviewed" else "pending"
        elif item["drafts_ready"]:
            state, state_class = "제보 초안 준비", "ready"
        elif item["verified"]:
            state, state_class = "PoC 대조 성공", "verified"
        else:
            state, state_class = "미확인", "pending"
        links = ""
        if item["drafts_ready"]:
            key = quote(item["key"], safe="")
            links = f'<div class="report-links"><a href="/reports?report={key}&amp;doc=ghsa">GHSA 초안 보기</a><a href="/reports?report={key}&amp;doc=cve">CVE 브리프 보기</a></div>'
        scope_labels = {"target_execution": "실제 대상 함수 실행", "compatible_sink_control_not_framework_execution": "호환 sink 입력 통제 확인 · 실제 프레임워크 실행 아님"}
        cards += f'''<article class="report-card"><div class="report-card-head"><span class="report-state {state_class}">{state}</span><small>{esc(str(item.get("validated_at") or "검증 기록 없음")[:19])}</small></div><h2>{esc(item["title"])}</h2><p>{esc(item["repo"])} · <code>{esc(item["commit"][:12])}</code></p><dl><div><dt>후보 ID</dt><dd>{esc(item["finding_id"])}</dd></div><div><dt>유형</dt><dd>{esc(item["kind"] or "미기재")}</dd></div><div><dt>위치</dt><dd>{esc(item["path"])}:{esc(item["sink_line"])}</dd></div><div><dt>생성기</dt><dd>{esc(item.get("generator") or "수동/이전 형식")}</dd></div><div><dt>검증 범위</dt><dd>{esc(scope_labels.get(item.get("proof_scope"), item.get("proof_scope") or "이전 형식 · 범위 미기재"))}</dd></div><div><dt>격리 방식</dt><dd>{esc(item.get("verification_mode") or "미실행")}</dd></div><div><dt>제출 참조</dt><dd>{esc(submission.get("reference") or "기록 없음")}</dd></div></dl>{links}</article>'''
    viewer = ""
    if selected:
        label = "GHSA 비공개 제보 초안" if document == "ghsa" else "CVE 요청 브리프"
        content = selected["ghsa_text"] if document == "ghsa" else selected["cve_text"]
        if selected["drafts_ready"] and content:
            viewer = f'''<section class="report-viewer"><div class="section-heading"><div><span class="eyebrow">PRIVATE DRAFT</span><h2>{label}</h2></div><a href="/reports">닫기</a></div><div class="notice subdued">로컬 CLI가 생성한 비공개 초안입니다. 자동 제출되지 않았으며 공개 전 사람의 검토가 필요합니다.</div><pre>{esc(content)}</pre></section>'''
    body = f'''<section class="page-head"><span class="eyebrow">CLI ARTIFACTS</span><h1>검증 리포트</h1><p>자원 제한 CLI 검증 결과와 비공개 GHSA/CVE 제보 초안을 읽기 전용으로 확인합니다.</p></section><section><div class="metrics compact">{metric("CLI 산출물", len(reports), "PoC 실행 기록 포함")}{metric("PoC 대조 성공", verified, "동일 커밋·후보 근거")}{metric("제보 초안", ready, "GHSA와 CVE 문서 쌍")}{metric("사람이 제출", submitted, "CLI에 기록된 상태")}</div></section>{viewer}<section><div class="section-heading"><div><span class="eyebrow">LOCAL ONLY</span><h2>리포트 목록</h2></div><p>새로고침할 때 data/research를 다시 읽음</p></div><div class="notice subdued">웹은 이 산출물을 실행하거나 수정하거나 외부로 제출하지 않습니다. 제출 상태도 사람이 수행한 결과를 CLI로 기록한 값일 뿐입니다.</div><div class="report-grid">{cards}</div>{empty("아직 CLI PoC 검증 또는 제보 초안 산출물이 없습니다.") if not reports else ""}</section>'''
    return page("검증 리포트", "reports", body)


def page(title: str, active: str, content: str, refresh: bool = False) -> str:
    nav = "".join(f'<a class="{"active" if active == key else ""}" href="{url}">{label}</a>' for key, url, label in [("home", "/", "Home"), ("lab", "/lab", "실험실"), ("summary", "/summary", "정리"), ("graph", "/graph", "관계망"), ("reports", "/reports", "리포트")])
    meta = '<meta http-equiv="refresh" content="5">' if refresh else ""
    return f'''<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{meta}<title>{esc(title)} · OSS Security Timeline</title><style>{CSS}</style></head>
<body><div class="shell"><header class="topbar"><a class="brand" href="/"><span class="brand-mark">◈</span> OSS Security Timeline</a><nav aria-label="주요 메뉴">{nav}</nav><button id="theme-toggle" class="theme-toggle" type="button" aria-label="낮과 밤 밝기 전환" title="낮과 밤 밝기 전환">☾</button><span class="local-badge">LOCAL ONLY</span></header><main>{content}</main><footer>공개 정보와 로컬 조사 기록을 보여줍니다. 코드 후보는 검증된 취약점이 아닙니다.</footer></div><script src="/theme.js" defer></script></body></html>'''


def metric(label: str, value: object, detail: str) -> str:
    return f'<article class="metric"><span>{esc(label)}</span><strong>{esc(value)}</strong><small>{esc(detail)}</small></article>'


def empty(message: str) -> str:
    return f'<div class="empty">{esc(message)}</div>'


def table(headings: list[str], rows: str) -> str:
    head = "".join(f"<th>{esc(x)}</th>" for x in headings)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>'


def weakness_label(item: dict) -> str:
    names = item.get("cwe_names") or {}
    values = [f'{code} · {names[code]}' if names.get(code) else code for code in item.get("cwe_ids") or []]
    return ", ".join(values) or "미기재"


def home(report: dict, stats: dict, audits: list[dict], agents: list[dict]) -> str:
    hypotheses = sum(len(x["hypotheses"]) for x in audits)
    contrasts = sum(x["poc_contrasts"] for x in audits)
    cards = "".join(f'<article class="agent-card"><span class="lane">{"공개 데이터" if x.get("lane") == "timeline" else "코드 조사"}</span><h3>{esc(x.get("name"))}</h3><p>{esc(AGENT_DESCRIPTIONS.get(x.get("name"), x.get("purpose")))}</p></article>' for x in agents)
    public_recent = [{**x, "display": x.get("title") or x.get("id")} for x in report.get("timeline", [])]
    research_recent = [{**x, "url": None, "display": f'연구 · {x.get("kind")} · {x.get("status")}'} for x in report.get("research_timeline", [])]
    recent_items = sorted(public_recent + research_recent, key=lambda item: item.get("at") or "", reverse=True)[:8]
    recent = "".join(f'<li><span>{esc(str(x.get("at") or "")[:10])}</span><div><b>{esc(x.get("repo"))}</b><p>{safe_link(x.get("url"), x.get("display"))}</p></div></li>' for x in recent_items)
    body = f'''<section class="hero"><span class="eyebrow">OPEN SOURCE SECURITY INTELLIGENCE</span><h1>공개 변경부터 검증 가능한<br><em>보안 가설</em>까지.</h1><p>GitHub 저장소의 업데이트와 CVE·GHSA·OSV 공지를 시간순으로 모으고, 코드에서 발견한 후보를 별도의 검증 흐름으로 추적합니다.</p><a class="button" href="/lab">저장소 조사 시작 ↗</a></section>
<section><div class="section-heading"><div><span class="eyebrow">PROJECT TOTALS</span><h2>누적 탐지</h2></div><p>현재 로컬 데이터 기준 · 샘플 값 없음</p></div><div class="metrics">{metric("추적 저장소", stats["repos"], "수집된 OSS")}{metric("고유 보안 공지", stats["advisories"], "CVE·GHSA 별칭 통합")}{metric("변경 이벤트", stats["events"], "릴리스·커밋")}{metric("코드 검토 후보", hypotheses, "취약점 확정 아님")}{metric("PoC 대조 성공", contrasts, "수동 검토 필요")}</div></section>
<section class="split"><div class="panel"><div class="section-heading"><div><span class="eyebrow">ACTIVITY</span><h2>최근 타임라인</h2></div><a href="/summary">전체 보기 ↗</a></div>{'<ul class="activity">' + recent + '</ul>' if recent else empty("아직 수집된 기록이 없습니다. 실험실에서 저장소를 입력하세요.")}</div><div class="panel intro"><span class="eyebrow">HOW IT WORKS</span><h2>두 갈래의 조사 흐름</h2><p>공개 릴리스·커밋과 보안 공지를 수집해 시간축과 순위를 만듭니다. 이어서 소스 코드의 입력 경로와 위험 동작을 검토 가설로 찾습니다.</p><p>가설은 곧 제로데이가 아닙니다. 재현과 중복 공지 검토, 사람의 코드 확인을 거쳐 비공개 제보 초안으로 이어집니다.</p></div></section>
<section><div class="section-heading"><div><span class="eyebrow">AGENT MAP</span><h2>에이전트 구성</h2></div><p>역할별 Python 모듈 · 변경·공지 수집은 병렬</p></div><div class="agent-grid">{cards}</div></section>'''
    return page("Home", "home", body)


def lab(selected: str | None, report: dict | None, audits: list[dict], job: dict | None, error: str | None, comparisons: dict, fix_year: str = "", fix_month: str = "") -> str:
    value = esc("https://github.com/" + selected) if selected else ""
    capabilities = "".join(f"<span>{esc(label)}</span>" for label in ("명령·코드 실행", "SSRF · 네트워크 스텁", "SQL · DB 스텁", "경로 조작 · scratch", "pickle · stdout 전용", "템플릿 sink · 범위 표시", "C/C++ · ASan/UBSan"))
    form = f'''<form method="post" action="/lab/start" class="repo-form"><label for="repo">GitHub 오픈소스 저장소</label><div class="input-row"><input id="repo" name="repo" type="url" value="{value}" placeholder="https://github.com/owner/repo" autocomplete="url" required><button class="button" type="submit">수집 · 심층 조사 시작 ↗</button></div><small>공개 GitHub 저장소만 허용합니다. 지원되는 제한 PoC는 로컬에서 대조하지만 제보는 자동 제출하지 않습니다.</small><div class="capability-list" aria-label="제한 자동 재현 범위">{capabilities}</div></form>'''
    notice = f'<div class="notice error">{esc(error)}</div>' if error else ""
    running = bool(job and job["status"] == "running")
    if job:
        state = "진행 중" if running else "완료" if job["status"] == "complete" else "실패"
        notice += f'<div class="notice job-status {"running" if running else "complete" if job["status"] == "complete" else "failed"}"><b>{esc(job["repo"])} · {state}</b><span>{esc(job["step"] if running else job.get("error") or "수집과 코드 조사가 완료됐습니다.")}</span></div>'
    details = ""
    if selected and report:
        repo_data = report["repositories"][0]
        advisories = [x for x in report["timeline"] if x["kind"].startswith("advisory")]
        changes = [x for x in report["timeline"] if not x["kind"].startswith("advisory")]
        count = report["ranking"][0]["advisories"] if report["ranking"] else 0
        warnings = ", ".join(repo_data["warnings"]) or "보고된 경고 없음"
        coverage = ", ".join(k for k, v in repo_data["coverage"].items() if not v) or "설정한 범위 내 완료"
        rows = "".join(f'<tr><td>{esc(str(x.get("at") or "")[:10])}</td><td>{"수정" if x["kind"] == "advisory_update" else "게시"}</td><td>{esc(x.get("ghsa") or x.get("id"))}</td><td>{esc(x.get("cve") or "미등록")}</td><td>{esc(weakness_label(x))}</td><td>{safe_link(x.get("url"), x.get("title") or x.get("id"))}</td><td>{esc(x.get("severity") or "-")}</td></tr>' for x in advisories)
        audit_result = next((x for x in audits if x["repo"] == selected), None)
        latest_research_run = next((x for x in report.get("research_runs", []) if x["repo"] == selected), None)
        deep_status = research_status(audit_result, latest_research_run)
        hypotheses = audit_result["hypotheses"] if audit_result else []
        orchestration = audit_result.get("orchestration", {}) if audit_result else {}
        verdicts = {x["finding_id"]: x for x in orchestration.get("results", [])}
        attempted = int(orchestration.get("attempted_candidates", 0) or 0)
        unavailable = int(orchestration.get("automation_unavailable_candidates", 0) or 0)
        deferred = int(orchestration.get("deferred_supported_candidates", 0) or 0)
        if not hypotheses:
            research_explanation = "정적 분석에서 후보를 만들지 못했습니다. 이는 안전 판정이 아니며 미지원 언어·패턴과 조사 상한을 함께 확인해야 합니다."
        elif unavailable == len(hypotheses) and attempted == 0:
            research_explanation = f"후보 {len(hypotheses)}건은 발견됐지만 현재 안전한 자동 PoC 범위 밖이라 동적 검증을 실행하지 않았습니다."
        elif attempted:
            research_explanation = f"후보 중 {attempted}건을 동적 검증 대상으로 선택했습니다. 자동화 미지원 {unavailable}건, 다음 실행으로 이월 {deferred}건입니다."
        else:
            research_explanation = "정적 후보는 있으나 이 실행에는 동적 검증 시도 기록이 없습니다. 기존 감사 결과를 최신 엔진으로 다시 실행하세요."
        profile = audit_result.get("profile", {}) if audit_result else {}
        code_coverage = audit_result.get("coverage", {}) if audit_result else {}
        inspected = code_coverage.get("files_inspected")
        eligible = code_coverage.get("eligible_files")
        languages = ", ".join(code_coverage.get("languages", []))
        code_scope = f'조사 파일 {inspected}/{eligible if eligible is not None else inspected}개 · 지원 언어 {languages}' if inspected is not None else "아직 코드 조사 기록이 없습니다"
        if audit_result and audit_result.get("scan_cache", {}).get("reused"):
            code_scope += " · 동일 커밋 스캔 캐시 재사용"
        elif inspected is not None:
            code_scope += " · 최근 변경 파일 우선"
        if code_coverage.get("truncated"):
            code_scope += " · 파일 상한으로 조사 잘림"
        candidate_rows = []
        for finding in hypotheses:
            verdict = verdicts.get(finding.get("id"), {})
            stages = verdict.get("stages", {})
            trace = " → ".join(f'{step.get("role")}:{step.get("path")}:{step.get("line")}' for step in finding.get("trace", [])) or f'{finding.get("path")}:{finding.get("sink_line")}'
            gate = stages.get("evidence_gate", {}).get("verdict") or stages.get("reachability_gate", {}).get("verdict") or "미검증"
            candidate_rows.append(f'<tr><td>{esc(finding.get("id"))}</td><td>{esc(finding.get("kind"))}</td><td>{esc(trace)}</td><td>{esc(verdict.get("status", "가설"))}</td><td>{esc(gate)}</td></tr>')
        candidates = "".join(candidate_rows)
        verification_rows = []
        scope_labels = {"target_execution": "실제 대상 함수 실행", "compatible_sink_control_not_framework_execution": "호환 sink만 검증 · 실제 프레임워크 실행 아님"}
        for result in orchestration.get("results", []):
            stages = result.get("stages", {})
            build = stages.get("build_environment", {})
            preflight = build.get("dependency_preflight", {})
            evidence = result.get("web_evidence", {})
            dependencies = []
            if preflight.get("stubbed_by_generator"):
                dependencies.append("스텁: " + ", ".join(preflight["stubbed_by_generator"]))
            if preflight.get("missing"):
                dependencies.append("누락: " + ", ".join(preflight["missing"]))
            if not dependencies and preflight:
                dependencies.append("누락 없음")
            generator = evidence.get("generator") or "미생성"
            scope = scope_labels.get(evidence.get("proof_scope"), evidence.get("proof_scope") or "검증 기록 없음")
            contrast = evidence.get("mechanical_result") or stages.get("isolated_contrast", {}).get("status") or "미실행"
            verification_rows.append(f'<tr><td>{esc(result.get("finding_id"))}</td><td>{esc(build.get("status") or "미실행")}</td><td>{esc(" · ".join(dependencies) or build.get("reason") or "사전검사 기록 없음")}</td><td>{esc(generator)}</td><td>{esc(scope)}</td><td>{esc(contrast)}</td></tr>')
        verification_table = table(["후보 ID", "빌드 환경", "의존성 사전검사", "PoC 생성기", "검증 범위", "대조 결과"], "".join(verification_rows)) if verification_rows else empty("아직 동적 검증 단계 기록이 없습니다.")
        language_text = ", ".join(f"{name} {amount}" for name, amount in profile.get("languages", {}).items()) or "미확인"
        framework_text = ", ".join(profile.get("frameworks", [])) or "자동 식별 없음"
        recent_changes = profile.get("recent_changes", {})
        profile_rows = "".join(f'<tr><td>{esc(item.get("kind"))}</td><td>{esc(item.get("path"))}:{esc(item.get("line"))}</td><td>{esc(item.get("code"))}</td></tr>' for item in profile.get("entrypoints", [])[:50])
        research_rows = "".join(f'<tr><td>{esc(str(x.get("at") or "")[:19])}</td><td>{esc(x.get("kind"))}</td><td>{esc(x.get("finding_id") or "-")}</td><td>{esc(x.get("status"))}</td></tr>' for x in report.get("research_timeline", [])[:50])
        versions = "".join(f'<tr><td>{esc(x["advisory_id"])}</td><td>{esc(x["ecosystem"])} / {esc(x["name"])}</td><td>{esc(x["version_range"] or "미기재")}</td><td>{esc(x["patched"] or "미기재")}</td></tr>' for x in report.get("fix_versions", []))
        advisory_dates = {str(item.get("id")): str(item.get("at") or "")[:10] for item in advisories}
        dated_comparisons = []
        for comparison in comparisons.get("comparisons", []):
            dates = sorted(advisory_dates.get(str(advisory_id), "") for advisory_id in comparison.get("advisory_ids", []) if advisory_dates.get(str(advisory_id)))
            dated_comparisons.append((comparison, dates[0] if dates else ""))
        available_years = sorted({date[:4] for _, date in dated_comparisons if len(date) >= 7}, reverse=True)
        filtered_comparisons = [(comparison, date) for comparison, date in dated_comparisons if (not fix_year or date.startswith(fix_year + "-")) and (not fix_month or len(date) >= 7 and date[5:7] == fix_month)]
        year_options = '<option value="">전체 연도</option>' + "".join(f'<option value="{esc(year)}"{" selected" if year == fix_year else ""}>{esc(year)}년</option>' for year in available_years)
        month_options = '<option value="">전체 월</option>' + "".join(f'<option value="{month:02d}"{" selected" if f"{month:02d}" == fix_month else ""}>{month}월</option>' for month in range(1, 13))
        fix_filter = f'''<form class="fix-filter" method="get" action="/lab"><input type="hidden" name="repo" value="{esc(selected)}"><label for="fix-year">연도</label><select id="fix-year" name="year">{year_options}</select><label for="fix-month">월</label><select id="fix-month" name="month">{month_options}</select><button type="submit">적용</button><a href="/lab?repo={quote(selected)}">초기화</a></form>'''
        diff_cards = ""
        for comparison, comparison_date in filtered_comparisons:
            files = ""
            for item in comparison.get("files", []):
                before = esc(item.get("before") or "삭제된 줄 없음")
                after = esc(item.get("after") or "추가된 줄 없음")
                files += f'<details class="diff-file"><summary>{esc(item.get("path"))} <small>{esc(item.get("status"))}</small></summary><div class="diff-pair"><div><span>전 · 삭제된 줄</span><pre>{before}</pre></div><div><span>후 · 추가된 줄</span><pre>{after}</pre></div></div></details>'
            warning = f'<p class="coverage">{esc(comparison["warning"])}</p>' if comparison.get("warning") else ""
            diff_cards += f'<details class="panel diff-card"><summary><b>{esc(", ".join(comparison.get("advisory_ids", [])))}</b><span>{esc(comparison_date or "날짜 미상")} · {len(comparison.get("files", []))}개 파일</span></summary><p>공지에서 참조한 커밋: {safe_link(comparison.get("url"), str(comparison.get("commit") or "")[:12])}</p>{warning}{files or empty("이 커밋의 변경 파일 정보가 제공되지 않았습니다.")}</details>'
        compare_note = "참조 커밋의 차이는 공지와 연결된 근거이며, 각 변경이 실제 fix인지 사람의 확인이 필요합니다."
        if comparisons.get("truncated"):
            compare_note += " 참조 커밋은 처음 5개만 수집했습니다."
        details = f'''<section><div class="section-heading"><div><span class="eyebrow">SELECTED REPOSITORY</span><h2>{esc(selected)}</h2></div><span class="pill">마지막 수집 {esc(str(repo_data.get("last_sync") or "")[:16])} UTC</span></div><div class="metrics compact">{metric("고유 공지", count, "저장소 연관 공지")}{metric("변경 기록", len(changes), "표시 범위 최대 300건")}{metric("코드 가설", len(hypotheses), "미검증 후보")}{metric("심층 조사", deep_status, "DB 실행 기록 기준")}</div><p class="coverage">수집 범위: {esc(coverage)}<br>경고: {esc(warnings)}</p></section>
<section><div class="section-heading"><div><span class="eyebrow">ADVISORY TRACKING</span><h2>보안 공지 추적</h2></div><p>CWE는 공지 원문에 명시된 값만 표시</p></div>{table(["시각", "기록", "식별자", "CVE", "취약점 유형 (CWE)", "공지", "심각도"], rows) if rows else empty("이 저장소의 보안 공지 기록이 아직 없습니다.")}</section>
<section><div class="section-heading"><div><span class="eyebrow">ZERO-DAY RESEARCH</span><h2>미공개 취약점 조사</h2></div><p>후보 ≠ 발견 확정</p></div><div class="notice subdued">{esc(research_explanation)}</div><p class="coverage">{esc(code_scope)}. 미지원 언어·패턴의 후보 0건은 안전성의 증거가 아닙니다.</p>{table(["후보 ID", "분류", "입력→호출→위험 동작", "상태", "근거 게이트"], candidates) if candidates else empty("코드 가설이 없습니다. 조사 완료 여부와 스캔 범위를 확인하세요.")}<h3 class="subheading">동적 PoC·실행 환경</h3>{verification_table}</section>'''
        details += f'''<section><div class="section-heading"><div><span class="eyebrow">REPOSITORY PROFILE</span><h2>코드·패키지 조사 범위</h2></div><p>커밋 {esc((audit_result or {}).get("commit", "")[:12])}</p></div><div class="metrics compact">{metric("확인 파일", profile.get("files_seen", 0), "vendor·생성 디렉터리 제외")}{metric("코드 파일", profile.get("code_files", 0), language_text)}{metric("의존성 항목", profile.get("dependency_count", 0), ", ".join(f"{k} {v}" for k, v in profile.get("dependency_ecosystems", {}).items()) or "지원 lockfile 기준")}</div><p class="coverage">유형 {esc(profile.get("project_kind", "미확인"))} · 프레임워크 {esc(framework_text)} · 최근 변경 분석 커밋 {recent_changes.get("commits_considered", 0)}개/파일 {len(recent_changes.get("files", {}))}개<br>매니페스트 {len(profile.get("manifests", []))}개 · lockfile {len(profile.get("lockfiles", []))}개 · 엔트리포인트 {len(profile.get("entrypoints", []))}개 · 미지원 코드 {profile.get("unsupported_code_files", 0)}개 · 프로필 잘림 {"예" if profile.get("truncated") else "아니오"} · 의존성 잘림 {"예" if profile.get("dependencies_truncated") else "아니오"}</p>{table(["입력 유형", "위치", "코드"], profile_rows) if profile_rows else empty("자동 식별된 엔트리포인트가 없습니다.")}</section><section><div class="section-heading"><div><span class="eyebrow">RESEARCH TIMELINE</span><h2>조사 상태 이력</h2></div><p>공개 공지와 별도 기록</p></div>{table(["시각", "단계", "후보", "상태"], research_rows) if research_rows else empty("아직 저장된 연구 이벤트가 없습니다.")}</section>'''
        details += f'''<section><div class="section-heading"><div><span class="eyebrow">BEFORE / AFTER</span><h2>Fix 전후 비교</h2></div><p>버전과 공지 참조 커밋 기준</p></div><div class="notice subdued">{esc(compare_note)}</div><h3>영향 버전 → 패치 버전</h3>{table(["공지", "패키지", "영향 범위", "패치 버전"], versions) if versions else empty("공지에 연결된 패키지 버전 정보가 없습니다.")}<div class="section-heading subheading"><h3>참조 커밋의 변경 줄</h3><p>{len(filtered_comparisons)}/{len(dated_comparisons)}개 비교</p></div>{fix_filter}{diff_cards or empty("선택한 기간에 저장된 fix 비교가 없습니다.")}</section>'''
    elif selected:
        details = "<section>" + empty("아직 이 저장소의 수집 기록이 없습니다. 조사 상태를 확인하세요.") + "</section>"
    body = f'''<section class="page-head"><span class="eyebrow">WORKBENCH</span><h1>실험실</h1><p>저장소 링크 하나로 공개 업데이트와 보안 공지를 수집하고 코드 검토 후보를 조사합니다.</p></section><section class="panel">{form}{notice}</section>{details}'''
    return page("실험실", "lab", body, running)


def summary(report: dict, audits: list[dict], benchmark: dict | None = None, upstream_benchmark: dict | None = None) -> str:
    by_repo = {}
    for audit in audits:
        by_repo.setdefault(audit["repo"], audit)
    latest_run = {}
    for run in report.get("research_runs", []):
        latest_run.setdefault(run["repo"], run)
    rank = {x["repo"]: x["advisories"] for x in report["ranking"]}
    ordered = sorted(report["repositories"], key=lambda x: (-rank.get(x["name"], 0), x["name"]))
    rows = "".join(f'<tr><td><a href="/lab?repo={quote(x["name"])}">{esc(x["name"])}</a></td><td>{rank.get(x["name"], 0)}</td><td>{sum(p["repo"] == x["name"] for p in report["packages"])}</td><td>{len(by_repo.get(x["name"], {}).get("hypotheses", []))}</td><td>{esc(research_status(by_repo.get(x["name"]), latest_run.get(x["name"])))}</td><td>{esc(str(x.get("last_sync") or "")[:16])} UTC</td></tr>' for x in ordered)
    packages = "".join(f'<tr><td>{esc(x["repo"])}</td><td>{esc(x["ecosystem"])}</td><td>{esc(x["name"])}</td><td>{x["advisories"]}</td></tr>' for x in report["packages"][:50])
    benchmark_section = ""
    if benchmark:
        metrics = benchmark["metrics"]
        percent = lambda value: f"{float(value) * 100:.1f}%" if value is not None else "미산출"
        historical = metrics.get("by_origin", {}).get("historical", {})
        historical_card = metric("공개 취약/수정 쌍", f'{metrics.get("historical_pairs_passed", 0)}/{metrics.get("historical_pairs_total", 0)}', f'출처 고정 사례 {historical.get("cases", 0)}개') if historical else ""
        upstream_card = ""
        upstream_note = "전체 원본 저장소 평가는 아직 실행되지 않았습니다."
        if upstream_benchmark:
            upstream_metrics = upstream_benchmark.get("metrics", {})
            upstream_card = metric("전체 저장소 쌍", f'{upstream_metrics.get("pairs_passed", 0)}/{upstream_metrics.get("pairs_total", 0)}', f'고정 커밋 사례 {upstream_metrics.get("cases", 0)}개')
            upstream_note = f'{upstream_benchmark.get("scope", "")} · 파일 상한 {upstream_benchmark.get("max_files_per_checkout", 0)}개/체크아웃'
        benchmark_section = f'''<section><div class="section-heading"><div><span class="eyebrow">SCANNER BENCHMARK</span><h2>정적 탐지 기준선</h2></div><p>{esc(benchmark.get("corpus_version", ""))} · {esc(str(benchmark.get("generated_at") or "")[:19])} UTC</p></div><div class="metrics compact">{metric("취약 사례 재현율", percent(metrics.get("recall_at_case_limit")), f'{metrics.get("true_positive_cases", 0)}/{metrics.get("vulnerable_cases", 0)} 사례')}{metric("사례 정밀도", percent(metrics.get("case_precision")), f'오탐 사례 {metrics.get("false_positive_cases", 0)}건')}{metric("정상 사례 특이도", percent(metrics.get("clean_specificity")), f'{metrics.get("true_negative_cases", 0)}/{metrics.get("clean_cases", 0)} 사례')}{metric("전체 통과율", percent(metrics.get("pass_rate")), f'총 {metrics.get("total_cases", 0)} 사례')}{historical_card}{upstream_card}</div><p class="coverage">{esc(benchmark.get("scope"))}. 발췌문 기준 수치는 실제 저장소 성능을 대신하지 않습니다.<br>{esc(upstream_note)}</p></section>'''
    forecast = report.get("forecast", {})
    if forecast.get("status") == "estimated":
        interval = forecast.get("interval_90", ["?", "?"])
        forecast_text = f'향후 {forecast.get("horizon_months")}개월 공개 공지 {forecast.get("expected")}건 · 90% 구간 {interval[0]}–{interval[1]}건 · 신뢰 {forecast.get("confidence", "미평가")}'
        backtest = forecast.get("backtest", {})
        forecast_note = f'후향 검증 실제 {backtest.get("actual")}건 / 구간 포함 {"예" if backtest.get("covered") else "아니오"}' if backtest.get("status") == "evaluated" else backtest.get("reason", "후향 검증 미실행")
    else:
        forecast_text = forecast.get("reason", "관측 기간과 공지 건수가 부족합니다.")
        forecast_note = "표본 기준을 충족한 뒤 예측 구간을 계산합니다."
    forecast_rows = ""
    for name, item in sorted(report.get("repository_forecasts", {}).items()):
        context = item.get("context", {})
        estimate = f'{item.get("expected")} ({item.get("interval_90", ["?", "?"])[0]}–{item.get("interval_90", ["?", "?"])[1]})' if item.get("status") == "estimated" else "데이터 부족"
        forecast_rows += f'<tr><td>{esc(name)}</td><td>{esc(estimate)}</td><td>{esc(item.get("confidence", "-"))}</td><td>{context.get("updates_last_12_months", 0)}</td><td>{esc(context.get("code_files") if context.get("code_files") is not None else "미측정")}</td></tr>'
    body = f'''<section class="page-head"><span class="eyebrow">PORTFOLIO</span><h1>정리</h1><p>OSS별 공개 공지와 패키지, 코드 검토 후보를 한눈에 비교합니다.</p></section><section><div class="section-heading"><div><span class="eyebrow">REPOSITORIES</span><h2>저장소별 결과</h2></div><p>공지 수는 저장소별 고유 건수</p></div>{table(["저장소", "공지", "패키지", "코드 가설", "심층 조사", "마지막 수집"], rows) if rows else empty("아직 조사한 저장소가 없습니다. 실험실에서 첫 링크를 입력하세요.")}</section>{benchmark_section}<section><div class="section-heading"><div><span class="eyebrow">PACKAGE RANKING</span><h2>패키지별 보안 공지</h2></div></div>{table(["저장소", "생태계", "패키지", "공지"], packages) if packages else empty("아직 패키지에 연결된 보안 공지가 없습니다.")}</section><section class="panel"><span class="eyebrow">FORECAST</span><h2>공개 공지 추정</h2><p>{esc(forecast_text)}</p><small>{esc(forecast_note)} · 활동량과 코드 규모는 보정 전 참고값이며, 미공개 제로데이 발생 수는 예측하지 않습니다.</small></section><section><div class="section-heading"><div><span class="eyebrow">REPOSITORY FORECASTS</span><h2>저장소별 예측 문맥</h2></div><p>예상값(90% 구간) · 활동/규모는 미보정</p></div>{table(["저장소", "12개월 공개 공지", "신뢰", "최근 업데이트", "코드 파일"], forecast_rows) if forecast_rows else empty("저장소별 예측 자료가 없습니다.")}</section>'''
    return page("정리", "summary", body)


def serve(port: int, db_path: Path, research_root: Path, registry_path: Path) -> None:
    reconciliation = reconcile_research_runs(db_path, research_root)
    jobs_path = db_path.parent / "web-jobs.json"
    jobs: dict[str, dict] = load_jobs(jobs_path)
    lock = threading.Lock()
    token, auth_source = github_token()

    def persist_jobs() -> None:
        jobs_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = jobs_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(jobs, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(jobs_path)

    with lock:
        persist_jobs()

    def run_job(repo: str) -> None:
        try:
            with lock:
                jobs[repo]["step"] = "공개 릴리스·커밋·보안 공지 수집 중"
                persist_jobs()
            store = Store(db_path)
            client = HttpClient(token=token)
            try:
                result = synchronize(client, store, repo, max_pages=100, max_manifests=100)
            finally:
                store.db.close()
            with lock:
                jobs[repo]["step"] = "공지 참조 커밋의 전후 변경 확인 중"
                persist_jobs()
            collect_reference_diffs(client, repo, result.advisories, db_path.parent / "fix-comparisons")
            with lock:
                jobs[repo]["step"] = "최신 커밋 복제 및 저장소 프로파일링 중"
                persist_jobs()
            root, _ = checkout(repo, research_root.parent / "checkouts")
            audit_file = audit(root, repo, research_root, timeline_db=db_path)
            with lock:
                jobs[repo]["step"] = "코드 가설 우선순위화 및 제한 PoC 대조 중"
                persist_jobs()
            ResearchOrchestrator().run(audit_file, max_candidates=3, timeline_db=db_path)
            with lock:
                jobs[repo].update(status="complete", step="완료")
                persist_jobs()
        except (ApiError, ValueError, RuntimeError, OSError, KeyError) as exc:
            with lock:
                jobs[repo].update(status="failed", step="실패", error=str(exc)[-400:])
                persist_jobs()

    class Handler(BaseHTTPRequestHandler):
        def respond(self, body: str, status: int = 200, content_type: str = "text/html; charset=utf-8", location: str | None = None) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'")
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/health":
                self.respond('{"status":"ok"}', content_type="application/json; charset=utf-8")
                return
            if path == "/graph.js":
                self.respond(GRAPH_JS, content_type="text/javascript; charset=utf-8")
                return
            if path == "/theme.js":
                self.respond(THEME_JS, content_type="text/javascript; charset=utf-8")
                return
            if path in {"/", "/lab", "/summary", "/graph", "/reports", "/api/report", "/api/research", "/api/graph"}:
                audits = research_index(research_root)
                if path == "/api/research":
                    self.respond(json.dumps(audits, ensure_ascii=False), content_type="application/json; charset=utf-8")
                    return
                selected = None
                error = None
                if path in {"/lab", "/graph", "/api/graph"}:
                    raw = parse_qs(parsed.query).get("repo", [None])[0]
                    if raw:
                        try:
                            selected = repo_name(raw)
                        except ValueError as exc:
                            error = str(exc)
                if path == "/api/graph":
                    if error:
                        self.respond(json.dumps({"error": error}, ensure_ascii=False), status=400, content_type="application/json; charset=utf-8")
                    else:
                        self.respond(json.dumps(graph_snapshot(db_path, research_root, db_path.parent / "fix-comparisons", selected), ensure_ascii=False), content_type="application/json; charset=utf-8")
                    return
                try:
                    report, stats = snapshot(db_path, selected)
                except ValueError:
                    report, stats = None, {}
                if path == "/api/report":
                    self.respond(json.dumps(report, ensure_ascii=False), content_type="application/json; charset=utf-8")
                elif path == "/":
                    self.respond(home(report, stats, audits, agent_registry(registry_path)))
                elif path == "/summary":
                    self.respond(summary(report, audits, benchmark_snapshot(db_path.parent / "benchmarks" / "latest.json"), benchmark_snapshot(db_path.parent / "benchmarks" / "upstream-latest.json")))
                elif path == "/graph":
                    all_report, _ = snapshot(db_path)
                    self.respond(graph_page([x["name"] for x in all_report["repositories"]], selected))
                elif path == "/reports":
                    query = parse_qs(parsed.query)
                    document = query.get("doc", ["ghsa"])[0]
                    if document not in {"ghsa", "cve"}:
                        document = "ghsa"
                    self.respond(reports_page(disclosure_index(research_root), query.get("report", [None])[0], document))
                else:
                    with lock:
                        job = jobs.get(selected, {}).copy() if selected else None
                    query = parse_qs(parsed.query)
                    fix_year = query.get("year", [""])[0]
                    fix_month = query.get("month", [""])[0]
                    if fix_year and not re.fullmatch(r"20\d{2}", fix_year):
                        fix_year = ""
                    if fix_month and not re.fullmatch(r"0[1-9]|1[0-2]", fix_month):
                        fix_month = ""
                    self.respond(lab(selected, report, audits, job, error, fix_index(db_path.parent / "fix-comparisons", selected), fix_year, fix_month))
                return
            if path in {"/agents", "/research"}:
                self.respond("", status=303, location="/" if path == "/agents" else "/lab")
                return
            self.respond(page("찾을 수 없음", "", empty("페이지가 없습니다.")), status=404)

        def do_POST(self) -> None:
            if urlparse(self.path).path != "/lab/start":
                self.respond("허용되지 않은 요청", status=405)
                return
            origin = self.headers.get("Origin")
            if self.headers.get("Host") != f"127.0.0.1:{port}" or origin != f"http://127.0.0.1:{port}":
                self.respond("요청 출처가 올바르지 않습니다", status=403)
                return
            if not self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
                self.respond("잘못된 요청 형식", status=415)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 1024:
                    raise ValueError("입력 길이는 1~1024바이트여야 합니다")
                value = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True).get("repo", [""])[0]
                if not value.startswith("https://github.com/"):
                    raise ValueError("HTTPS GitHub 저장소 링크를 입력하세요")
                repo = repo_name(value)
            except (ValueError, UnicodeError) as exc:
                self.respond(page("입력 오류", "lab", empty(str(exc))), status=400)
                return
            with lock:
                if any(x["status"] == "running" for x in jobs.values()):
                    self.respond(page("진행 중", "lab", empty("다른 조사가 진행 중입니다. 완료 후 다시 시도하세요.")), status=409)
                    return
                jobs[repo] = {"repo": repo, "status": "running", "step": "조사 대기 중", "started_at": datetime.now(timezone.utc).isoformat()}
                persist_jobs()
            threading.Thread(target=run_job, args=(repo,), daemon=True).start()
            self.respond("", status=303, location="/lab?repo=" + quote(repo))

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Local dashboard: http://127.0.0.1:{server.server_port}/", flush=True)
    print(f"GitHub API authentication: {auth_source}", flush=True)
    if reconciliation["imported"] or reconciliation["invalid"]:
        print(f'Research history migration: imported={reconciliation["imported"]}, invalid={reconciliation["invalid"]}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local OSS security dashboard")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", type=Path, default=ROOT / "data/timeline.sqlite3")
    parser.add_argument("--research-root", type=Path, default=ROOT / "data/research")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    serve(args.port, args.db, args.research_root, ROOT / "agents/registry.json")


if __name__ == "__main__":
    main()
