"""Loopback-only OSS security dashboard."""
from __future__ import annotations

import argparse
import html
import json
import os
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
from oss_timeline.research import audit, checkout  # noqa: E402

CSS = Path(__file__).with_name("web.css").read_text(encoding="utf-8")
AGENT_DESCRIPTIONS = {
    "InventoryAgent": "저장소 매니페스트에서 배포 가능한 패키지 식별",
    "ChangeAgent": "릴리스와 커밋 변경 기록 수집",
    "AdvisoryAgent": "GitHub·OSV 공개 보안 공지 수집",
    "CandidateAgent": "보안 관련 공개 변경의 검토 후보 선별",
    "SourceScanAgent": "코드의 입력 경로와 위험 동작 연결 가설 탐색",
    "PocValidatorAgent": "정상·공격 입력의 격리 PoC 결과 대조",
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
            items.append({"repo": data.get("repo", ""), "commit": data.get("commit", ""), "generated_at": data.get("generated_at"), "hypotheses": hypotheses, "poc_contrasts": contrasts, "draft_pairs": drafts, "coverage": coverage, "truncated": bool(coverage.get("truncated"))})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(items, key=lambda x: x.get("generated_at") or "", reverse=True)


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
        }
        return report, stats
    finally:
        store.db.close()


def page(title: str, active: str, content: str, refresh: bool = False) -> str:
    nav = "".join(f'<a class="{"active" if active == key else ""}" href="{url}">{label}</a>' for key, url, label in [("home", "/", "Home"), ("lab", "/lab", "실험실"), ("summary", "/summary", "정리")])
    meta = '<meta http-equiv="refresh" content="5">' if refresh else ""
    return f'''<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{meta}<title>{esc(title)} · OSS Security Timeline</title><style>{CSS}</style></head>
<body><div class="shell"><header class="topbar"><a class="brand" href="/"><span class="brand-mark">◈</span> OSS Security Timeline</a><nav aria-label="주요 메뉴">{nav}</nav><span class="local-badge">LOCAL ONLY</span></header><main>{content}</main><footer>공개 정보와 로컬 조사 기록을 보여줍니다. 코드 후보는 검증된 취약점이 아닙니다.</footer></div></body></html>'''


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
    recent = "".join(f'<li><span>{esc(str(x.get("at") or "")[:10])}</span><div><b>{esc(x.get("repo"))}</b><p>{safe_link(x.get("url"), x.get("title") or x.get("id"))}</p></div></li>' for x in report.get("timeline", [])[:5])
    body = f'''<section class="hero"><span class="eyebrow">OPEN SOURCE SECURITY INTELLIGENCE</span><h1>공개 변경부터 검증 가능한<br><em>보안 가설</em>까지.</h1><p>GitHub 저장소의 업데이트와 CVE·GHSA·OSV 공지를 시간순으로 모으고, 코드에서 발견한 후보를 별도의 검증 흐름으로 추적합니다.</p><a class="button" href="/lab">저장소 조사 시작 ↗</a></section>
<section><div class="section-heading"><div><span class="eyebrow">PROJECT TOTALS</span><h2>누적 탐지</h2></div><p>현재 로컬 데이터 기준 · 샘플 값 없음</p></div><div class="metrics">{metric("추적 저장소", stats["repos"], "수집된 OSS")}{metric("고유 보안 공지", stats["advisories"], "CVE·GHSA 별칭 통합")}{metric("변경 이벤트", stats["events"], "릴리스·커밋")}{metric("코드 검토 후보", hypotheses, "취약점 확정 아님")}{metric("PoC 대조 성공", contrasts, "수동 검토 필요")}</div></section>
<section class="split"><div class="panel"><div class="section-heading"><div><span class="eyebrow">ACTIVITY</span><h2>최근 타임라인</h2></div><a href="/summary">전체 보기 ↗</a></div>{'<ul class="activity">' + recent + '</ul>' if recent else empty("아직 수집된 기록이 없습니다. 실험실에서 저장소를 입력하세요.")}</div><div class="panel intro"><span class="eyebrow">HOW IT WORKS</span><h2>두 갈래의 조사 흐름</h2><p>공개 릴리스·커밋과 보안 공지를 수집해 시간축과 순위를 만듭니다. 이어서 소스 코드의 입력 경로와 위험 동작을 검토 가설로 찾습니다.</p><p>가설은 곧 제로데이가 아닙니다. 재현과 중복 공지 검토, 사람의 코드 확인을 거쳐 비공개 제보 초안으로 이어집니다.</p></div></section>
<section><div class="section-heading"><div><span class="eyebrow">AGENT MAP</span><h2>에이전트 구성</h2></div><p>역할별 Python 모듈 · 변경·공지 수집은 병렬</p></div><div class="agent-grid">{cards}</div></section>'''
    return page("Home", "home", body)


def lab(selected: str | None, report: dict | None, audits: list[dict], job: dict | None, error: str | None, comparisons: dict) -> str:
    value = esc("https://github.com/" + selected) if selected else ""
    form = f'''<form method="post" action="/lab/start" class="repo-form"><label for="repo">GitHub 오픈소스 저장소</label><div class="input-row"><input id="repo" name="repo" type="url" value="{value}" placeholder="https://github.com/owner/repo" autocomplete="url" required><button class="button" type="submit">수집 · 코드 조사 시작 ↗</button></div><small>공개 GitHub 저장소만 허용합니다. PoC나 제보는 자동 실행하지 않습니다.</small></form>'''
    notice = f'<div class="notice error">{esc(error)}</div>' if error else ""
    running = bool(job and job["status"] == "running")
    if job:
        state = "진행 중" if running else "완료" if job["status"] == "complete" else "실패"
        notice += f'<div class="notice"><b>{esc(job["repo"])} · {state}</b><span>{esc(job["step"] if running else job.get("error") or "수집과 코드 조사가 완료됐습니다.")}</span></div>'
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
        hypotheses = audit_result["hypotheses"] if audit_result else []
        code_coverage = audit_result.get("coverage", {}) if audit_result else {}
        inspected = code_coverage.get("files_inspected")
        languages = ", ".join(code_coverage.get("languages", []))
        code_scope = f'조사 파일 {inspected}개 · 지원 언어 {languages}' if inspected is not None else "아직 코드 조사 기록이 없습니다"
        if code_coverage.get("truncated"):
            code_scope += " · 파일 상한으로 조사 잘림"
        candidates = "".join(f'<tr><td>{esc(x.get("id"))}</td><td>{esc(x.get("kind"))}</td><td>{esc(x.get("path"))}:{esc(x.get("sink_line"))}</td><td>검토 후보</td></tr>' for x in hypotheses)
        versions = "".join(f'<tr><td>{esc(x["advisory_id"])}</td><td>{esc(x["ecosystem"])} / {esc(x["name"])}</td><td>{esc(x["version_range"] or "미기재")}</td><td>{esc(x["patched"] or "미기재")}</td></tr>' for x in report.get("fix_versions", []))
        diff_cards = ""
        for comparison in comparisons.get("comparisons", []):
            files = ""
            for item in comparison.get("files", []):
                before = esc(item.get("before") or "삭제된 줄 없음")
                after = esc(item.get("after") or "추가된 줄 없음")
                files += f'<div class="diff-file"><h4>{esc(item.get("path"))} <small>{esc(item.get("status"))}</small></h4><div class="diff-pair"><div><span>전 · 삭제된 줄</span><pre>{before}</pre></div><div><span>후 · 추가된 줄</span><pre>{after}</pre></div></div></div>'
            warning = f'<p class="coverage">{esc(comparison["warning"])}</p>' if comparison.get("warning") else ""
            diff_cards += f'<article class="panel diff-card"><h3>{esc(", ".join(comparison.get("advisory_ids", [])))}</h3><p>공지에서 참조한 커밋: {safe_link(comparison.get("url"), str(comparison.get("commit") or "")[:12])}</p>{warning}{files or empty("이 커밋의 변경 파일 정보가 제공되지 않았습니다.")}</article>'
        compare_note = "참조 커밋의 차이는 공지와 연결된 근거이며, 각 변경이 실제 fix인지 사람의 확인이 필요합니다."
        if comparisons.get("truncated"):
            compare_note += " 참조 커밋은 처음 5개만 수집했습니다."
        details = f'''<section><div class="section-heading"><div><span class="eyebrow">SELECTED REPOSITORY</span><h2>{esc(selected)}</h2></div><span class="pill">마지막 수집 {esc(str(repo_data.get("last_sync") or "")[:16])} UTC</span></div><div class="metrics compact">{metric("고유 공지", count, "저장소 연관 공지")}{metric("변경 기록", len(changes), "표시 범위 최대 300건")}{metric("코드 가설", len(hypotheses), "미검증 후보")}</div><p class="coverage">수집 범위: {esc(coverage)}<br>경고: {esc(warnings)}</p></section>
<section><div class="section-heading"><div><span class="eyebrow">ADVISORY TRACKING</span><h2>보안 공지 추적</h2></div><p>CWE는 공지 원문에 명시된 값만 표시</p></div>{table(["시각", "기록", "식별자", "CVE", "취약점 유형 (CWE)", "공지", "심각도"], rows) if rows else empty("이 저장소의 보안 공지 기록이 아직 없습니다.")}</section>
<section><div class="section-heading"><div><span class="eyebrow">ZERO-DAY RESEARCH</span><h2>미공개 취약점 조사</h2></div><p>후보 ≠ 발견 확정</p></div><div class="notice subdued">소스 스캔은 검토 가설만 만듭니다. 제로데이 판정에는 영향 재현, 중복 공지 확인, 사람의 검토가 필요합니다.</div><p class="coverage">{esc(code_scope)}. 미지원 언어·패턴의 후보 0건은 안전성의 증거가 아닙니다.</p>{table(["후보 ID", "분류", "코드 위치", "상태"], candidates) if candidates else empty("코드 가설이 없습니다. 조사 완료 여부와 스캔 범위를 확인하세요.")}</section>'''
        details += f'''<section><div class="section-heading"><div><span class="eyebrow">BEFORE / AFTER</span><h2>Fix 전후 비교</h2></div><p>버전과 공지 참조 커밋 기준</p></div><div class="notice subdued">{esc(compare_note)}</div><h3>영향 버전 → 패치 버전</h3>{table(["공지", "패키지", "영향 범위", "패치 버전"], versions) if versions else empty("공지에 연결된 패키지 버전 정보가 없습니다.")}<h3 class="subheading">참조 커밋의 변경 줄</h3>{diff_cards or empty("저장된 공지 참조 커밋 비교가 없습니다. 새로 수집한 공지에 수정 커밋 링크가 없다면 코드 전후를 자동 연결하지 않습니다.")}</section>'''
    elif selected:
        details = "<section>" + empty("아직 이 저장소의 수집 기록이 없습니다. 조사 상태를 확인하세요.") + "</section>"
    body = f'''<section class="page-head"><span class="eyebrow">WORKBENCH</span><h1>실험실</h1><p>저장소 링크 하나로 공개 업데이트와 보안 공지를 수집하고 코드 검토 후보를 조사합니다.</p></section><section class="panel">{form}{notice}</section>{details}'''
    return page("실험실", "lab", body, running)


def summary(report: dict, audits: list[dict]) -> str:
    by_repo = {x["repo"]: x for x in audits}
    rank = {x["repo"]: x["advisories"] for x in report["ranking"]}
    ordered = sorted(report["repositories"], key=lambda x: (-rank.get(x["name"], 0), x["name"]))
    rows = "".join(f'<tr><td><a href="/lab?repo={quote(x["name"])}">{esc(x["name"])}</a></td><td>{rank.get(x["name"], 0)}</td><td>{sum(p["repo"] == x["name"] for p in report["packages"])}</td><td>{len(by_repo.get(x["name"], {}).get("hypotheses", []))}</td><td>{esc(str(x.get("last_sync") or "")[:16])} UTC</td></tr>' for x in ordered)
    packages = "".join(f'<tr><td>{esc(x["repo"])}</td><td>{esc(x["ecosystem"])}</td><td>{esc(x["name"])}</td><td>{x["advisories"]}</td></tr>' for x in report["packages"][:50])
    forecast = report.get("forecast", {})
    forecast_text = f'향후 {forecast.get("horizon_months")}개월 공개 공지 {forecast.get("expected")}건 예상' if forecast.get("status") == "estimated" else forecast.get("reason", "관측 기간과 공지 건수가 부족합니다.")
    body = f'''<section class="page-head"><span class="eyebrow">PORTFOLIO</span><h1>정리</h1><p>OSS별 공개 공지와 패키지, 코드 검토 후보를 한눈에 비교합니다.</p></section><section><div class="section-heading"><div><span class="eyebrow">REPOSITORIES</span><h2>저장소별 결과</h2></div><p>공지 수는 저장소별 고유 건수</p></div>{table(["저장소", "공지", "패키지", "코드 가설", "마지막 수집"], rows) if rows else empty("아직 조사한 저장소가 없습니다. 실험실에서 첫 링크를 입력하세요.")}</section><section><div class="section-heading"><div><span class="eyebrow">PACKAGE RANKING</span><h2>패키지별 보안 공지</h2></div></div>{table(["저장소", "생태계", "패키지", "공지"], packages) if packages else empty("아직 패키지에 연결된 보안 공지가 없습니다.")}</section><section class="panel"><span class="eyebrow">FORECAST</span><h2>공개 공지 추정</h2><p>{esc(forecast_text)}</p><small>미공개 제로데이 발생 수는 공개 공지 이력만으로 예측할 수 없습니다.</small></section>'''
    return page("정리", "summary", body)


def serve(port: int, db_path: Path, research_root: Path, registry_path: Path) -> None:
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
                jobs[repo]["step"] = "최신 커밋 복제 및 코드 가설 조사 중"
                persist_jobs()
            root, _ = checkout(repo, research_root.parent / "checkouts")
            audit(root, repo, research_root, timeline_db=db_path)
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
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
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
            if path in {"/", "/lab", "/summary", "/api/report", "/api/research"}:
                audits = research_index(research_root)
                if path == "/api/research":
                    self.respond(json.dumps(audits, ensure_ascii=False), content_type="application/json; charset=utf-8")
                    return
                selected = None
                error = None
                if path == "/lab":
                    raw = parse_qs(parsed.query).get("repo", [None])[0]
                    if raw:
                        try:
                            selected = repo_name(raw)
                        except ValueError as exc:
                            error = str(exc)
                try:
                    report, stats = snapshot(db_path, selected)
                except ValueError:
                    report, stats = None, {}
                if path == "/api/report":
                    self.respond(json.dumps(report, ensure_ascii=False), content_type="application/json; charset=utf-8")
                elif path == "/":
                    self.respond(home(report, stats, audits, agent_registry(registry_path)))
                elif path == "/summary":
                    self.respond(summary(report, audits))
                else:
                    with lock:
                        job = jobs.get(selected, {}).copy() if selected else None
                    self.respond(lab(selected, report, audits, job, error, fix_index(db_path.parent / "fix-comparisons", selected)))
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
