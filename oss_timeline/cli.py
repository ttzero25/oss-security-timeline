from __future__ import annotations

import argparse
import html
import json
import sys
import time
from pathlib import Path

from .core import ApiError, HttpClient, Store, repo_name, synchronize
from .research import DisclosureAgent, PocValidatorAgent, audit, checkout, prepare_poc


def html_report(data: dict) -> str:
    escape = lambda x: html.escape(str(x or ""), quote=True)
    def link(url: str | None, label: str) -> str:
        if not url or not url.startswith("https://"):
            return escape(label)
        return f'<a href="{escape(url)}" target="_blank" rel="noopener noreferrer">{escape(label)}</a>'

    repo_cards = []
    for repo in data["repositories"]:
        flags = ", ".join(k for k, value in repo["coverage"].items() if not value) or "수집 범위 내 완료"
        notes = "".join(f"<li>{escape(w)}</li>" for w in repo["warnings"])
        repo_cards.append(f'<article class="card"><h3>{link(repo["url"], repo["name"])}</h3><p>마지막 수집: {escape(repo["last_sync"])} · 미완료: {escape(flags)}</p><ul>{notes}</ul></article>')
    rank_rows = "".join(f'<tr><td>{escape(x["repo"])}</td><td>{x["advisories"]}</td></tr>' for x in data["ranking"])
    package_rows = "".join(f'<tr><td>{escape(x["repo"])}</td><td>{escape(x["ecosystem"])}</td><td>{escape(x["name"])}</td><td>{x["advisories"]}</td></tr>' for x in data["packages"])
    timeline_rows = "".join(f'<tr><td>{escape(x["at"])}</td><td><span class="tag">{escape(x["kind"])}</span></td><td>{escape(x["repo"])}</td><td>{link(x["url"], x["title"] or x["id"])}</td><td>{escape(x["cve"] or x["ghsa"] or "")}</td></tr>' for x in data["timeline"])
    finding_rows = "".join(f'<tr><td>{escape(x["at"])}</td><td>{escape(x["repo"])}</td><td>{link(x["url"], x["title"])}</td><td>{escape(", ".join(x["reasons"]))}</td><td>{escape(", ".join(x["paths"]))}</td><td>{escape(" | ".join(x["evidence"]))}</td></tr>' for x in data["findings"])
    fc = data["forecast"]
    if fc["status"] == "estimated":
        forecast_text = f'향후 {fc["horizon_months"]}개월 공개 보안 공지 예상 {fc["expected"]}건 · 90% 예측 구간 {fc["interval_90"][0]}–{fc["interval_90"][1]}건 · 과거 게시율 {fc["annual_observed_rate"]}건/년'
    else:
        forecast_text = fc.get("reason", "관측 데이터가 부족합니다")
    return f'''<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OSS 보안 타임라인</title><style>
    :root {{ color-scheme: dark; font-family: system-ui, sans-serif; background: #10151e; color: #e8edf4 }}
    body {{ max-width: 1320px; margin: auto; padding: 30px 22px 90px }} h1 {{ font-size: 2rem }} h2 {{ margin-top: 48px }} p,.muted {{ color: #aab8c9 }} a {{ color: #85d9ff }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(280px,1fr)); gap: 14px }} .card {{ background:#1a2432; border:1px solid #354355; border-radius:12px; padding:18px }} .card h3 {{ margin-top:0 }} .card ul {{ padding-left:20px; color:#d6ab78 }}
    .table {{ overflow-x:auto; border:1px solid #354355; border-radius:12px }} table {{ border-collapse:collapse; width:100% }} th,td {{ padding:11px 14px; border-bottom:1px solid #354355; text-align:left; vertical-align:top }} th {{ color:#c2d4e8; background:#1a2432 }} tr:last-child td {{ border-bottom:0 }} .tag {{ background:#293d54; border-radius:6px; padding:3px 7px }}
    </style></head><body><h1>오픈소스 보안 타임라인</h1><p>생성 시각 {escape(data.get("generated_at"))} UTC · 공개 정보 기반. 후보는 취약점 확인 결과가 아닙니다.</p>
    <div class="cards">{''.join(repo_cards)}</div>
    <h2>공개 보안 공지 예측</h2><div class="card"><p>{escape(forecast_text)}</p><p>제로데이 발생 수는 공개 공지 이력으로 식별하거나 예측할 수 없어 미산출로 표시합니다.</p></div>
    <h2>저장소별 보안 공지</h2><div class="table"><table><thead><tr><th>저장소</th><th>고유 공지 수</th></tr></thead><tbody>{rank_rows}</tbody></table></div>
    <h2>패키지별 보안 공지</h2><div class="table"><table><thead><tr><th>저장소</th><th>생태계</th><th>패키지</th><th>고유 공지 수</th></tr></thead><tbody>{package_rows}</tbody></table></div>
    <h2>시간순 타임라인</h2><div class="table"><table><thead><tr><th>공개 시각 (UTC)</th><th>종류</th><th>저장소</th><th>내용</th><th>CVE/GHSA</th></tr></thead><tbody>{timeline_rows}</tbody></table></div>
    <h2>보안 관련 변경 후보</h2><p class="muted">커밋·릴리스 메시지와 변경 파일의 검토 대기 목록입니다. 검증된 제로데이 목록이 아닙니다.</p><div class="table"><table><thead><tr><th>시각 (UTC)</th><th>저장소</th><th>변경</th><th>단서</th><th>변경 파일</th><th>패치 근거</th></tr></thead><tbody>{finding_rows}</tbody></table></div>
    </body></html>'''


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oss-timeline", description="공개 GitHub 저장소 보안 타임라인")
    parser.add_argument("--db", type=Path, default=Path("data/timeline.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)
    sync = commands.add_parser("sync", help="저장소 URL 수집")
    sync.add_argument("repos", nargs="+", help="owner/repo 또는 GitHub URL")
    sync.add_argument("--max-pages", type=int, default=100, help="각 API 종류의 최대 페이지 수")
    sync.add_argument("--max-manifests", type=int, default=100)
    watch = commands.add_parser("watch", help="지정 간격으로 반복 수집")
    watch.add_argument("repos", nargs="+", help="owner/repo 또는 GitHub URL")
    watch.add_argument("--interval-hours", type=float, default=6)
    watch.add_argument("--max-pages", type=int, default=100)
    watch.add_argument("--max-manifests", type=int, default=100)
    report = commands.add_parser("report", help="JSON 또는 HTML 보고서")
    report.add_argument("--repo")
    report.add_argument("--limit", type=int, default=300)
    report.add_argument("--format", choices=["json", "html"], default="json")
    report.add_argument("--output", type=Path)
    research = commands.add_parser("audit", help="체크아웃의 코드 경로에서 보안 가설 찾기")
    research.add_argument("target", help="공개 GitHub URL 또는 로컬 체크아웃 경로")
    research.add_argument("--repo", help="로컬 경로의 owner/repo")
    research.add_argument("--max-files", type=int, default=20_000)
    poc_init = commands.add_parser("poc-init", help="후보용 정상/공격 대조군 PoC 준비")
    poc_init.add_argument("audit_file", type=Path)
    poc_init.add_argument("finding_id")
    poc_verify = commands.add_parser("poc-verify", help="완성된 PoC를 오프라인 컨테이너에서 검증")
    poc_verify.add_argument("manifest_file", type=Path)
    poc_verify.add_argument("--local", action="store_true", help="격리 없이 로컬 실행: 신뢰하는 테스트 코드에만 사용")
    disclosure = commands.add_parser("disclosure", help="재현 근거로 비공개 GHSA/CVE 초안 생성")
    disclosure.add_argument("audit_file", type=Path)
    disclosure.add_argument("finding_id")
    disclosure.add_argument("--claim", type=Path, required=True)
    disclosure.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command in {"sync", "watch"} and (args.max_pages < 1 or args.max_manifests < 1):
        parser.error("페이지 및 매니페스트 제한은 1 이상이어야 합니다")
    if args.command == "watch" and args.interval_hours < 1 / 60:
        parser.error("수집 간격은 1분 이상이어야 합니다")
    if args.command == "audit" and args.max_files < 1:
        parser.error("파일 조사 상한은 1 이상이어야 합니다")
    if args.command in {"audit", "poc-init", "poc-verify", "disclosure"}:
        try:
            if args.command == "audit":
                target_path = Path(args.target)
                if target_path.is_dir():
                    if not args.repo:
                        raise ValueError("로컬 체크아웃은 --repo owner/repo가 필요합니다")
                    repo = repo_name(args.repo)
                    root = target_path
                else:
                    root, repo = checkout(args.target, Path("data/checkouts"))
                output = audit(root, repo, Path("data/research"), args.max_files, args.db)
                summary = json.loads(output.read_text(encoding="utf-8"))
                print(json.dumps({"audit_file": str(output), "repo": repo, "commit": summary["commit"], "hypotheses": len(summary["hypotheses"]), "coverage": summary["coverage"]}, ensure_ascii=False))
            elif args.command == "poc-init":
                print(prepare_poc(args.audit_file, args.finding_id))
            elif args.command == "poc-verify":
                output = PocValidatorAgent().run(args.manifest_file, local=args.local)
                evidence = json.loads(output.read_text(encoding="utf-8"))
                print(json.dumps({"evidence_file": str(output), "mechanical_result": evidence["mechanical_result"]}, ensure_ascii=False))
                return 0 if evidence["mechanical_result"] == "contrast_matched" else 1
            else:
                ghsa, cve = DisclosureAgent().run(args.audit_file, args.finding_id, args.claim, args.evidence)
                print(json.dumps({"ghsa_draft": str(ghsa), "cve_brief": str(cve)}, ensure_ascii=False))
            return 0
        except (ValueError, RuntimeError, OSError, json.JSONDecodeError, KeyError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    store = Store(args.db)
    try:
        if args.command in {"sync", "watch"}:
            client = HttpClient()
            try:
                while True:
                    failures = 0
                    for value in args.repos:
                        try:
                            result = synchronize(client, store, value, args.max_pages, args.max_manifests)
                            print(json.dumps({"repo": result.repo, "packages": len(result.packages), "advisories": len({a['id'] for a in result.advisories}), "events": len(result.events), "findings": len(result.findings), "coverage": result.coverage, "warnings": result.warnings}, ensure_ascii=False), flush=True)
                        except (ApiError, ValueError) as exc:
                            failures += 1
                            print(f"{value}: {exc}", file=sys.stderr, flush=True)
                    if args.command == "sync":
                        return 1 if failures else 0
                    time.sleep(args.interval_hours * 3600)
            except KeyboardInterrupt:
                return 130
        selected = repo_name(args.repo) if args.repo else None
        data = store.report(selected, args.limit)
        output = html_report(data) if args.format == "html" else json.dumps(data, ensure_ascii=False, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(args.output)
        else:
            print(output)
        return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
