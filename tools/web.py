"""Read-only loopback dashboard for the local timeline and research workflow."""
from __future__ import annotations

import argparse
import html
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from oss_timeline.cli import html_report  # noqa: E402
from oss_timeline.core import Store  # noqa: E402


def research_index(root: Path) -> list[dict]:
    output = []
    if not root.is_dir():
        return output
    for audit_file in root.rglob("audit.json"):
        try:
            data = json.loads(audit_file.read_text(encoding="utf-8"))
            hypotheses = data.get("hypotheses", [])
            validated = drafts = 0
            for finding in hypotheses:
                folder = audit_file.parent / finding["id"]
                evidence_file = folder / "evidence.json"
                if evidence_file.is_file():
                    evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
                    validated += evidence.get("mechanical_result") == "contrast_matched"
                drafts += (folder / "GHSA_CANDIDATE.md").is_file() and (folder / "CVE_REQUEST_BRIEF.md").is_file()
            output.append({"repo": data.get("repo", "unknown"), "commit": data.get("commit", ""), "generated_at": data.get("generated_at"), "hypotheses": len(hypotheses), "poc_contrasts": validated, "draft_pairs": drafts, "truncated": bool(data.get("coverage", {}).get("truncated"))})
        except (OSError, ValueError, KeyError):
            continue
    return sorted(output, key=lambda x: x.get("generated_at") or "", reverse=True)


def registry(path: Path) -> list[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def layout(title: str, content: str) -> str:
    return f'''<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title><style>
    :root{{color-scheme:dark;font-family:system-ui,sans-serif;background:#10151e;color:#e8edf4}}body{{max-width:1180px;margin:auto;padding:28px 22px 70px}}a{{color:#85d9ff}}p{{color:#adbbcc}}nav{{display:flex;gap:18px;margin:0 0 28px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}.card{{background:#1a2432;border:1px solid #354355;border-radius:12px;padding:18px}}.table{{overflow-x:auto;border:1px solid #354355;border-radius:12px}}table{{border-collapse:collapse;width:100%}}th,td{{padding:12px;border-bottom:1px solid #354355;text-align:left}}th{{background:#1a2432}}
    </style></head><body><nav><a href="/">타임라인</a><a href="/agents">에이전트</a><a href="/research">코드 조사</a></nav><h1>{html.escape(title)}</h1>{content}</body></html>'''


def agents_page(items: list[dict]) -> str:
    cards = "".join(f'<article class="card"><h2>{html.escape(x.get("name", ""))}</h2><p>{html.escape(x.get("purpose", ""))}</p><small>{html.escape(x.get("lane", ""))} · {html.escape(x.get("code", ""))}</small></article>' for x in items)
    return layout("에이전트 구성", '<p>공개 타임라인과 코드 조사 역할을 보여줍니다. 현재 병렬 실행은 변경·공지 수집 두 역할에 적용됩니다.</p><div class="cards">' + cards + "</div>")


def research_page(items: list[dict]) -> str:
    rows = "".join(f'<tr><td>{html.escape(x["repo"])}</td><td>{html.escape(x["commit"][:12])}</td><td>{x["hypotheses"]}</td><td>{x["poc_contrasts"]}</td><td>{x["draft_pairs"]}</td><td>{"예" if x["truncated"] else "아니오"}</td></tr>' for x in items)
    empty = "<p>아직 코드 조사 기록이 없습니다. <code>python3 -m oss_timeline audit https://github.com/owner/repo</code>로 생성할 수 있습니다.</p>" if not items else ""
    return layout("코드 조사 현황", '<p>후보는 취약점 판정이 아니며, PoC 대조 결과도 검토자의 코드 확인이 필요합니다. 제보 초안 내용은 이 웹 화면에서 공개하지 않습니다.</p>' + empty + '<div class="table"><table><thead><tr><th>저장소</th><th>커밋</th><th>가설</th><th>PoC 대조 성공</th><th>초안 쌍</th><th>조사 잘림</th></tr></thead><tbody>' + rows + '</tbody></table></div>')


def serve(port: int, db_file: Path, research_root: Path, registry_file: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def respond(self, body: str, content_type: str = "text/html; charset=utf-8", status: int = 200) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/health":
                self.respond('{"status":"ok"}', "application/json; charset=utf-8")
                return
            if path in {"/", "/api/report"}:
                store = Store(db_file)
                try:
                    report = store.report()
                finally:
                    store.db.close()
                if path == "/api/report":
                    self.respond(json.dumps(report, ensure_ascii=False), "application/json; charset=utf-8")
                else:
                    body = html_report(report)
                    nav = '<nav style="display:flex;gap:18px;margin-bottom:22px"><a href="/">타임라인</a><a href="/agents">에이전트</a><a href="/research">코드 조사</a></nav>'
                    body = body.replace("<body>", "<body>" + nav, 1)
                    self.respond(body)
                return
            if path == "/agents":
                self.respond(agents_page(registry(registry_file)))
                return
            if path in {"/research", "/api/research"}:
                items = research_index(research_root)
                if path == "/api/research":
                    self.respond(json.dumps(items, ensure_ascii=False), "application/json; charset=utf-8")
                else:
                    self.respond(research_page(items))
                return
            self.respond(layout("찾을 수 없음", "<p>페이지가 없습니다.</p>"), status=404)

        def do_POST(self) -> None:
            self.respond('{"error":"read_only"}', "application/json; charset=utf-8", 405)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Local dashboard: http://127.0.0.1:{server.server_port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only local security timeline dashboard")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", type=Path, default=PROJECT_ROOT / "data/timeline.sqlite3")
    parser.add_argument("--research-root", type=Path, default=PROJECT_ROOT / "data/research")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    serve(args.port, args.db, args.research_root, PROJECT_ROOT / "agents/registry.json")


if __name__ == "__main__":
    main()
