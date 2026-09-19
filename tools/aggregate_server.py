"""Small authenticated central collector for team-wide, deduplicated totals."""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oss_timeline.aggregate import AggregateStore, MAX_BUNDLE_BYTES, MAX_WIRE_BYTES  # noqa: E402


def serve(host: str, port: int, db_path: Path, token: str) -> None:
    if len(token) < 24:
        raise ValueError("집계 토큰은 24자 이상이어야 합니다")
    store = AggregateStore(db_path)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "OSSTimelineAggregate/1"

        def respond(self, data: dict, status: int = 200, public: bool = False) -> None:
            payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "public, max-age=30" if public else "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            if public:
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/health":
                self.respond({"status": "ok"})
            elif path == "/v1/stats":
                with lock:
                    stats = store.stats()
                self.respond(stats, public=True)
            else:
                self.respond({"error": "not_found"}, status=404)

        def do_POST(self) -> None:
            if urlparse(self.path).path != "/v1/ingest":
                self.respond({"error": "not_found"}, status=404)
                return
            supplied = self.headers.get("Authorization", "")
            if not supplied.startswith("Bearer ") or not secrets.compare_digest(supplied[7:], token):
                self.respond({"error": "unauthorized"}, status=401)
                return
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self.respond({"error": "content_type_must_be_json"}, status=415)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= MAX_WIRE_BYTES:
                    raise ValueError("payload_size")
                wire = self.rfile.read(length)
                if self.headers.get("Content-Encoding", "").lower() == "gzip":
                    with gzip.GzipFile(fileobj=io.BytesIO(wire)) as compressed:
                        raw = compressed.read(MAX_BUNDLE_BYTES + 1)
                    if len(raw) > MAX_BUNDLE_BYTES:
                        raise ValueError("expanded_payload_size")
                elif self.headers.get("Content-Encoding"):
                    raise ValueError("unsupported_content_encoding")
                else:
                    raw = wire
                bundle = json.loads(raw.decode("utf-8"))
                with lock:
                    result = store.ingest(bundle)
                self.respond(result, status=202)
            except (OSError, ValueError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
                self.respond({"error": "invalid_bundle", "detail": str(exc)[:300]}, status=400)

        def log_message(self, pattern: str, *args: object) -> None:
            print(f"{self.address_string()} - {pattern % args}", flush=True)

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Aggregate collector: http://{host}:{server.server_port}/", flush=True)
    print("Public endpoint: /v1/stats · authenticated endpoint: /v1/ingest", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="OSS Security Timeline central aggregate collector")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "aggregate.sqlite3")
    parser.add_argument("--token-env", default="OSS_TIMELINE_AGGREGATE_TOKEN")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    token = os.environ.get(args.token_env, "")
    if not token:
        parser.error(f"환경 변수 {args.token_env}에 업로드 토큰을 설정하세요")
    serve(args.host, args.port, args.db, token)


if __name__ == "__main__":
    main()
