"""Privacy-minimized, idempotent aggregation for independent local installations."""
from __future__ import annotations

import hashlib
import hmac
import gzip
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_WIRE_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 250_000
INSTANCE_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
ITEM_FIELDS = {
    "repositories": {"name", "last_sync"},
    "packages": {"repo", "ecosystem", "name"},
    "advisories": {"repo", "id", "ghsa", "cve"},
    "events": {"repo", "id", "kind", "at"},
    "research_runs": {"repo", "commit_hash", "status", "finished_at"},
    "candidates": {"repo", "candidate_key", "status", "commit", "fixture"},
    "contrasts": {"repo", "candidate_key", "commit", "fixture"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _instance_id(path: Path) -> str:
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if INSTANCE_RE.fullmatch(value):
            return value
        raise ValueError("집계 인스턴스 ID 파일이 올바르지 않습니다")
    value = str(uuid.uuid4())
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value + "\n", encoding="utf-8")
    temporary.replace(path)
    return value


def _candidate_key(repo: str, tracking_id: str) -> str:
    return hashlib.sha256(f"{repo}|{tracking_id}".encode()).hexdigest()


def _bundle_digest(bundle: dict) -> str:
    signed = {key: value for key, value in bundle.items() if key not in {"bundle_id", "generated_at"}}
    canonical = json.dumps(signed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _contrast_rows(research_root: Path) -> list[dict]:
    rows: dict[tuple[str, str], dict] = {}
    for orchestration_path in research_root.rglob("orchestration.json") if research_root.is_dir() else []:
        try:
            orchestration = json.loads(orchestration_path.read_text(encoding="utf-8"))
            audit = json.loads((orchestration_path.parent / "audit.json").read_text(encoding="utf-8"))
            repo = str(audit["repo"])
            commit = str(audit["commit"])
            tracking = {str(item["id"]): str(item.get("tracking_id") or item["id"]) for item in audit.get("hypotheses", [])}
            fixture = repo.startswith("fixture/")
            if fixture:
                continue
            for result in orchestration.get("results", []):
                finding_id = str(result.get("finding_id") or "")
                stage = result.get("stages", {}).get("isolated_contrast", {})
                if finding_id and stage.get("status") == "contrast_matched":
                    key = _candidate_key(repo, tracking.get(finding_id, finding_id))
                    rows[(repo, key)] = {"repo": repo, "candidate_key": key, "commit": commit, "fixture": False}
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            continue
    return sorted(rows.values(), key=lambda item: (item["repo"], item["candidate_key"]))


def build_bundle(db_path: Path, research_root: Path, instance_file: Path) -> dict:
    """Export identifiers and counts only; never export source, paths, PoCs or drafts."""
    if not db_path.is_file():
        raise ValueError(f"로컬 타임라인 DB가 없습니다: {db_path}")
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        repositories = [dict(row) for row in connection.execute("SELECT name,last_sync FROM repositories WHERE name NOT LIKE 'fixture/%' ORDER BY name")]
        packages = [dict(row) for row in connection.execute("SELECT repo,ecosystem,name FROM packages WHERE repo NOT LIKE 'fixture/%' ORDER BY repo,ecosystem,name")]
        advisories = [dict(row) for row in connection.execute("""SELECT ar.repo,a.id,a.ghsa,a.cve FROM advisories a
            JOIN advisory_repos ar ON ar.advisory_id=a.id WHERE ar.repo NOT LIKE 'fixture/%' ORDER BY ar.repo,a.id""")]
        events = [dict(row) for row in connection.execute("SELECT repo,id,kind,at FROM events WHERE repo NOT LIKE 'fixture/%' ORDER BY repo,id")]
        runs = [dict(row) for row in connection.execute("SELECT repo,commit_hash,status,finished_at FROM research_runs WHERE repo NOT LIKE 'fixture/%' ORDER BY repo,commit_hash")]
        candidates = [{"repo": row["repo"], "candidate_key": _candidate_key(row["repo"], row["tracking_id"]), "status": row["status"], "commit": row["commit_hash"], "fixture": False} for row in connection.execute("SELECT repo,tracking_id,status,commit_hash FROM research_findings WHERE repo NOT LIKE 'fixture/%' ORDER BY repo,tracking_id")]
    finally:
        connection.close()
    payload = {
        "schema_version": SCHEMA_VERSION,
        "instance_id": _instance_id(instance_file),
        "repositories": repositories,
        "packages": packages,
        "advisories": advisories,
        "events": events,
        "research_runs": runs,
        "candidates": candidates,
        "contrasts": _contrast_rows(research_root),
    }
    payload["bundle_id"] = _bundle_digest(payload)
    payload["generated_at"] = _now()
    validate_bundle(payload)
    return payload


def validate_bundle(bundle: dict) -> None:
    if not isinstance(bundle, dict) or bundle.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("지원하지 않는 집계 번들 스키마입니다")
    allowed_top = {"schema_version", "instance_id", "bundle_id", "generated_at", *ITEM_FIELDS}
    if set(bundle) != allowed_top:
        raise ValueError("집계 번들에 정의되지 않은 필드가 있습니다")
    if not isinstance(bundle.get("generated_at"), str) or not 1 <= len(bundle["generated_at"]) <= 80:
        raise ValueError("집계 생성 시각이 올바르지 않습니다")
    if not INSTANCE_RE.fullmatch(str(bundle.get("instance_id") or "")):
        raise ValueError("집계 인스턴스 ID가 올바르지 않습니다")
    if not re.fullmatch(r"[0-9a-f]{64}", str(bundle.get("bundle_id") or "")):
        raise ValueError("집계 번들 ID가 올바르지 않습니다")
    for name, allowed_fields in ITEM_FIELDS.items():
        value = bundle.get(name)
        if not isinstance(value, list) or len(value) > MAX_ITEMS or any(not isinstance(item, dict) for item in value):
            raise ValueError(f"집계 번들의 {name} 목록이 올바르지 않습니다")
        if any(set(item) - allowed_fields or any(isinstance(field, (dict, list)) for field in item.values()) for item in value):
            raise ValueError(f"집계 번들의 {name} 항목에 정의되지 않은 필드가 있습니다")
    if not hmac.compare_digest(bundle["bundle_id"], _bundle_digest(bundle)):
        raise ValueError("집계 번들 무결성 검증에 실패했습니다")
    encoded = json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode()
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise ValueError("집계 번들이 최대 크기를 초과했습니다")


def _endpoint(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("집계 서버 URL이 올바르지 않습니다")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("원격 집계 서버는 HTTPS를 사용해야 합니다")
    return base_url.rstrip("/") + path


def push_bundle(base_url: str, token: str, bundle: dict, timeout: float = 15) -> dict:
    if not token:
        raise ValueError("집계 업로드 토큰이 없습니다")
    validate_bundle(bundle)
    body = gzip.compress(json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode(), compresslevel=6)
    if len(body) > MAX_WIRE_BYTES:
        raise ValueError("압축된 집계 번들이 전송 크기 제한을 초과했습니다")
    request = Request(_endpoint(base_url, "/v1/ingest"), data=body, method="POST", headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Content-Encoding": "gzip", "User-Agent": "oss-security-timeline/aggregate-v1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read(MAX_BUNDLE_BYTES).decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read(2048).decode("utf-8", "replace")
        raise RuntimeError(f"집계 서버가 HTTP {exc.code}을 반환했습니다: {detail}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"집계 서버에 연결할 수 없습니다: {exc}") from exc


def fetch_stats(base_url: str, timeout: float = 3) -> dict:
    request = Request(_endpoint(base_url, "/v1/stats"), headers={"Accept": "application/json", "User-Agent": "oss-security-timeline/aggregate-v1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read(64 * 1024).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, UnicodeError) as exc:
        raise RuntimeError(f"중앙 집계 통계를 읽을 수 없습니다: {exc}") from exc
    if data.get("schema_version") != SCHEMA_VERSION or not isinstance(data.get("counts"), dict):
        raise RuntimeError("중앙 집계 통계 형식이 올바르지 않습니다")
    return data


class AggregateStore:
    def __init__(self, filename: Path):
        filename.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(filename, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS bundles (bundle_id TEXT PRIMARY KEY,instance_id TEXT NOT NULL,generated_at TEXT,ingested_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS repositories (name TEXT PRIMARY KEY,last_sync TEXT);
            CREATE TABLE IF NOT EXISTS packages (repo TEXT NOT NULL,ecosystem TEXT NOT NULL,name TEXT NOT NULL,PRIMARY KEY(repo,ecosystem,name));
            CREATE TABLE IF NOT EXISTS advisories (canonical_id TEXT PRIMARY KEY,ghsa TEXT,cve TEXT);
            CREATE TABLE IF NOT EXISTS advisory_aliases (alias TEXT PRIMARY KEY,canonical_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS advisory_repos (canonical_id TEXT NOT NULL,repo TEXT NOT NULL,PRIMARY KEY(canonical_id,repo));
            CREATE TABLE IF NOT EXISTS events (repo TEXT NOT NULL,id TEXT NOT NULL,kind TEXT,at TEXT,PRIMARY KEY(repo,id));
            CREATE TABLE IF NOT EXISTS research_runs (repo TEXT NOT NULL,commit_hash TEXT NOT NULL,status TEXT,finished_at TEXT,PRIMARY KEY(repo,commit_hash));
            CREATE TABLE IF NOT EXISTS candidates (repo TEXT NOT NULL,candidate_key TEXT NOT NULL,status TEXT,commit_hash TEXT,fixture INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(repo,candidate_key));
            CREATE TABLE IF NOT EXISTS contrasts (repo TEXT NOT NULL,candidate_key TEXT NOT NULL,commit_hash TEXT,fixture INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(repo,candidate_key));
        """)

    @staticmethod
    def _text(item: dict, key: str, limit: int = 300) -> str:
        value = str(item.get(key) or "")
        if not value or len(value) > limit or "\x00" in value:
            raise ValueError(f"집계 필드 {key}가 올바르지 않습니다")
        return value

    @classmethod
    def _repo(cls, item: dict) -> str:
        value = cls._text(item, "repo", 220)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", value):
            raise ValueError("집계 저장소 식별자가 올바르지 않습니다")
        return value

    @classmethod
    def _candidate(cls, item: dict) -> str:
        value = cls._text(item, "candidate_key", 64)
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("집계 후보 식별자가 올바르지 않습니다")
        return value

    def _advisory(self, item: dict) -> None:
        repo = self._repo(item)
        aliases = [str(item.get(key) or "") for key in ("ghsa", "cve", "id")]
        aliases = list(dict.fromkeys(value for value in aliases if value and len(value) <= 100))
        if not aliases:
            raise ValueError("공지 식별자가 없습니다")
        existing = {row["canonical_id"] for alias in aliases for row in self.db.execute("SELECT canonical_id FROM advisory_aliases WHERE alias=?", (alias,))}
        canonical = sorted(existing)[0] if existing else next((value for value in aliases if value.startswith("GHSA-")), next((value for value in aliases if value.startswith("CVE-")), aliases[0]))
        for old in existing - {canonical}:
            self.db.execute("INSERT OR IGNORE INTO advisory_repos SELECT ?,repo FROM advisory_repos WHERE canonical_id=?", (canonical, old))
            self.db.execute("DELETE FROM advisory_repos WHERE canonical_id=?", (old,))
            self.db.execute("UPDATE advisory_aliases SET canonical_id=? WHERE canonical_id=?", (canonical, old))
            self.db.execute("DELETE FROM advisories WHERE canonical_id=?", (old,))
        ghsa = next((value for value in aliases if value.startswith("GHSA-")), None)
        cve = next((value for value in aliases if value.startswith("CVE-")), None)
        self.db.execute("INSERT INTO advisories VALUES(?,?,?) ON CONFLICT(canonical_id) DO UPDATE SET ghsa=COALESCE(excluded.ghsa,ghsa),cve=COALESCE(excluded.cve,cve)", (canonical, ghsa, cve))
        for alias in aliases:
            self.db.execute("INSERT INTO advisory_aliases VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET canonical_id=excluded.canonical_id", (alias, canonical))
        self.db.execute("INSERT OR IGNORE INTO advisory_repos VALUES(?,?)", (canonical, repo))

    def ingest(self, bundle: dict) -> dict:
        validate_bundle(bundle)
        with self.db:
            if self.db.execute("SELECT 1 FROM bundles WHERE bundle_id=?", (bundle["bundle_id"],)).fetchone():
                return {"accepted": False, "duplicate": True, "stats": self.stats()}
            for item in bundle["repositories"]:
                name = self._text(item, "name")
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", name):
                    raise ValueError("집계 저장소 식별자가 올바르지 않습니다")
                self.db.execute("INSERT INTO repositories VALUES(?,?) ON CONFLICT(name) DO UPDATE SET last_sync=CASE WHEN last_sync IS NULL OR excluded.last_sync>last_sync THEN excluded.last_sync ELSE last_sync END", (name, item.get("last_sync")))
            for item in bundle["packages"]:
                self.db.execute("INSERT OR IGNORE INTO packages VALUES(?,?,?)", (self._repo(item), self._text(item, "ecosystem", 80), self._text(item, "name")))
            for item in bundle["advisories"]:
                self._advisory(item)
            for item in bundle["events"]:
                self.db.execute("INSERT INTO events VALUES(?,?,?,?) ON CONFLICT(repo,id) DO UPDATE SET kind=excluded.kind,at=excluded.at", (self._repo(item), self._text(item, "id"), str(item.get("kind") or "")[:80], str(item.get("at") or "")[:80]))
            for item in bundle["research_runs"]:
                self.db.execute("INSERT INTO research_runs VALUES(?,?,?,?) ON CONFLICT(repo,commit_hash) DO UPDATE SET status=excluded.status,finished_at=CASE WHEN finished_at IS NULL OR excluded.finished_at>finished_at THEN excluded.finished_at ELSE finished_at END", (self._repo(item), self._text(item, "commit_hash", 100), str(item.get("status") or "")[:80], str(item.get("finished_at") or "")[:80]))
            for item in bundle["candidates"]:
                self.db.execute("INSERT INTO candidates VALUES(?,?,?,?,?) ON CONFLICT(repo,candidate_key) DO UPDATE SET status=excluded.status,commit_hash=excluded.commit_hash,fixture=excluded.fixture", (self._repo(item), self._candidate(item), str(item.get("status") or "")[:80], str(item.get("commit") or "")[:100], int(bool(item.get("fixture")))))
            for item in bundle["contrasts"]:
                self.db.execute("INSERT INTO contrasts VALUES(?,?,?,?) ON CONFLICT(repo,candidate_key) DO UPDATE SET commit_hash=excluded.commit_hash,fixture=excluded.fixture", (self._repo(item), self._candidate(item), str(item.get("commit") or "")[:100], int(bool(item.get("fixture")))))
            self.db.execute("INSERT INTO bundles VALUES(?,?,?,?)", (bundle["bundle_id"], bundle["instance_id"], str(bundle.get("generated_at") or "")[:80], _now()))
        return {"accepted": True, "duplicate": False, "stats": self.stats()}

    def stats(self) -> dict:
        count = lambda table, where="": self.db.execute(f"SELECT COUNT(*) FROM {table} {where}").fetchone()[0]
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": _now(),
            "counts": {
                "contributors": self.db.execute("SELECT COUNT(DISTINCT instance_id) FROM bundles").fetchone()[0],
                "bundles": count("bundles"),
                "repositories": count("repositories"),
                "packages": count("packages"),
                "advisories": count("advisories"),
                "events": count("events"),
                "research_runs": count("research_runs"),
                "candidates": count("candidates", "WHERE fixture=0"),
                "contrasts": count("contrasts", "WHERE fixture=0"),
                "fixture_contrasts": count("contrasts", "WHERE fixture=1"),
            },
            "last_ingested_at": self.db.execute("SELECT MAX(ingested_at) FROM bundles").fetchone()[0],
        }

    def close(self) -> None:
        self.db.close()
