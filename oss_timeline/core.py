from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import random
import re
import sqlite3
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


UTC = timezone.utc
MANIFESTS = {"package.json", "pyproject.toml", "Cargo.toml", "go.mod", "composer.json", "pom.xml"}
SECURITY_WORDS = re.compile(r"\b(security|vulnerab(?:ility|ilities)|cve-\d{4}-\d+|ghsa-[\w-]+|xss|ssrf|rce|injection|traversal|auth(?:entication|orization)? bypass|deserializ|privilege escalation|sanitize|hardening)\b", re.I)
SENSITIVE_PATHS = re.compile(r"(?:^|/)(?:auth|security|crypto|parser|upload|request|http|api)(?:/|[._-])", re.I)
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
ECOSYSTEMS = {"npm": "npm", "pip": "PyPI", "rust": "crates.io", "go": "Go", "composer": "Packagist", "maven": "Maven"}


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def repo_name(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password or parsed.port:
            raise ValueError("HTTPS github.com 저장소 URL만 허용합니다")
        parts = [p for p in parsed.path.strip("/").split("/") if p]
    else:
        parts = value.strip("/").split("/")
    if len(parts) != 2:
        raise ValueError("owner/repo 또는 https://github.com/owner/repo 형식이어야 합니다")
    parts[1] = parts[1].removesuffix(".git")
    if not all(REPO_RE.fullmatch(p) and p not in {".", ".."} for p in parts):
        raise ValueError("유효하지 않은 저장소 이름입니다")
    return "/".join(parts)


class ApiError(RuntimeError):
    pass


class HttpClient:
    def __init__(self, token: str | None = None):
        self.token = token or os.getenv("GITHUB_TOKEN")

    def request(self, url: str, data: dict | None = None, github: bool = True) -> tuple[object, dict]:
        host = urllib.parse.urlparse(url).hostname
        if host not in ({"api.github.com"} if github else {"api.osv.dev"}):
            raise ApiError("허용되지 않은 API 호스트")
        headers = {"Accept": "application/vnd.github+json" if github else "application/json", "User-Agent": "oss-security-timeline/0.1"}
        if github and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = None if data is None else json.dumps(data).encode()
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=25) as response:
                    return json.load(response), dict(response.headers)
            except urllib.error.HTTPError as exc:
                if exc.code in {429, 502, 503, 504} and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                detail = exc.read(300).decode("utf-8", "replace")
                raise ApiError(f"{host} HTTP {exc.code}: {detail}") from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise ApiError(f"{host} 연결 실패: {exc}") from exc
        raise ApiError("API 재시도 실패")

    def github(self, path: str, params: dict | None = None) -> object:
        query = urllib.parse.urlencode(params or {}, doseq=True)
        url = "https://api.github.com" + path + ("?" + query if query else "")
        return self.request(url)[0]

    def pages(self, path: str, params: dict | None = None, max_pages: int = 100) -> tuple[list[dict], bool]:
        records: list[dict] = []
        url = "https://api.github.com" + path + "?" + urllib.parse.urlencode({**(params or {}), "per_page": 100})
        seen: set[str] = set()
        for _ in range(max_pages):
            if url in seen:
                raise ApiError("페이지 순환이 감지되었습니다")
            seen.add(url)
            batch, headers = self.request(url)
            if not isinstance(batch, list):
                raise ApiError("예상하지 못한 GitHub 페이지 응답")
            records.extend(batch)
            links = headers.get("Link", "")
            match = re.search(r'<(https://api\.github\.com[^>]+)>; rel="next"', links)
            url = match.group(1) if match else ""
            if not url:
                return records, False
        return records, bool(url)

    def osv(self, ecosystem: str, package: str, max_pages: int = 100) -> tuple[list[dict], bool]:
        vulns: list[dict] = []
        page_token = ""
        seen: set[str] = set()
        for _ in range(max_pages):
            payload = {"package": {"ecosystem": ecosystem, "name": package}}
            if page_token:
                payload["page_token"] = page_token
            result, _ = self.request("https://api.osv.dev/v1/query", payload, github=False)
            if not isinstance(result, dict):
                raise ApiError("예상하지 못한 OSV 응답")
            vulns.extend(result.get("vulns", []))
            page_token = result.get("next_page_token", "")
            if not page_token:
                return vulns, False
            if page_token in seen:
                raise ApiError("OSV 페이지 순환이 감지되었습니다")
            seen.add(page_token)
        return vulns, bool(page_token)


@dataclass
class Collection:
    repo: str
    packages: list[tuple[str, str, str]] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    advisories: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coverage: dict[str, bool] = field(default_factory=dict)


def manifest_package(path: str, text: str) -> tuple[str, str] | None:
    name = path.rsplit("/", 1)[-1]
    try:
        if name == "package.json":
            return "npm", json.loads(text)["name"]
        if name == "pyproject.toml":
            doc = tomllib.loads(text)
            package = doc.get("project", {}).get("name") or doc.get("tool", {}).get("poetry", {}).get("name")
            return ("pip", package) if package else None
        if name == "Cargo.toml":
            package = tomllib.loads(text).get("package", {}).get("name")
            return ("rust", package) if package else None
        if name == "go.mod":
            match = re.search(r"^module\s+(\S+)", text, re.M)
            return ("go", match.group(1)) if match else None
        if name == "composer.json":
            return "composer", json.loads(text)["name"]
        if name == "pom.xml":
            root = ET.fromstring(text)
            ns = {"m": root.tag.split("}")[0].removeprefix("{")} if "}" in root.tag else {}
            prefix = "m:" if ns else ""
            group = root.findtext(prefix + "groupId", namespaces=ns) or root.findtext(prefix + "parent/" + prefix + "groupId", namespaces=ns)
            artifact = root.findtext(prefix + "artifactId", namespaces=ns)
            return ("maven", f"{group}:{artifact}") if group and artifact else None
    except (ValueError, KeyError, ET.ParseError):
        return None
    return None


class InventoryAgent:
    def __init__(self, client: HttpClient, max_manifests: int):
        self.client, self.max_manifests = client, max_manifests

    def run(self, result: Collection) -> dict:
        meta = self.client.github("/repos/" + result.repo)
        if not isinstance(meta, dict) or meta.get("private"):
            raise ApiError("공개 저장소 정보가 없습니다")
        result.repo = meta["full_name"]
        branch = meta["default_branch"]
        path = "/repos/" + result.repo
        tree = self.client.github(path + "/git/trees/" + urllib.parse.quote(branch, safe=""), {"recursive": "1"})
        if not isinstance(tree, dict):
            raise ApiError("트리 응답이 잘못되었습니다")
        candidates = [x for x in tree.get("tree", []) if x.get("type") == "blob" and x.get("path", "").rsplit("/", 1)[-1] in MANIFESTS and x.get("size", 0) <= 200_000]
        candidates.sort(key=lambda x: (x["path"].count("/"), x["path"]))
        if tree.get("truncated"):
            result.warnings.append("Git 트리가 잘려 패키지 목록이 불완전할 수 있습니다")
        if len(candidates) > self.max_manifests:
            result.warnings.append(f"매니페스트 {len(candidates)}개 중 {self.max_manifests}개만 읽었습니다")
        for item in candidates[: self.max_manifests]:
            try:
                blob = self.client.github(path + "/git/blobs/" + item["sha"])
                if not isinstance(blob, dict) or blob.get("encoding") != "base64":
                    continue
                content = base64.b64decode(blob["content"]).decode("utf-8", "replace")
                package = manifest_package(item["path"], content)
                if package and package[1]:
                    result.packages.append((package[0], package[1], item["path"]))
            except (ApiError, ValueError) as exc:
                result.warnings.append(f"매니페스트 {item['path']} 읽기 실패: {exc}")
        result.packages = sorted(set(result.packages))
        result.coverage["inventory"] = not tree.get("truncated") and len(candidates) <= self.max_manifests
        if not result.packages:
            result.warnings.append("공개 매니페스트에서 배포 패키지를 확인하지 못했습니다")
        return meta


class ChangeAgent:
    def __init__(self, client: HttpClient, max_pages: int):
        self.client, self.max_pages = client, max_pages

    def run(self, result: Collection) -> None:
        base = "/repos/" + result.repo
        for kind, endpoint in (("release", "/releases"), ("commit", "/commits")):
            try:
                rows, truncated = self.client.pages(base + endpoint, max_pages=self.max_pages)
                result.coverage[kind] = not truncated
                if truncated:
                    result.warnings.append(f"{kind} 페이지 제한에 도달했습니다. 전수 수집이 아닙니다")
                for row in rows:
                    if kind == "release":
                        stamp = row.get("published_at") or row.get("created_at")
                        if not stamp or row.get("draft"):
                            continue
                        event = {"id": "release:" + str(row["id"]), "kind": kind, "at": stamp, "title": row.get("name") or row.get("tag_name") or "release", "url": row.get("html_url"), "body": row.get("body") or "", "paths": []}
                    else:
                        commit = row.get("commit", {})
                        stamp = commit.get("committer", {}).get("date") or commit.get("author", {}).get("date")
                        if not stamp:
                            continue
                        message = commit.get("message") or ""
                        event = {"id": "commit:" + row["sha"], "kind": kind, "at": stamp, "title": message.splitlines()[0][:300], "url": row.get("html_url"), "body": message, "paths": []}
                    result.events.append(event)
            except ApiError as exc:
                result.coverage[kind] = False
                result.warnings.append(f"{kind} 수집 실패: {exc}")


def advisory_key(row: dict) -> str:
    aliases = [row.get("ghsa_id"), *(row.get("aliases") or []), row.get("cve_id"), row.get("id")]
    return next((x for x in aliases if isinstance(x, str) and x.startswith("GHSA-")), None) or next((x for x in aliases if isinstance(x, str) and x.startswith("CVE-")), None) or next((x for x in aliases if isinstance(x, str)), "unknown")


def normalize_advisory(row: dict, source: str, package: tuple[str, str] | None = None) -> dict:
    key = advisory_key(row)
    affected = []
    if source == "OSV":
        for item in row.get("affected", []):
            p = item.get("package", {})
            affected.append({"ecosystem": p.get("ecosystem"), "name": p.get("name"), "range": "", "patched": ""})
        if package and not affected:
            affected.append({"ecosystem": package[0], "name": package[1], "range": "", "patched": ""})
        cvss = None
        stamp = row.get("published") or row.get("modified")
        url = "https://osv.dev/vulnerability/" + urllib.parse.quote(row.get("id", key), safe="")
    else:
        for item in row.get("vulnerabilities", []):
            p = item.get("package", {})
            affected.append({"ecosystem": p.get("ecosystem"), "name": p.get("name"), "range": item.get("vulnerable_version_range") or "", "patched": item.get("patched_versions") or item.get("first_patched_version") or ""})
        cvss = (row.get("cvss") or {}).get("score")
        stamp = row.get("published_at")
        url = row.get("html_url")
    return {"id": key, "ghsa": row.get("ghsa_id") or next((x for x in row.get("aliases", []) if x.startswith("GHSA-")), None), "cve": row.get("cve_id") or next((x for x in row.get("aliases", []) if x.startswith("CVE-")), None), "published_at": stamp, "modified_at": row.get("updated_at") or row.get("modified"), "summary": row.get("summary") or "", "severity": row.get("severity") or "unknown", "cvss": cvss, "url": url, "source": source, "affected": affected}


class AdvisoryAgent:
    def __init__(self, client: HttpClient, max_pages: int):
        self.client, self.max_pages = client, max_pages

    def run(self, result: Collection) -> None:
        try:
            rows, cut = self.client.pages("/repos/" + result.repo + "/security-advisories", {"state": "published"}, self.max_pages)
            result.coverage["repository_advisories"] = not cut
            if cut:
                result.warnings.append("저장소 보안 공지 페이지 제한에 도달했습니다")
            result.advisories.extend(normalize_advisory(x, "repository") for x in rows)
        except ApiError as exc:
            result.coverage["repository_advisories"] = False
            result.warnings.append(f"저장소 보안 공지 수집 실패: {exc}")
        unique = sorted({(ecosystem, package) for ecosystem, package, _ in result.packages})
        if not unique:
            result.coverage["package_advisories"] = False
            return
        complete = True
        for ecosystem, package in unique:
            for advisory_type in ("reviewed", "unreviewed"):
                try:
                    rows, cut = self.client.pages("/advisories", {"ecosystem": ecosystem, "affects": package, "type": advisory_type}, self.max_pages)
                    if cut:
                        complete = False
                        result.warnings.append(f"{package} {advisory_type} 글로벌 공지 페이지 제한에 도달했습니다")
                    result.advisories.extend(normalize_advisory(x, "GitHub " + advisory_type, (ecosystem, package)) for x in rows)
                except ApiError as exc:
                    complete = False
                    result.warnings.append(f"{package} {advisory_type} 글로벌 공지 수집 실패: {exc}")
            osv_ecosystem = ECOSYSTEMS.get(ecosystem)
            if osv_ecosystem:
                try:
                    rows, cut = self.client.osv(osv_ecosystem, package, self.max_pages)
                    if cut:
                        complete = False
                        result.warnings.append(f"{package} OSV 페이지 제한에 도달했습니다")
                    result.advisories.extend(normalize_advisory(x, "OSV", (osv_ecosystem, package)) for x in rows)
                except ApiError as exc:
                    complete = False
                    result.warnings.append(f"{package} OSV 수집 실패: {exc}")
        result.coverage["package_advisories"] = complete


class CandidateAgent:
    """Public signals for human review; never labels a finding as a vulnerability."""
    def __init__(self, client: HttpClient, max_details: int = 30):
        self.client, self.max_details = client, max_details

    def run(self, result: Collection) -> None:
        published_ids = {x.lower() for a in result.advisories for x in (a.get("id"), a.get("ghsa"), a.get("cve")) if x}
        inspected = 0
        for event in result.events:
            text = event["title"] + "\n" + event["body"]
            terms = sorted({m.group(0).lower() for m in SECURITY_WORDS.finditer(text)})
            if not terms:
                continue
            identifiers = {x.lower() for x in re.findall(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)", text, re.I)}
            if identifiers and identifiers <= published_ids:
                continue
            paths: list[str] = []
            evidence: list[str] = []
            patch_identifiers: set[str] = set()
            if event["kind"] == "commit" and inspected < self.max_details:
                inspected += 1
                try:
                    detail = self.client.github("/repos/" + result.repo + "/commits/" + event["id"].split(":", 1)[1])
                    if isinstance(detail, dict):
                        files = detail.get("files", [])
                        paths = [x.get("filename", "") for x in files if x.get("filename")][:30]
                        for item in files:
                            patch = item.get("patch") or ""
                            patch_identifiers.update(x.lower() for x in re.findall(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)", patch, re.I))
                            additions = [line[1:].strip() for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++")]
                            relevant = [line for line in additions if SECURITY_WORDS.search(line) or re.search(r"\b(?:validate|reject|deny|escape|sanitize|authorize|permission|limit|safe)\b", line, re.I)]
                            if relevant:
                                evidence.append(item.get("filename", "") + ": " + relevant[0][:160])
                            if len(evidence) >= 3:
                                break
                except ApiError as exc:
                    result.warnings.append(f"커밋 근거 수집 실패 {event['id']}: {exc}")
            if patch_identifiers and patch_identifiers <= published_ids:
                continue
            if paths and all(p.lower().endswith((".md", ".rst", ".txt", ".adoc")) for p in paths):
                continue
            if any(SENSITIVE_PATHS.search(p) for p in paths):
                terms.append("security-sensitive file")
            result.findings.append({"id": event["id"], "at": event["at"], "title": event["title"], "url": event["url"], "reasons": terms[:8], "paths": paths, "evidence": evidence, "status": "review_needed"})
        if inspected == self.max_details:
            result.warnings.append(f"커밋 상세 조사 상한 {self.max_details}건에 도달했습니다")


def forecast(publications: list[str], months: int = 12, as_of: datetime | None = None) -> dict:
    as_of = as_of or datetime.now(UTC)
    observed = [x for x in (parse_time(v) for v in publications) if x and x <= as_of]
    if len(observed) < 5 or (as_of - min(observed)).days < 730:
        return {"status": "insufficient_data", "reason": "공개 공지 5건 및 관측 기간 24개월 이상 필요"}
    years = (as_of - min(observed)).days / 365.2425
    annual = len(observed) / years
    # Gamma-Poisson posterior predictive interval; fixed seed keeps reports reproducible.
    rng = random.Random(71)
    shape = len(observed) + 1
    rate = years + 1
    draws = []
    for _ in range(10_000):
        lam = rng.gammavariate(shape, 1 / rate) * months / 12
        if lam < 30:
            threshold, cumulative, k, term = rng.random(), math.exp(-lam), 0, math.exp(-lam)
            while cumulative < threshold:
                k += 1
                term *= lam / k
                cumulative += term
            draws.append(k)
        else:
            draws.append(max(0, round(rng.gauss(lam, math.sqrt(lam)))))
    draws.sort()
    return {"status": "estimated", "horizon_months": months, "historical_publications": len(observed), "annual_observed_rate": round(annual, 2), "expected": round(shape / rate * months / 12, 1), "interval_90": [draws[499], draws[9499]], "target": "future_public_advisories", "zero_day_count": None}


class Store:
    def __init__(self, filename: Path):
        filename.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(filename)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS repositories (name TEXT PRIMARY KEY, url TEXT NOT NULL, last_sync TEXT, coverage TEXT NOT NULL DEFAULT '{}', warnings TEXT NOT NULL DEFAULT '[]');
            CREATE TABLE IF NOT EXISTS packages (repo TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL, manifest TEXT NOT NULL, PRIMARY KEY(repo, ecosystem, name, manifest));
            CREATE TABLE IF NOT EXISTS advisories (id TEXT PRIMARY KEY, ghsa TEXT, cve TEXT, published_at TEXT, modified_at TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, summary TEXT, severity TEXT, cvss REAL, url TEXT, sources TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS advisory_observations (advisory_id TEXT NOT NULL, observed_at TEXT NOT NULL, modified_at TEXT, content_hash TEXT NOT NULL, PRIMARY KEY(advisory_id,content_hash));
            CREATE TABLE IF NOT EXISTS advisory_repos (advisory_id TEXT NOT NULL, repo TEXT NOT NULL, PRIMARY KEY(advisory_id, repo));
            CREATE TABLE IF NOT EXISTS advisory_packages (advisory_id TEXT NOT NULL, repo TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL, version_range TEXT, patched TEXT, PRIMARY KEY(advisory_id, repo, ecosystem, name));
            CREATE TABLE IF NOT EXISTS events (repo TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, at TEXT NOT NULL, title TEXT, url TEXT, first_seen TEXT NOT NULL, PRIMARY KEY(repo, id));
            CREATE TABLE IF NOT EXISTS findings (repo TEXT NOT NULL, id TEXT NOT NULL, at TEXT NOT NULL, title TEXT, url TEXT, reasons TEXT, paths TEXT NOT NULL DEFAULT '[]', evidence TEXT NOT NULL DEFAULT '[]', status TEXT, PRIMARY KEY(repo, id));
        """)
        columns = {x["name"] for x in self.db.execute("PRAGMA table_info(findings)")}
        if "paths" not in columns:
            self.db.execute("ALTER TABLE findings ADD COLUMN paths TEXT NOT NULL DEFAULT '[]'")
        if "evidence" not in columns:
            self.db.execute("ALTER TABLE findings ADD COLUMN evidence TEXT NOT NULL DEFAULT '[]'")

    def save(self, result: Collection) -> None:
        stamp = now()
        with self.db:
            self.db.execute("INSERT INTO repositories(name,url,last_sync,coverage,warnings) VALUES(?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET last_sync=excluded.last_sync,coverage=excluded.coverage,warnings=excluded.warnings", (result.repo, "https://github.com/" + result.repo, stamp, json.dumps(result.coverage), json.dumps(result.warnings, ensure_ascii=False)))
            self.db.execute("DELETE FROM packages WHERE repo=?", (result.repo,))
            self.db.executemany("INSERT INTO packages VALUES(?,?,?,?)", ((result.repo, *p) for p in result.packages))
            known = {(row["ecosystem"], row["name"]) for row in self.db.execute("SELECT ecosystem,name FROM packages WHERE repo=?", (result.repo,))}
            for raw in result.advisories:
                matched = self.db.execute("SELECT id FROM advisories WHERE id=? OR (ghsa IS NOT NULL AND ghsa=?) OR (cve IS NOT NULL AND cve=?) LIMIT 1", (raw["id"], raw.get("ghsa"), raw.get("cve"))).fetchone()
                if matched:
                    raw = {**raw, "id": matched["id"]}
                existing = self.db.execute("SELECT * FROM advisories WHERE id=?", (raw["id"],)).fetchone()
                sources = sorted(set((json.loads(existing["sources"]) if existing else []) + [raw["source"]]))
                chosen = raw if not existing or raw["source"] != "OSV" else dict(existing)
                self.db.execute("INSERT INTO advisories(id,ghsa,cve,published_at,modified_at,first_seen,last_seen,summary,severity,cvss,url,sources) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET ghsa=COALESCE(excluded.ghsa,advisories.ghsa),cve=COALESCE(excluded.cve,advisories.cve),published_at=COALESCE(excluded.published_at,advisories.published_at),modified_at=COALESCE(excluded.modified_at,advisories.modified_at),last_seen=excluded.last_seen,summary=CASE WHEN excluded.summary!='' THEN excluded.summary ELSE advisories.summary END,severity=CASE WHEN excluded.severity!='unknown' THEN excluded.severity ELSE advisories.severity END,cvss=COALESCE(excluded.cvss,advisories.cvss),url=COALESCE(excluded.url,advisories.url),sources=excluded.sources", (raw["id"], raw.get("ghsa"), raw.get("cve"), raw.get("published_at"), raw.get("modified_at"), existing["first_seen"] if existing else stamp, stamp, chosen.get("summary") or "", chosen.get("severity") or "unknown", chosen.get("cvss"), chosen.get("url"), json.dumps(sources)))
                current = self.db.execute("SELECT ghsa,cve,published_at,modified_at,summary,severity,cvss FROM advisories WHERE id=?", (raw["id"],)).fetchone()
                fingerprint = hashlib.sha256(json.dumps(dict(current), sort_keys=True).encode()).hexdigest()
                self.db.execute("INSERT OR IGNORE INTO advisory_observations VALUES(?,?,?,?)", (raw["id"], stamp, current["modified_at"], fingerprint))
                self.db.execute("INSERT OR IGNORE INTO advisory_repos VALUES(?,?)", (raw["id"], result.repo))
                for p in raw["affected"]:
                    ecosystem = p.get("ecosystem")
                    normalized = {"PyPI": "pip", "crates.io": "rust", "Go": "go", "Packagist": "composer", "Maven": "maven"}.get(ecosystem, ecosystem)
                    if (normalized, p.get("name")) in known:
                        self.db.execute("INSERT INTO advisory_packages VALUES(?,?,?,?,?,?) ON CONFLICT(advisory_id,repo,ecosystem,name) DO UPDATE SET version_range=CASE WHEN excluded.version_range!='' THEN excluded.version_range ELSE advisory_packages.version_range END,patched=CASE WHEN excluded.patched!='' THEN excluded.patched ELSE advisory_packages.patched END", (raw["id"], result.repo, normalized, p["name"], p.get("range") or "", p.get("patched") or ""))
            for event in result.events:
                self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?)", (result.repo, event["id"], event["kind"], event["at"], event["title"], event["url"], stamp))
            self.db.executemany("DELETE FROM findings WHERE repo=? AND id=?", ((result.repo, event["id"]) for event in result.events))
            for finding in result.findings:
                self.db.execute("INSERT INTO findings(repo,id,at,title,url,reasons,paths,evidence,status) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(repo,id) DO UPDATE SET reasons=excluded.reasons,paths=excluded.paths,evidence=excluded.evidence", (result.repo, finding["id"], finding["at"], finding["title"], finding["url"], json.dumps(finding["reasons"]), json.dumps(finding.get("paths", [])), json.dumps(finding.get("evidence", [])), finding["status"]))

    def report(self, repo: str | None = None, limit: int = 300) -> dict:
        repositories = [dict(x) for x in self.db.execute("SELECT * FROM repositories ORDER BY name") if repo is None or x["name"] == repo]
        if repo and not repositories:
            raise ValueError("저장되지 않은 저장소입니다")
        scope = [x["name"] for x in repositories]
        if not scope:
            return {"repositories": [], "ranking": [], "packages": [], "timeline": [], "findings": [], "advisory_observations": [], "forecast": {"status": "insufficient_data"}}
        marks = ",".join("?" for _ in scope)
        ranking = [dict(x) for x in self.db.execute(f"SELECT repo,COUNT(DISTINCT advisory_id) AS advisories FROM advisory_repos WHERE repo IN ({marks}) GROUP BY repo ORDER BY advisories DESC,repo", scope)]
        packages = [dict(x) for x in self.db.execute(f"SELECT repo,ecosystem,name,COUNT(DISTINCT advisory_id) AS advisories FROM advisory_packages WHERE repo IN ({marks}) GROUP BY repo,ecosystem,name ORDER BY advisories DESC,repo,name", scope)]
        timeline = [dict(x) for x in self.db.execute(f"SELECT a.id,a.ghsa,a.cve,a.published_at AS at,a.modified_at,a.first_seen,a.summary AS title,a.url,a.severity,ar.repo,'advisory' AS kind FROM advisories a JOIN advisory_repos ar ON ar.advisory_id=a.id WHERE ar.repo IN ({marks}) AND a.published_at IS NOT NULL UNION ALL SELECT a.id,a.ghsa,a.cve,a.modified_at AS at,a.modified_at,a.first_seen,a.summary AS title,a.url,a.severity,ar.repo,'advisory_update' AS kind FROM advisories a JOIN advisory_repos ar ON ar.advisory_id=a.id WHERE ar.repo IN ({marks}) AND a.modified_at IS NOT NULL AND a.modified_at!=a.published_at UNION ALL SELECT id,NULL,NULL,at,NULL,first_seen,title,url,NULL,repo,kind FROM events WHERE repo IN ({marks}) ORDER BY at DESC LIMIT ?", [*scope, *scope, *scope, limit])]
        findings = [dict(x) for x in self.db.execute(f"SELECT * FROM findings WHERE repo IN ({marks}) ORDER BY at DESC LIMIT ?", [*scope, limit])]
        publications = [x["published_at"] for x in self.db.execute(f"SELECT DISTINCT a.id,a.published_at FROM advisories a JOIN advisory_repos ar ON ar.advisory_id=a.id WHERE ar.repo IN ({marks}) AND a.published_at IS NOT NULL", scope)]
        for item in repositories:
            item["coverage"] = json.loads(item["coverage"])
            item["warnings"] = json.loads(item["warnings"])
        for item in findings:
            item["reasons"] = json.loads(item["reasons"])
            item["paths"] = json.loads(item["paths"])
            item["evidence"] = json.loads(item["evidence"])
        observations = [dict(x) for x in self.db.execute(f"SELECT ao.advisory_id,ao.observed_at,ao.modified_at,ar.repo FROM advisory_observations ao JOIN advisory_repos ar ON ar.advisory_id=ao.advisory_id WHERE ar.repo IN ({marks}) ORDER BY ao.observed_at DESC LIMIT ?", [*scope, limit])]
        return {"generated_at": now(), "repositories": repositories, "ranking": ranking, "packages": packages, "timeline": timeline, "findings": findings, "advisory_observations": observations, "forecast": forecast(publications)}


def synchronize(client: HttpClient, store: Store, repo: str, max_pages: int = 100, max_manifests: int = 100) -> Collection:
    result = Collection(repo_name(repo))
    InventoryAgent(client, max_manifests).run(result)
    with ThreadPoolExecutor(max_workers=2) as pool:
        change = pool.submit(ChangeAgent(client, max_pages).run, result)
        advisory = pool.submit(AdvisoryAgent(client, max_pages).run, result)
        change.result()
        advisory.result()
    CandidateAgent(client).run(result)
    store.save(result)
    return result
