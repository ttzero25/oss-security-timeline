import tempfile
import unittest
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from oss_timeline.cli import html_report
from oss_timeline.core import CandidateAgent, Collection, Store, advisory_key, forecast, manifest_package, normalize_advisory, repo_name, synchronize


class TimelineTests(unittest.TestCase):
    def test_repo_url_rejects_other_hosts_and_nested_paths(self):
        self.assertEqual(repo_name("https://github.com/pypa/packaging.git"), "pypa/packaging")
        for url in ("https://evil.example/pypa/packaging", "https://github.com/pypa/packaging/issues", "http://github.com/pypa/packaging"):
            with self.assertRaises(ValueError):
                repo_name(url)

    def test_manifest_mappings(self):
        self.assertEqual(manifest_package("src/package.json", '{"name":"@scope/demo"}'), ("npm", "@scope/demo"))
        self.assertEqual(manifest_package("pyproject.toml", '[project]\nname="demo"'), ("pip", "demo"))
        self.assertEqual(manifest_package("go.mod", "module example.com/demo\n"), ("go", "example.com/demo"))
        self.assertEqual(manifest_package("pom.xml", "<project><groupId>org.demo</groupId><artifactId>core</artifactId></project>"), ("maven", "org.demo:core"))

    def test_advisory_alias_prefers_ghsa(self):
        self.assertEqual(advisory_key({"id": "OSV-1", "aliases": ["CVE-2024-1234", "GHSA-aaaa-bbbb-cccc"]}), "GHSA-aaaa-bbbb-cccc")
        normalized = normalize_advisory({"ghsa_id": "GHSA-aaaa-bbbb-cccc", "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "demo"}, "first_patched_version": "1.2.3"}]}, "GitHub reviewed")
        self.assertEqual(normalized["affected"][0]["patched"], "1.2.3")
        with_cwe = normalize_advisory({"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cwe_id": "CWE-999", "cwes": [{"cwe_id": "CWE-22"}, {"cwe_id": "CWE-79"}]}, "GitHub reviewed")
        self.assertEqual(with_cwe["cwe_ids"], ["CWE-22", "CWE-79"])
        identifiers = normalize_advisory({"ghsa_id": "GHSA-aaaa-bbbb-cccc", "identifiers": [{"type": "CVE", "value": "CVE-2025-1234"}], "cwe_ids": ["CWE-22"]}, "repository")
        self.assertEqual(identifiers["cve"], "CVE-2025-1234")
        self.assertEqual(identifiers["cwe_ids"], ["CWE-22"])

    def test_candidate_excludes_known_patch_and_docs_only_change(self):
        class FakeClient:
            def github(self, path):
                if path.endswith("/commits/known"):
                    return {"files": [{"filename": "src/auth.py", "patch": "+# GHSA-aaaa-bbbb-cccc\n+validate(user)"}]}
                return {"files": [{"filename": "README.md", "patch": "+security guidance"}]}
        collection = Collection("example/demo", advisories=[{"id": "GHSA-aaaa-bbbb-cccc"}])
        collection.events = [{"id": "commit:known", "kind": "commit", "at": "2025-01-01T00:00:00Z", "title": "security fix", "body": "", "url": "https://github.com/example/demo/commit/known"}, {"id": "commit:docs", "kind": "commit", "at": "2025-01-02T00:00:00Z", "title": "security docs", "body": "", "url": "https://github.com/example/demo/commit/docs"}]
        CandidateAgent(FakeClient()).run(collection)
        self.assertEqual(collection.findings, [])

    def test_orchestrator_collects_package_change_and_advisory(self):
        class FakeClient:
            def __init__(self):
                self.commit_params = []

            def github(self, path, params=None):
                if path == "/repos/example/demo":
                    return {"full_name": "example/demo", "private": False, "default_branch": "main"}
                if "/git/trees/" in path:
                    return {"truncated": False, "tree": [{"type": "blob", "path": "package.json", "size": 20, "sha": "abc"}]}
                if "/git/blobs/" in path:
                    import base64
                    return {"encoding": "base64", "content": base64.b64encode(b'{"name":"demo"}').decode()}
                if "/commits/" in path:
                    return {"files": [{"filename": "src/auth.js", "patch": "+validate(user)"}]}
                raise AssertionError(path)

            def pages(self, path, params=None, max_pages=100):
                if path.endswith("/releases"):
                    return [], False
                if path.endswith("/commits"):
                    self.commit_params.append(params)
                    return [{"sha": "abc", "commit": {"message": "security: validate user", "committer": {"date": "2025-01-01T00:00:00Z"}}, "html_url": "https://github.com/example/demo/commit/abc"}], False
                if path.endswith("/security-advisories"):
                    return [], False
                if path == "/advisories" and params["type"] == "reviewed":
                    return [{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2025-1234", "published_at": "2025-02-01T00:00:00Z", "summary": "issue", "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "demo"}}]}], False
                if path == "/advisories" and params["type"] == "unreviewed":
                    return [], False
                raise AssertionError(path)

            def osv(self, ecosystem, package, max_pages=100):
                return [], False

        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            client = FakeClient()
            result = synchronize(client, store, "https://github.com/example/demo")
            self.assertEqual(len(result.packages), 1)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(store.report()["ranking"][0]["advisories"], 1)
            synchronize(client, store, "https://github.com/example/demo")
            self.assertIsNone(client.commit_params[0])
            self.assertIn("since", client.commit_params[1])
            store.db.close()

    def test_store_deduplicates_and_preserves_first_seen(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            collection = Collection("example/demo", packages=[("npm", "demo", "package.json")], coverage={"inventory": True})
            advisory = {"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": "CVE-2023-1234", "published_at": "2023-01-01T00:00:00Z", "modified_at": "2023-01-02T00:00:00Z", "summary": "Issue", "severity": "high", "cvss": 7.5, "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "source": "GitHub", "affected": [{"ecosystem": "npm", "name": "demo", "range": "< 1.1", "patched": "1.1"}]}
            collection.advisories = [advisory, {**advisory, "id": "CVE-2023-1234", "ghsa": None, "source": "OSV", "cvss": None}]
            collection.events = [{"id": "commit:abc", "kind": "commit", "at": "2023-01-03T00:00:00Z", "title": "Fix", "url": "https://github.com/example/demo/commit/abc"}]
            store.save(collection)
            first = store.db.execute("SELECT first_seen FROM advisories").fetchone()[0]
            store.save(collection)
            report = store.report()
            self.assertEqual(report["ranking"][0]["advisories"], 1)
            self.assertEqual(report["packages"][0]["advisories"], 1)
            self.assertEqual(sum(x["kind"] == "advisory" for x in report["timeline"]), 1)
            self.assertEqual(store.db.execute("SELECT first_seen FROM advisories").fetchone()[0], first)
            self.assertEqual(set(json.loads(store.db.execute("SELECT sources FROM advisories").fetchone()[0])), {"GitHub", "OSV"})
            self.assertEqual(len(report["advisory_observations"]), 1)
            store.db.close()

    def test_cwe_migration_and_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "db.sqlite3"
            legacy = sqlite3.connect(path)
            legacy.execute("CREATE TABLE advisories (id TEXT PRIMARY KEY, ghsa TEXT, cve TEXT, published_at TEXT, modified_at TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, summary TEXT, severity TEXT, cvss REAL, url TEXT, sources TEXT NOT NULL)")
            legacy.close()
            store = Store(path)
            collection = Collection("example/demo")
            collection.advisories = [{"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": "CVE-2025-1234", "published_at": "2025-01-01T00:00:00Z", "modified_at": None, "summary": "Issue", "severity": "high", "cvss": None, "cwe_ids": ["CWE-22"], "url": None, "source": "GitHub", "affected": []}]
            store.save(collection)
            row = next(x for x in store.report()["timeline"] if x["kind"] == "advisory")
            self.assertEqual(row["cve"], "CVE-2025-1234")
            self.assertEqual(row["cwe_ids"], ["CWE-22"])
            store.db.close()

    def test_forecast_has_explicit_unknown_zero_day_and_data_gate(self):
        as_of = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(forecast(["2025-01-01T00:00:00Z"], as_of=as_of)["status"], "insufficient_data")
        dates = [f"{year}-01-01T00:00:00Z" for year in range(2020, 2026)]
        result = forecast(dates, as_of=as_of)
        self.assertEqual(result["status"], "estimated")
        self.assertIsNone(result["zero_day_count"])
        self.assertLessEqual(result["interval_90"][0], result["expected"])
        self.assertGreaterEqual(result["interval_90"][1], result["expected"])

    def test_html_escapes_untrusted_repository_text(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            collection = Collection("example/demo")
            collection.events = [{"id": "commit:abc", "kind": "commit", "at": "2023-01-03T00:00:00Z", "title": "<script>alert(1)</script>", "url": "https://github.com/example/demo/commit/abc"}]
            store.save(collection)
            rendered = html_report(store.report())
            self.assertNotIn("<script>", rendered)
            self.assertIn("&lt;script&gt;", rendered)
            store.db.close()


if __name__ == "__main__":
    unittest.main()
