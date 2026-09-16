import json
import tempfile
import unittest
from pathlib import Path

from oss_timeline.core import Collection, Store
from tools.web import disclosure_index, fix_index, graph_page, graph_snapshot, home, lab, load_jobs, reports_page, snapshot, summary


class DashboardTests(unittest.TestCase):
    def test_empty_home_has_real_zero_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            report, stats = snapshot(Path(temp) / "db.sqlite3")
            rendered = home(report, stats, [], [])
            self.assertIn("추적 저장소", rendered)
            self.assertIn("<strong>0</strong>", rendered)
            self.assertNotIn("lodash/lodash", rendered)

    def test_lab_shows_cve_cwe_and_before_after_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            collection = Collection("example/demo", packages=[("npm", "demo", "package.json")])
            collection.advisories = [{"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": "CVE-2026-1234", "published_at": "2026-01-01T00:00:00Z", "modified_at": None, "summary": "Path issue", "severity": "high", "cvss": None, "cwe_ids": ["CWE-22"], "cwe_names": {"CWE-22": "Path Traversal"}, "url": None, "source": "GitHub", "affected": [{"ecosystem": "npm", "name": "demo", "range": "< 2.0", "patched": "2.0"}]}]
            store.save(collection)
            rendered = lab("example/demo", store.report("example/demo"), [], None, None, {"comparisons": [], "truncated": False})
            self.assertIn("CVE-2026-1234", rendered)
            self.assertIn("CWE-22 · Path Traversal", rendered)
            self.assertIn("&lt; 2.0", rendered)
            self.assertIn(">2.0<", rendered)
            store.db.close()

    def test_restart_marks_running_job_interrupted(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "jobs.json"
            path.write_text(json.dumps({"example/demo": {"status": "running", "step": "collecting"}}), encoding="utf-8")
            jobs = load_jobs(path)
            self.assertEqual(jobs["example/demo"]["status"], "failed")
            self.assertIn("중단", jobs["example/demo"]["error"])
            self.assertEqual(fix_index(Path(temp), "example/demo")["comparisons"], [])

    def test_summary_orders_repositories_by_advisory_count(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            store.save(Collection("a/low"))
            high = Collection("z/high")
            high.advisories = [{"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": None, "published_at": "2026-01-01T00:00:00Z", "modified_at": None, "summary": "Issue", "severity": "high", "cvss": None, "url": None, "source": "GitHub", "affected": []}]
            store.save(high)
            rendered = summary(store.report(), [])
            self.assertLess(rendered.index(">z/high</a>"), rendered.index(">a/low</a>"))
            store.db.close()

    def test_graph_links_repo_advisory_cve_cwe_and_package(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            database = folder / "db.sqlite3"
            store = Store(database)
            collection = Collection("example/demo", packages=[("npm", "demo", "package.json")])
            collection.advisories = [{"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": "CVE-2026-1234", "published_at": "2026-01-01T00:00:00Z", "modified_at": None, "summary": "Path issue", "severity": "high", "cvss": None, "cwe_ids": ["CWE-22"], "cwe_names": {"CWE-22": "Path Traversal"}, "url": None, "source": "GitHub", "affected": [{"ecosystem": "npm", "name": "demo", "range": "< 2.0", "patched": "2.0"}]}]
            store.save(collection)
            store.db.close()
            graph = graph_snapshot(database, folder / "research", folder / "fix", "example/demo")
            ids = {node["id"] for node in graph["nodes"]}
            self.assertTrue({"repo:example/demo", "advisory:GHSA-aaaa-bbbb-cccc", "cve:CVE-2026-1234", "cwe:CWE-22", "package:example/demo:npm:demo"} <= ids)
            relations = {edge["relation"] for edge in graph["edges"]}
            self.assertTrue({"보안 공지", "별칭", "유형", "영향"} <= relations)
            rendered = graph_page(["example/demo"], "example/demo")
            self.assertIn('href="/graph"', rendered)
            self.assertIn('src="/graph.js"', rendered)

    def test_cli_disclosure_artifacts_are_read_only_web_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit_folder = root / "example_demo" / ("a" * 40)
            finding_id = "FIND-123456789ABC"
            report_folder = audit_folder / finding_id
            report_folder.mkdir(parents=True)
            audit = {"repo": "example/demo", "commit": "a" * 40, "hypotheses": [{"id": finding_id, "kind": "command_injection", "path": "app.py", "sink_line": 9}]}
            (audit_folder / "audit.json").write_text(json.dumps(audit), encoding="utf-8")
            evidence = {"finding_id": finding_id, "commit": "a" * 40, "mechanical_result": "contrast_matched", "mode": "offline_container", "validated_at": "2026-09-16T00:00:00Z"}
            (report_folder / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
            (report_folder / "GHSA_CANDIDATE.md").write_text("# Private <candidate>\n\nDo not submit automatically.", encoding="utf-8")
            (report_folder / "CVE_REQUEST_BRIEF.md").write_text("# CVE request brief\n", encoding="utf-8")
            reports = disclosure_index(root)
            self.assertEqual(len(reports), 1)
            self.assertTrue(reports[0]["drafts_ready"])
            rendered = reports_page(reports, reports[0]["key"], "ghsa")
            self.assertIn("제보 초안 준비", rendered)
            self.assertIn("Private &lt;candidate&gt;", rendered)
            self.assertNotIn("Private <candidate>", rendered)
            self.assertIn('href="/reports"', rendered)


if __name__ == "__main__":
    unittest.main()
