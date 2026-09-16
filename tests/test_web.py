import json
import tempfile
import unittest
from pathlib import Path

from oss_timeline.core import Collection, Store
from tools.web import benchmark_snapshot, disclosure_index, fix_index, graph_page, graph_snapshot, home, lab, load_jobs, reconcile_research_runs, reports_page, research_status, snapshot, summary


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

    def test_lab_shows_multihop_trace_and_evidence_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            store.save(Collection("example/demo"))
            finding_id = "FIND-123456789ABC"
            audits = [{"repo": "example/demo", "commit": "a" * 40, "generated_at": "2026-09-16T00:00:00Z", "hypotheses": [{"id": finding_id, "kind": "command_injection", "path": "app.py", "source_path": "app.py", "sink_path": "helpers.py", "sink_line": 5, "trace": [{"role": "source", "path": "app.py", "line": 9}, {"role": "call", "path": "service.py", "line": 4}, {"role": "sink", "path": "helpers.py", "line": 5}]}], "poc_contrasts": 1, "draft_pairs": 1, "coverage": {"files_inspected": 3, "languages": ["python"]}, "profile": {"files_seen": 3, "code_files": 3, "languages": {"python": 3}, "frameworks": ["FastAPI"], "project_kind": "service", "recent_changes": {"commits_considered": 4, "files": {"app.py": 2}}}, "orchestration": {"results": [{"finding_id": finding_id, "status": "draft_ready", "stages": {"evidence_gate": {"verdict": "CONFIRMED"}}}]}}]
            rendered = lab("example/demo", store.report("example/demo"), audits, None, None, {"comparisons": [], "truncated": False})
            self.assertIn("입력→호출→위험 동작", rendered)
            self.assertIn("source:app.py:9 → call:service.py:4 → sink:helpers.py:5", rendered)
            self.assertIn("CONFIRMED", rendered)
            self.assertIn("FastAPI", rendered)
            self.assertIn("최근 변경 분석 커밋 4개", rendered)
            store.db.close()

    def test_restart_marks_running_job_interrupted(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "jobs.json"
            path.write_text(json.dumps({"example/demo": {"status": "running", "step": "collecting"}}), encoding="utf-8")
            jobs = load_jobs(path)
            self.assertEqual(jobs["example/demo"]["status"], "failed")
            self.assertIn("중단", jobs["example/demo"]["error"])
            self.assertEqual(fix_index(Path(temp), "example/demo")["comparisons"], [])

    def test_reconciles_legacy_orchestration_without_rerunning_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "db.sqlite3"
            research = root / "research"
            folder = research / "example_demo" / ("a" * 40)
            folder.mkdir(parents=True)
            store = Store(database)
            store.save(Collection("example/demo"))
            store.db.close()
            audit = {"repo": "example/demo", "commit": "a" * 40, "generated_at": "2026-09-16T00:00:00Z", "coverage": {}, "profile": {}, "hypotheses": []}
            orchestration = {"repo": "example/demo", "commit": "a" * 40, "generated_at": "2026-09-16T00:01:00Z", "execution_mode": "limited_process", "results": []}
            (folder / "audit.json").write_text(json.dumps(audit), encoding="utf-8")
            (folder / "orchestration.json").write_text(json.dumps(orchestration), encoding="utf-8")
            first = reconcile_research_runs(database, research)
            second = reconcile_research_runs(database, research)
            self.assertEqual(first["imported"], 1)
            self.assertEqual(second["already_present"], 1)
            store = Store(database)
            run = store.report("example/demo")["research_runs"][0]
            store.db.close()
            self.assertEqual(run["status"], "no_candidates")

    def test_research_status_distinguishes_static_and_completed_runs(self):
        self.assertEqual(research_status(None, None), "미실행")
        self.assertEqual(research_status({"orchestration": {}}, None), "정적 조사만 완료")
        self.assertEqual(research_status({"orchestration": {"results": []}}, None), "결과 파일 있음 · DB 미연동")
        self.assertEqual(research_status(None, {"status": "no_candidates"}), "완료 · 후보 없음")
        self.assertEqual(research_status(None, {"status": "candidates"}), "완료 · 검토 후보 있음")
        self.assertEqual(research_status(None, {"status": "draft_ready"}), "완료 · 초안 준비")

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

    def test_summary_shows_saved_scanner_benchmark(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            path = folder / "latest.json"
            path.write_text(json.dumps({"schema_version": 1, "corpus_version": "fixture-1", "generated_at": "2026-09-16T00:00:00Z", "scope": "static only", "metrics": {"total_cases": 10, "vulnerable_cases": 6, "clean_cases": 4, "true_positive_cases": 6, "false_positive_cases": 1, "true_negative_cases": 3, "recall_at_case_limit": 1.0, "case_precision": 0.8571, "clean_specificity": 0.75, "pass_rate": 0.9}}), encoding="utf-8")
            benchmark = benchmark_snapshot(path)
            store = Store(folder / "db.sqlite3")
            rendered = summary(store.report(), [], benchmark)
            store.db.close()
            self.assertIn("정적 탐지 기준선", rendered)
            self.assertIn("100.0%", rendered)
            self.assertIn("오탐 사례 1건", rendered)
            self.assertIn("실제 저장소 성능을 대신하지 않습니다", rendered)

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
            evidence = {"finding_id": finding_id, "commit": "a" * 40, "mechanical_result": "contrast_matched", "mode": "limited_process", "validated_at": "2026-09-16T00:00:00Z"}
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
