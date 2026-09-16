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
            self.assertIn('id="theme-toggle"', rendered)
            self.assertIn('title="낮과 밤 밝기 전환">☾</button>', rendered)
            self.assertIn('src="/theme.js"', rendered)

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

    def test_fix_comparison_filters_by_year_month_and_uses_dropdowns(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            collection = Collection("example/demo")
            collection.advisories = [{"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": None, "published_at": "2026-05-03T00:00:00Z", "modified_at": None, "summary": "Issue", "severity": "high", "cvss": None, "url": None, "source": "GitHub", "affected": []}]
            store.save(collection)
            comparisons = {"comparisons": [{"advisory_ids": ["GHSA-aaaa-bbbb-cccc"], "commit": "a" * 40, "url": "https://github.com/example/demo/commit/" + "a" * 40, "files": [{"path": "app.py", "status": "modified", "before": "old", "after": "new"}], "warning": None}], "truncated": False}
            rendered = lab("example/demo", store.report("example/demo"), [], None, None, comparisons, "2026", "05")
            store.db.close()
            self.assertIn('name="year"', rendered)
            self.assertIn('value="2026" selected', rendered)
            self.assertIn('name="month"', rendered)
            self.assertIn('value="05" selected', rendered)
            self.assertIn('<details class="panel diff-card">', rendered)
            self.assertIn('<details class="diff-file">', rendered)

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

    def test_lab_shows_poc_scope_and_dependency_preflight(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            store.save(Collection("example/demo"))
            finding_id = "FIND-123456789ABC"
            audits = [{"repo": "example/demo", "commit": "a" * 40, "generated_at": "2026-09-16T00:00:00Z", "hypotheses": [{"id": finding_id, "kind": "template_injection", "path": "view.py", "sink_line": 4}], "coverage": {}, "profile": {}, "orchestration": {"results": [{"finding_id": finding_id, "status": "draft_ready", "web_evidence": {"generator": "bounded_python_template_v1", "proof_scope": "compatible_sink_control_not_framework_execution", "mechanical_result": "contrast_matched"}, "stages": {"build_environment": {"status": "ready", "dependency_preflight": {"stubbed_by_generator": ["flask"], "missing": []}}}}]}}]
            rendered = lab("example/demo", store.report("example/demo"), audits, None, None, {"comparisons": [], "truncated": False})
            store.db.close()
            self.assertIn("동적 PoC·실행 환경", rendered)
            self.assertIn("bounded_python_template_v1", rendered)
            self.assertIn("스텁: flask", rendered)
            self.assertIn("실제 프레임워크 실행 아님", rendered)

    def test_running_lab_uses_neutral_job_status_class(self):
        rendered = lab(None, None, [], {"repo": "example/demo", "status": "running", "step": "코드 조사 중"}, None, {"comparisons": [], "truncated": False})
        self.assertIn('class="notice job-status running"', rendered)
        self.assertIn("SSRF · 네트워크 스텁", rendered)
        self.assertIn("경로 조작 · scratch", rendered)

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
            path.write_text(json.dumps({"schema_version": 1, "corpus_version": "fixture-1", "generated_at": "2026-09-16T00:00:00Z", "scope": "static only", "metrics": {"total_cases": 10, "vulnerable_cases": 6, "clean_cases": 4, "true_positive_cases": 6, "false_positive_cases": 1, "true_negative_cases": 3, "recall_at_case_limit": 1.0, "case_precision": 0.8571, "clean_specificity": 0.75, "pass_rate": 0.9, "by_origin": {"historical": {"cases": 2}}, "historical_pairs_total": 1, "historical_pairs_passed": 1}}), encoding="utf-8")
            benchmark = benchmark_snapshot(path)
            store = Store(folder / "db.sqlite3")
            rendered = summary(store.report(), [], benchmark)
            store.db.close()
            self.assertIn("정적 탐지 기준선", rendered)
            self.assertIn("100.0%", rendered)
            self.assertIn("오탐 사례 1건", rendered)
            self.assertIn("공개 취약/수정 쌍", rendered)
            self.assertIn("출처 고정 사례 2개", rendered)
            self.assertIn("실제 저장소 성능을 대신하지 않습니다", rendered)

    def test_summary_shows_full_upstream_benchmark_separately(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            local = {"corpus_version": "fixture", "generated_at": "2026-09-16T00:00:00Z", "scope": "focused", "metrics": {"total_cases": 2, "vulnerable_cases": 1, "clean_cases": 1, "true_positive_cases": 1, "false_positive_cases": 0, "true_negative_cases": 1, "recall_at_case_limit": 1.0, "case_precision": 1.0, "clean_specificity": 1.0, "pass_rate": 1.0, "by_origin": {"historical": {"cases": 2}}, "historical_pairs_total": 1, "historical_pairs_passed": 1}}
            upstream = {"scope": "immutable full upstream checkout", "max_files_per_checkout": 20000, "metrics": {"cases": 2, "pairs_total": 1, "pairs_passed": 1}}
            rendered = summary(store.report(), [], local, upstream)
            store.db.close()
            self.assertIn("전체 저장소 쌍", rendered)
            self.assertIn("고정 커밋 사례 2개", rendered)
            self.assertIn("immutable full upstream checkout", rendered)

    def test_summary_shows_forecast_interval_confidence_and_context(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "db.sqlite3")
            collection = Collection("example/forecast")
            collection.advisories = [{"id": f"GHSA-aaaa-bbbb-{index:04d}", "ghsa": f"GHSA-aaaa-bbbb-{index:04d}", "cve": None, "published_at": f"{2020 + index}-01-01T00:00:00Z", "modified_at": None, "summary": "Issue", "severity": "medium", "cvss": None, "url": None, "source": "GitHub", "affected": []} for index in range(6)]
            store.save(collection)
            rendered = summary(store.report(), [])
            store.db.close()
            self.assertIn("90% 구간", rendered)
            self.assertIn("저장소별 예측 문맥", rendered)
            self.assertIn("활동량과 코드 규모는 보정 전 참고값", rendered)

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
            self.assertIn('id="graph-density"', rendered)
            self.assertIn("간단히 · 80", rendered)

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
            (report_folder / "submission.json").write_text(json.dumps({"finding_id": finding_id, "commit": "a" * 40, "status": "submitted", "external_action": "recorded_only", "reference": "SEC-123", "history": []}), encoding="utf-8")
            reports = disclosure_index(root)
            self.assertEqual(len(reports), 1)
            self.assertTrue(reports[0]["drafts_ready"])
            rendered = reports_page(reports, reports[0]["key"], "ghsa")
            self.assertIn("사람이 제출함", rendered)
            self.assertIn("SEC-123", rendered)
            self.assertIn("사람이 제출", rendered)
            self.assertIn("Private &lt;candidate&gt;", rendered)
            self.assertNotIn("Private <candidate>", rendered)
            self.assertIn('href="/reports"', rendered)


if __name__ == "__main__":
    unittest.main()
