import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from oss_timeline.benchmark import benchmark_passes, run_benchmark, run_upstream_benchmark
from oss_timeline.cli import main


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_measures_vulnerable_and_clean_cases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            vulnerable = root / "vulnerable"
            clean = root / "clean"
            vulnerable.mkdir()
            clean.mkdir()
            (vulnerable / "app.py").write_text('import subprocess\n\ndef handle(request):\n    value = request.args["value"]\n    return subprocess.run(value, shell=True)\n', encoding="utf-8")
            (clean / "app.py").write_text('import subprocess\n\ndef handle(request):\n    value = request.args["value"]\n    return subprocess.run(["printf", "%s", value], shell=False)\n', encoding="utf-8")
            manifest = root / "corpus.json"
            manifest.write_text(json.dumps({"schema_version": 1, "name": "fixture", "version": "1", "cases": [{"id": "vulnerable", "path": "vulnerable", "expectation": "vulnerable", "expected_kinds": ["command_injection"]}, {"id": "clean", "path": "clean", "expectation": "clean", "expected_kinds": []}]}), encoding="utf-8")
            output = root / "result.json"
            result = run_benchmark(manifest, output)
            self.assertEqual(result["metrics"]["true_positive_cases"], 1)
            self.assertEqual(result["metrics"]["true_negative_cases"], 1)
            self.assertEqual(result["metrics"]["recall_at_case_limit"], 1.0)
            self.assertTrue(benchmark_passes(result, 1.0, 0))
            self.assertEqual(json.loads(output.read_text())["manifest_sha256"], result["manifest_sha256"])

    def test_default_corpus_passes_after_known_semantic_fixes(self):
        result = run_benchmark(Path("benchmarks/corpus.json"))
        self.assertEqual(result["metrics"]["total_cases"], 57)
        self.assertEqual(result["metrics"]["false_negative_cases"], 0)
        self.assertEqual(result["metrics"]["false_positive_cases"], 0)
        allowlist = next(case for case in result["cases"] if case["id"] == "python-allowlist-command")
        self.assertTrue(allowlist["passed"])
        self.assertEqual(allowlist["found_kinds"], [])
        method_dispatch = next(case for case in result["cases"] if case["id"] == "python-method-multihop")
        self.assertTrue(method_dispatch["passed"])
        self.assertIn("command_injection", method_dispatch["found_kinds"])
        self.assertEqual(result["metrics"]["by_origin"]["historical"], {"cases": 12, "passed": 12, "pass_rate": 1.0})
        self.assertEqual(result["metrics"]["historical_pairs_passed"], 6)

    def test_cli_threshold_can_fail_a_regression_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = root / "conditional"
            case.mkdir()
            (case / "app.py").write_text('import subprocess\n\ndef handle(request):\n    action = request.args["action"]\n    command = "printf status" if action == "status" else "printf version"\n    return subprocess.run(command, shell=True)\n', encoding="utf-8")
            corpus = root / "corpus.json"
            corpus.write_text(json.dumps({"schema_version": 1, "cases": [{"id": "conditional", "path": "conditional", "expectation": "clean", "expected_kinds": []}]}), encoding="utf-8")
            output = root / "result.json"
            with redirect_stdout(io.StringIO()):
                code = main(["benchmark", "--corpus", str(corpus), "--output", str(output), "--max-false-positive-cases", "0"])
            self.assertEqual(code, 2)
            self.assertTrue(output.is_file())

    def test_historical_case_requires_a_complete_consistent_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = root / "case"
            case.mkdir()
            (case / "app.py").write_text("def safe(): return True\n", encoding="utf-8")
            provenance = {"advisory": "GHSA-5w57-2ccq-8w95", "repository": "owner/repo", "ref": "a" * 40, "source_path": "app.py", "snapshot_type": "focused_excerpt", "url": "https://github.com/owner/repo/blob/" + "a" * 40 + "/app.py"}
            manifest = root / "corpus.json"
            manifest.write_text(json.dumps({"schema_version": 1, "cases": [{"id": "only-fixed", "path": "case", "origin": "historical", "pair_id": "CVE-2099-1", "expectation": "clean", "expected_kinds": [], "provenance": provenance}]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "정확히 하나씩"):
                run_benchmark(manifest)

    def test_upstream_benchmark_scans_full_checkout_but_scores_source_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            vulnerable = root / "vulnerable"
            fixed = root / "fixed"
            vulnerable.mkdir()
            fixed.mkdir()
            unsafe = 'import subprocess\ndef run(request):\n    value = request.args["value"]\n    return subprocess.run(value, shell=True)\n'
            safe = 'import subprocess\ndef run(request):\n    value = request.args["value"]\n    return subprocess.run(["printf", "%s", value])\n\ndef unrelated(request):\n    other = request.args["other"]\n    return subprocess.run(other, shell=True)\n'
            (vulnerable / "app.py").write_text(unsafe, encoding="utf-8")
            (fixed / "app.py").write_text(safe, encoding="utf-8")
            (fixed / "unrelated.py").write_text(unsafe, encoding="utf-8")
            vuln_sha, fixed_sha = "a" * 40, "b" * 40
            common = {"advisory": "GHSA-5w57-2ccq-8w95", "repository": "owner/repo", "source_path": "app.py", "focus_sink_contains": "subprocess.run(value", "snapshot_type": "focused_excerpt"}
            cases = [
                {"id": "real-vulnerable", "path": "vulnerable", "origin": "historical", "pair_id": "CVE-2099-1", "expectation": "vulnerable", "expected_kinds": ["command_injection"], "provenance": {**common, "ref": vuln_sha, "url": f"https://github.com/owner/repo/blob/{vuln_sha}/app.py"}},
                {"id": "real-fixed", "path": "fixed", "origin": "historical", "pair_id": "CVE-2099-1", "expectation": "clean", "expected_kinds": [], "provenance": {**common, "ref": fixed_sha, "url": f"https://github.com/owner/repo/blob/{fixed_sha}/app.py"}},
            ]
            manifest = root / "corpus.json"
            manifest.write_text(json.dumps({"schema_version": 1, "version": "fixture", "cases": cases}), encoding="utf-8")
            output = root / "upstream.json"
            result = run_upstream_benchmark(manifest, output, checkout_roots={("owner/repo", vuln_sha): vulnerable, ("owner/repo", fixed_sha): fixed})
            self.assertEqual(result["metrics"]["pairs_passed"], 1)
            self.assertEqual(result["metrics"]["pair_pass_rate"], 1.0)
            self.assertEqual(result["cases"][1]["found_kinds"], [])
            self.assertEqual(result["cases"][1]["focus_sink_contains"], "subprocess.run(value")
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
