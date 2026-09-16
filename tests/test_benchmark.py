import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from oss_timeline.benchmark import benchmark_passes, run_benchmark
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

    def test_default_corpus_records_known_false_positive(self):
        result = run_benchmark(Path("benchmarks/corpus.json"))
        self.assertEqual(result["metrics"]["total_cases"], 11)
        self.assertEqual(result["metrics"]["false_negative_cases"], 1)
        allowlist = next(case for case in result["cases"] if case["id"] == "python-allowlist-command")
        self.assertFalse(allowlist["passed"])
        self.assertIn("command_injection", allowlist["found_kinds"])
        method_dispatch = next(case for case in result["cases"] if case["id"] == "python-method-multihop")
        self.assertFalse(method_dispatch["passed"])
        self.assertEqual(method_dispatch["found_kinds"], [])

    def test_cli_threshold_can_fail_a_regression_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result.json"
            with redirect_stdout(io.StringIO()):
                code = main(["benchmark", "--corpus", "benchmarks/corpus.json", "--output", str(output), "--min-recall", "1", "--max-false-positive-cases", "0"])
            self.assertEqual(code, 2)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
