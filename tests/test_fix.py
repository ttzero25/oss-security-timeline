import json
import tempfile
import unittest
from pathlib import Path

from oss_timeline.fix import changed_lines, collect_reference_diffs, referenced_commit


class FixComparisonTests(unittest.TestCase):
    def test_only_same_repo_advisory_commit_refs_are_accepted(self):
        sha = "a" * 40
        self.assertEqual(referenced_commit(f"https://github.com/example/demo/commit/{sha}", "example/demo"), sha)
        for url in (f"https://github.com/other/demo/commit/{sha}", f"https://evil.example/example/demo/commit/{sha}", "https://github.com/example/demo/commit/main"):
            self.assertIsNone(referenced_commit(url, "example/demo"))

    def test_changed_lines_show_only_removed_and_added_code(self):
        self.assertEqual(changed_lines("@@ -1 +1 @@\n-old()\n+new()\n context"), ("old()", "new()"))

    def test_collects_bounded_advisory_linked_diff(self):
        sha = "a" * 40

        class FakeClient:
            def github(self, path):
                self_path = f"/repos/example/demo/commits/{sha}"
                if path != self_path:
                    raise AssertionError(path)
                return {"files": [{"filename": "src/auth.py", "status": "modified", "patch": "@@ -1 +1 @@\n-skip_check()\n+validate()"}]}

        advisory = {"id": "GHSA-aaaa-bbbb-cccc", "references": [f"https://github.com/example/demo/commit/{sha}", f"https://github.com/other/demo/commit/{sha}"]}
        with tempfile.TemporaryDirectory() as temp:
            path = collect_reference_diffs(FakeClient(), "example/demo", [advisory], Path(temp))
            result = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(result["reference_count"], 1)
            self.assertEqual(result["comparisons"][0]["files"][0]["before"], "skip_check()")
            self.assertEqual(result["comparisons"][0]["files"][0]["after"], "validate()")


if __name__ == "__main__":
    unittest.main()
