import json
import tempfile
import unittest
from pathlib import Path

from oss_timeline.aggregate import AggregateStore, build_bundle, validate_bundle
from oss_timeline.core import Collection, Store


def populate(root: Path, advisory_id: str, ghsa: str | None, instance_name: str) -> dict:
    database = root / "timeline.sqlite3"
    research = root / "research"
    commit = "a" * 40
    finding_id = "FIND-123456789ABC"
    store = Store(database)
    collection = Collection("example/demo", packages=[("npm", "demo", "package.json")])
    collection.advisories = [{
        "id": advisory_id, "ghsa": ghsa, "cve": "CVE-2026-1234", "published_at": "2026-01-01T00:00:00Z",
        "modified_at": None, "summary": "Issue", "severity": "high", "cvss": None, "cwe_ids": [], "cwe_names": {},
        "url": None, "source": "GitHub", "references": [], "affected": [{"ecosystem": "npm", "name": "demo", "range": "<2", "patched": "2"}],
    }]
    collection.events = [{"id": "commit:abc", "kind": "commit", "at": "2026-01-02T00:00:00Z", "title": "Fix", "url": None}]
    store.save(collection)
    audit = {"repo": "example/demo", "commit": commit, "generated_at": "2026-01-03T00:00:00Z", "coverage": {}, "profile": {}, "hypotheses": [{"id": finding_id, "tracking_id": "TRACK-STABLE", "kind": "command_injection", "path": "/private/local/source.py", "source_line": 1, "sink_line": 2}]}
    orchestration = {"repo": "example/demo", "commit": commit, "generated_at": "2026-01-03T00:01:00Z", "execution_mode": "limited_process", "results": [{"finding_id": finding_id, "status": "draft_ready", "stages": {"isolated_contrast": {"status": "contrast_matched", "evidence": "/private/local/evidence.json"}}}]}
    folder = research / "example_demo" / commit
    folder.mkdir(parents=True)
    (folder / "audit.json").write_text(json.dumps(audit), encoding="utf-8")
    orchestration_path = folder / "orchestration.json"
    orchestration_path.write_text(json.dumps(orchestration), encoding="utf-8")
    store.save_research(audit, orchestration, orchestration_path)
    store.db.close()
    instance = root / "instance-id"
    instance.write_text(instance_name, encoding="utf-8")
    return build_bundle(database, research, instance)


class AggregateTests(unittest.TestCase):
    def test_bundle_excludes_paths_source_and_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = populate(Path(temp), "GHSA-aaaa-bbbb-cccc", "GHSA-aaaa-bbbb-cccc", "instance-alpha")
            validate_bundle(bundle)
            encoded = json.dumps(bundle)
            self.assertNotIn("/private/local", encoded)
            self.assertNotIn("command_injection", encoded)
            self.assertEqual(len(bundle["candidates"]), 1)
            self.assertEqual(len(bundle["contrasts"]), 1)

    def test_store_merges_two_instances_and_advisory_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = populate(root / "one", "GHSA-aaaa-bbbb-cccc", "GHSA-aaaa-bbbb-cccc", "instance-alpha")
            second = populate(root / "two", "CVE-2026-1234", None, "instance-bravo")
            aggregate = AggregateStore(root / "aggregate.sqlite3")
            self.assertTrue(aggregate.ingest(first)["accepted"])
            self.assertFalse(aggregate.ingest(first)["accepted"])
            result = aggregate.ingest(second)
            counts = result["stats"]["counts"]
            aggregate.close()
            self.assertEqual(counts["contributors"], 2)
            self.assertEqual(counts["bundles"], 2)
            self.assertEqual(counts["repositories"], 1)
            self.assertEqual(counts["packages"], 1)
            self.assertEqual(counts["advisories"], 1)
            self.assertEqual(counts["events"], 1)
            self.assertEqual(counts["research_runs"], 1)
            self.assertEqual(counts["candidates"], 1)
            self.assertEqual(counts["contrasts"], 1)

    def test_bundle_integrity_rejects_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = populate(Path(temp), "GHSA-aaaa-bbbb-cccc", "GHSA-aaaa-bbbb-cccc", "instance-alpha")
            bundle["repositories"][0]["name"] = "changed/repository"
            with self.assertRaisesRegex(ValueError, "무결성"):
                validate_bundle(bundle)

    def test_bundle_rejects_unexpected_sensitive_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = populate(Path(temp), "GHSA-aaaa-bbbb-cccc", "GHSA-aaaa-bbbb-cccc", "instance-alpha")
            bundle["candidates"][0]["source_path"] = "/private/local/source.py"
            with self.assertRaisesRegex(ValueError, "정의되지 않은 필드"):
                validate_bundle(bundle)

    def test_fixture_repository_is_not_exported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "timeline.sqlite3"
            store = Store(database)
            store.save(Collection("fixture/web-self-test", packages=[("pip", "fixture", "pyproject.toml")]))
            store.db.close()
            bundle = build_bundle(database, root / "research", root / "instance-id")
            self.assertEqual(bundle["repositories"], [])
            self.assertEqual(bundle["packages"], [])


if __name__ == "__main__":
    unittest.main()
