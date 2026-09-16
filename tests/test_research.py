import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from oss_timeline.core import Collection, Store
from oss_timeline.research import DisclosureAgent, PocValidatorAgent, ResearchOrchestrator, SourceScanAgent, audit, claim_template, prepare_poc


FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_app.py"
NATIVE_FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_native.c"


class ResearchTests(unittest.TestCase):
    def _checkout(self, folder: Path) -> Path:
        repo = folder / "repo"
        repo.mkdir()
        shutil.copyfile(FIXTURE, repo / "synthetic_app.py")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "synthetic_app.py"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], check=True)
        return repo

    def test_source_scan_keeps_pattern_as_hypothesis(self):
        findings, coverage = SourceScanAgent().run(FIXTURE.parent, "fixture/synthetic", "a" * 40)
        python_findings = [x for x in findings if x.path.endswith("synthetic_app.py")]
        self.assertEqual(len(python_findings), 2)
        self.assertTrue(all(x.kind == "command_injection" and x.status == "hypothesis" for x in python_findings))
        self.assertTrue(coverage["files_inspected"] >= 1)

    def test_source_scan_supports_conservative_c_patterns(self):
        findings, coverage = SourceScanAgent().run(NATIVE_FIXTURE.parent, "fixture/native", "b" * 40)
        native = [x for x in findings if x.path.endswith("synthetic_native.c")]
        self.assertEqual({x.kind for x in native}, {"command_injection", "format_string"})
        self.assertEqual(len(native), 2)
        self.assertIn("c/c++", coverage["languages"])

    def test_poc_controls_and_disclosure_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            repo = self._checkout(folder)
            audit_file = audit(repo, "fixture/synthetic", folder / "research")
            data = json.loads(audit_file.read_text())
            self.assertEqual(len(data["hypotheses"]), 2)
            finding = next(x for x in data["hypotheses"] if x["function"] == "handle")
            poc_dir = prepare_poc(audit_file, finding["id"])
            manifest = json.loads((poc_dir / "manifest.json").read_text())
            marker = manifest["observable"]["value"]
            proof = f'''import importlib.util
import os
import sys
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("fixture", os.path.join(os.environ["OSS_POC_REPO"], "synthetic_app.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
payload = "printf {marker}" if sys.argv[1] == "attack" else "printf benign"
result = module.handle(SimpleNamespace(args={{"command": payload}}))
print(result.stdout)
'''
            (poc_dir / "proof.py").write_text(proof)
            evidence_file = PocValidatorAgent().run(poc_dir / "manifest.json")
            evidence = json.loads(evidence_file.read_text())
            self.assertEqual(evidence["mechanical_result"], "contrast_matched")
            self.assertEqual(evidence["mode"], "limited_process")
            self.assertFalse(evidence["control_observable"])
            claim = claim_template(finding)
            with self.assertRaises(ValueError):
                DisclosureAgent().run(audit_file, finding["id"], poc_dir / "claim.example.json", evidence_file)
            claim.update({"title": "Synthetic command injection", "summary": "An external command value reaches a shell in the local fixture.", "cwe": "CWE-78", "impact": "A crafted input executes a harmless local command in this fixture.", "root_cause": "Untrusted command text is passed to a shell-enabled subprocess.", "default_configuration_evidence": "The function always uses shell=True.", "upstream_guard_analysis": "The fixture has no validation before the call.", "negative_control_explanation": "A benign value does not print the proof marker.", "remediation": "Pass a fixed executable and validated arguments without a shell.", "reproduction_steps": ["Run the supplied offline harness", "Compare the benign and attack outputs"]})
            claim["affected"] = {"ecosystem": "pip", "package": "synthetic-fixture", "versions": "fixture commit only", "patched_version": "Not yet available"}
            claim["source"]["attacker_control"] = "The command field"
            claim["sink"]["effect"] = "Executes the command through a shell"
            claim["known_advisory_checks"] = {"github": "Synthetic local fixture with no published advisory", "osv": "Synthetic local fixture with no package entry", "vendor_or_web": "Synthetic fixture has no vendor", "duplicate_analysis": "The single fixture code path is unique"}
            claim_file = poc_dir / "claim.json"
            claim_file.write_text(json.dumps(claim))
            ghsa, cve = DisclosureAgent().run(audit_file, finding["id"], claim_file, evidence_file)
            self.assertIn("Proof of concept", ghsa.read_text())
            self.assertIn("CVE ID: not assigned", cve.read_text())
            claim["sink"]["line"] += 1
            claim_file.write_text(json.dumps(claim))
            with self.assertRaisesRegex(ValueError, "인용 위치"):
                DisclosureAgent().run(audit_file, finding["id"], claim_file, evidence_file)
            claim["sink"]["line"] -= 1
            claim_file.write_text(json.dumps(claim))
            (poc_dir / "proof.py").write_text(proof + "\n# changed after verification\n")
            with self.assertRaisesRegex(ValueError, "변경"):
                DisclosureAgent().run(audit_file, finding["id"], claim_file, evidence_file)

    def test_audit_includes_saved_public_advisories_as_context(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            repo = self._checkout(folder)
            database = folder / "timeline.sqlite3"
            store = Store(database)
            collection = Collection("fixture/synthetic", advisories=[{"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": None, "published_at": "2025-01-01T00:00:00Z", "modified_at": None, "summary": "Old issue", "severity": "medium", "cvss": None, "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "source": "GitHub reviewed", "affected": []}])
            store.save(collection)
            store.db.close()
            audit_file = audit(repo, "fixture/synthetic", folder / "research", timeline_db=database)
            context = json.loads(audit_file.read_text())["public_context"]
            self.assertEqual(context["status"], "snapshot")
            self.assertEqual(context["known_advisories"][0]["id"], "GHSA-aaaa-bbbb-cccc")

    def test_orchestrator_generates_bounded_poc_and_manual_only_drafts(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            repo = self._checkout(folder)
            database = folder / "timeline.sqlite3"
            store = Store(database)
            store.save(Collection("fixture/synthetic"))
            store.db.close()
            audit_file = audit(repo, "fixture/synthetic", folder / "research", timeline_db=database)
            output = ResearchOrchestrator().run(audit_file, max_candidates=1)
            result = json.loads(output.read_text())
            self.assertEqual(result["external_submission"], "disabled_manual_only")
            self.assertEqual(result["results"][0]["status"], "draft_ready")
            self.assertEqual(result["results"][0]["stages"]["disclosure"]["submission"], "manual_only")
            destination = audit_file.parent / result["results"][0]["finding_id"]
            self.assertTrue((destination / "evidence.json").is_file())
            self.assertTrue((destination / "GHSA_CANDIDATE.md").is_file())
            self.assertTrue((destination / "CVE_REQUEST_BRIEF.md").is_file())

    def test_orchestrator_stops_draft_for_possible_duplicate(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            repo = self._checkout(folder)
            database = folder / "timeline.sqlite3"
            store = Store(database)
            collection = Collection("fixture/synthetic", advisories=[{"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": None, "published_at": "2026-01-01T00:00:00Z", "modified_at": None, "summary": "Command injection in request handling", "severity": "high", "cvss": None, "url": None, "source": "GitHub", "affected": []}])
            store.save(collection)
            store.db.close()
            audit_file = audit(repo, "fixture/synthetic", folder / "research", timeline_db=database)
            output = ResearchOrchestrator().run(audit_file, max_candidates=1)
            result = json.loads(output.read_text())["results"][0]
            self.assertEqual(result["status"], "duplicate_review_required")
            self.assertEqual(result["stages"]["duplicate_review"]["status"], "possible_duplicate")
            self.assertFalse((audit_file.parent / result["finding_id"] / "GHSA_CANDIDATE.md").exists())


if __name__ == "__main__":
    unittest.main()
