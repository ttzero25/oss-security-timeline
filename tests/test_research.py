import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from oss_timeline.core import Collection, Store
from oss_timeline.research import DisclosureAgent, PocValidatorAgent, RepositoryProfilerAgent, ResearchOrchestrator, SourceScanAgent, audit, claim_template, prepare_poc


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

    def test_python_scan_traces_one_same_module_helper_hop(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text('''import subprocess\n\nclass App:\n    def post(self, path):\n        return lambda fn: fn\napp = App()\n\ndef execute(value):\n    return subprocess.run(value, shell=True)\n\n@app.post("/run")\ndef route(command):\n    return execute(command)\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/interprocedural", "c" * 40)
            linked = [item for item in findings if item.function == "route" and item.source_line != item.sink_line]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0].kind, "command_injection")

    def test_python_scan_traces_multiple_modules_and_records_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text('''from service import forward\n\nclass App:\n    def post(self, path):\n        return lambda fn: fn\napp = App()\n\n@app.post("/run")\ndef route(command):\n    return forward(command)\n''', encoding="utf-8")
            (root / "service.py").write_text('''from helpers import execute\n\ndef forward(value):\n    return execute(value)\n''', encoding="utf-8")
            (root / "helpers.py").write_text('''import subprocess\n\ndef execute(value):\n    return subprocess.run(value, shell=True)\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/multihop", "d" * 40)
            linked = [item for item in findings if item.function == "route" and item.sink_path == "helpers.py"]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0].source_path, "app.py")
            self.assertEqual(linked[0].entry_kind, "http_route")
            self.assertGreaterEqual(len(linked[0].trace), 4)
            self.assertEqual([step["role"] for step in linked[0].trace][0], "source")
            self.assertEqual([step["role"] for step in linked[0].trace][-1], "sink")

    def test_python_scan_traces_imported_instance_method(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text('''from worker import Worker\n\nclass App:\n    def post(self, path):\n        return lambda fn: fn\napp = App()\nworker = Worker()\n\n@app.post("/run")\ndef route(command):\n    return worker.execute(command)\n''', encoding="utf-8")
            (root / "worker.py").write_text('''import subprocess\n\nclass Worker:\n    def execute(self, value):\n        return subprocess.run(value, shell=True)\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/method", "e" * 40)
            linked = [item for item in findings if item.function == "route" and item.sink_path == "worker.py"]
            self.assertEqual(len(linked), 1)
            self.assertTrue(any(step.get("callee") == "worker:Worker.execute" for step in linked[0].trace))

    def test_python_scan_treats_immutable_literal_allowlist_as_sanitizer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "safe.py").write_text('''import subprocess\nALLOWED = {"status": "printf status"}\n\ndef handle(request):\n    action = request.args["action"]\n    command = ALLOWED[action]\n    return subprocess.run(command, shell=True)\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/allowlist", "f" * 40)
            self.assertEqual(findings, [])

    def test_python_scan_does_not_trust_mutated_allowlist(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "unsafe.py").write_text('''import subprocess\nALLOWED = {"status": "printf status"}\n\ndef handle(request):\n    action = request.args["action"]\n    ALLOWED["dynamic"] = request.args["command"]\n    command = ALLOWED[action]\n    return subprocess.run(command, shell=True)\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/mutated", "0" * 40)
            self.assertTrue(any(item.kind == "command_injection" for item in findings))

    def test_javascript_scan_traces_imported_esm_functions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.js").write_text('''import { forward } from "./service.js";\nexport function route(req) {\n  const command = req.body.command;\n  return forward(command);\n}\n''', encoding="utf-8")
            (root / "service.js").write_text('''import { execute } from "./worker.js";\nexport function forward(value) {\n  return execute(value);\n}\n''', encoding="utf-8")
            (root / "worker.js").write_text('''import { exec } from "child_process";\nexport function execute(command) {\n  return exec(command);\n}\n''', encoding="utf-8")
            findings, coverage = SourceScanAgent().run(root, "fixture/javascript-multihop", "1" * 40)
            linked = [item for item in findings if item.function == "route" and item.sink_path == "worker.js"]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0].kind, "command_injection")
            self.assertEqual([step["role"] for step in linked[0].trace], ["source", "call", "call", "sink"])
            self.assertEqual(coverage["javascript_multihop_files"], 3)

    def test_javascript_scan_keeps_function_scopes_isolated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "safe.js").write_text('''function read(req) {\n  const value = req.body.value;\n  return value;\n}\nfunction fixed() {\n  return eval("2 + 2");\n}\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/javascript-scope", "2" * 40)
            self.assertEqual(findings, [])

    def test_repository_profile_records_packages_languages_and_entrypoints(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copyfile(FIXTURE, root / "app.py")
            (root / "pyproject.toml").write_text('[project]\nname="fixture"\ndependencies=["requests>=2", "flask>=3"]\n', encoding="utf-8")
            (root / "poetry.lock").write_text("", encoding="utf-8")
            (root / "worker.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
            profile = RepositoryProfilerAgent().run(root)
            self.assertEqual(profile["languages"]["python"], 1)
            self.assertEqual(profile["languages"]["go"], 1)
            self.assertEqual(profile["manifests"], ["pyproject.toml"])
            self.assertEqual(profile["lockfiles"], ["poetry.lock"])
            self.assertEqual(profile["dependency_count"], 2)
            self.assertEqual(profile["dependencies"][0]["name"], "requests")
            self.assertIn("Flask", profile["frameworks"])
            self.assertEqual(profile["project_kind"], "service")
            self.assertTrue({item["kind"] for item in profile["entrypoints"]} >= {"http", "cli"})

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
            output = ResearchOrchestrator().run(audit_file, max_candidates=1, timeline_db=database)
            result = json.loads(output.read_text())
            self.assertEqual(result["external_submission"], "disabled_manual_only")
            self.assertEqual(result["results"][0]["status"], "draft_ready")
            self.assertEqual(result["results"][0]["stages"]["disclosure"]["submission"], "manual_only")
            self.assertEqual(result["results"][0]["stages"]["reachability_gate"]["status"], "pass")
            self.assertIn(result["results"][0]["stages"]["evidence_gate"]["verdict"], {"CONFIRMED", "CONFIRMED_LOW"})
            self.assertEqual(result["results"][0]["stages"]["evidence_gate"]["criteria"]["C5_no_known_duplicate"], "PASS")
            destination = audit_file.parent / result["results"][0]["finding_id"]
            self.assertTrue((destination / "evidence.json").is_file())
            self.assertTrue((destination / "GHSA_CANDIDATE.md").is_file())
            self.assertTrue((destination / "CVE_REQUEST_BRIEF.md").is_file())
            self.assertIn("## Evidence gate", (destination / "GHSA_CANDIDATE.md").read_text())
            store = Store(database)
            timeline = store.report("fixture/synthetic")
            self.assertEqual(timeline["research_runs"][0]["status"], "draft_ready")
            self.assertTrue(any(item["kind"] == "research_verdict" for item in timeline["research_timeline"]))
            store.db.close()

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

    def test_orchestrator_reproduces_cross_module_route_trace(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            repo = folder / "repo"
            repo.mkdir()
            (repo / "app.py").write_text('''from service import forward\n\nclass App:\n    def post(self, path):\n        return lambda fn: fn\napp = App()\n\n@app.post("/run")\ndef route(command):\n    return forward(command)\n''', encoding="utf-8")
            (repo / "service.py").write_text('''from helpers import execute\n\ndef forward(value):\n    return execute(value)\n''', encoding="utf-8")
            (repo / "helpers.py").write_text('''import subprocess\n\ndef execute(value):\n    return subprocess.run(value, shell=True, capture_output=True, text=True)\n''', encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], check=True)
            database = folder / "timeline.sqlite3"
            store = Store(database)
            store.save(Collection("fixture/multihop"))
            store.db.close()
            audit_file = audit(repo, "fixture/multihop", folder / "research", timeline_db=database)
            output = ResearchOrchestrator().run(audit_file, max_candidates=1, timeline_db=database)
            result = json.loads(output.read_text())["results"][0]
            self.assertEqual(result["status"], "draft_ready")
            self.assertEqual(result["stages"]["evidence_gate"]["verdict"], "CONFIRMED")
            self.assertGreaterEqual(len(result["stages"]["semantic_analysis"]["trace"]), 4)
            store = Store(database)
            tracked = store.report("fixture/multihop")["research_findings"][0]
            store.db.close()
            self.assertEqual(tracked["source_path"], "app.py")
            self.assertEqual(tracked["sink_path"], "helpers.py")
            self.assertGreaterEqual(len(tracked["trace"]), 4)


if __name__ == "__main__":
    unittest.main()
