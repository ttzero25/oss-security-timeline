import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from oss_timeline.core import Collection, Store
from oss_timeline.research import BuildEnvironmentAgent, DisclosureAgent, DuplicateReviewAgent, LimitedPocAgent, PocValidatorAgent, RepositoryProfilerAgent, ResearchOrchestrator, SemanticAnalysisAgent, SourceScanAgent, audit, claim_template, mark_submission_status, prepare_poc, submission_status


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

    def test_python_scan_models_named_public_api_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "decoder.py").write_text('''import pickle\n\nclass Decoder:\n    def parse(self, params):\n        return self._decode(params["payload"])\n\n    def _decode(self, value):\n        return pickle.loads(value)\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/public-api", "7" * 40)
            linked = [item for item in findings if item.function == "parse"]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0].kind, "unsafe_deserialization")
            self.assertEqual(linked[0].entry_kind, "modeled_public_api")

    def test_python_scan_tracks_public_input_through_augmented_sql(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "store.py").write_text('''class Store:\n    def list(self, limit=None):\n        query = "SELECT * FROM records"\n        if limit:\n            query += f" LIMIT {limit}"\n        self.db.execute(query)\n''', encoding="utf-8")
            (root / "safe_store.py").write_text('''class Store:\n    def find(self, data):\n        values = [item[0] for item in data]\n        placeholders = ",".join("?" * len(values))\n        self.db.execute(f"SELECT * FROM records WHERE id IN ({placeholders})", values)\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/public-sql", "9" * 40)
            linked = [item for item in findings if item.function == "list"]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0].kind, "sql_injection")
            self.assertEqual(linked[0].entry_kind, "modeled_public_api")
            self.assertFalse(any(item.path == "safe_store.py" for item in findings))

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

    def test_javascript_scan_models_exported_default_destructured_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tool.ts").write_text('''import { execSync } from "node:child_process";\nexport default async function run({\n  command,\n}: {\n  command: string;\n}): Promise<void> {\n  execSync(`tool ${command}`);\n}\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/typescript-tool", "5" * 40)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].kind, "command_injection")
            self.assertEqual(findings[0].function, "run")

    def test_go_scan_traces_local_package_function(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "go.mod").write_text("module example.test/demo\n\ngo 1.22\n", encoding="utf-8")
            (root / "main.go").write_text('''package main\nimport (\n    "net/http"\n    "example.test/demo/worker"\n)\nfunc handler(w http.ResponseWriter, r *http.Request) {\n    command := r.FormValue("command")\n    worker.Execute(command)\n}\n''', encoding="utf-8")
            worker = root / "worker"
            worker.mkdir()
            (worker / "worker.go").write_text('''package worker\nimport "os/exec"\nfunc Execute(value string) {\n    exec.Command("sh", "-c", value).Run()\n}\n''', encoding="utf-8")
            findings, coverage = SourceScanAgent().run(root, "fixture/go-multihop", "3" * 40)
            linked = [item for item in findings if item.function == "handler" and item.sink_path == "worker/worker.go"]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0].kind, "command_injection")
            self.assertEqual([step["role"] for step in linked[0].trace], ["source", "call", "sink"])
            self.assertEqual(coverage["go_multihop_files"], 2)

    def test_go_scan_does_not_treat_argv_exec_as_shell(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.go").write_text('''package main\nimport ("net/http"; "os/exec")\nfunc handler(w http.ResponseWriter, r *http.Request) {\n    name := r.FormValue("name")\n    exec.Command("printf", "%s", name).Run()\n}\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/go-safe", "4" * 40)
            self.assertEqual(findings, [])

    def test_go_scan_models_rpc_request_parameters(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "rpc.go").write_text('''package main\nimport "os/exec"\ntype RunRequest struct { Command string }\nfunc execute(command string) {\n    exec.Command("sh", "-c", command).Run()\n}\nfunc Run(opts *RunRequest) {\n    execute(opts.Command)\n}\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/go-rpc", "8" * 40)
            linked = [item for item in findings if item.function == "Run"]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0].kind, "command_injection")
            self.assertEqual(linked[0].entry_kind, "modeled_request")

    def test_go_scan_models_echo_query_param(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "handler.go").write_text('''package main\nimport "net/http"\nfunc Get(c Context) {\n    target := c.QueryParam("url")\n    http.Get(target)\n}\n''', encoding="utf-8")
            findings, _ = SourceScanAgent().run(root, "fixture/go-echo", "a" * 40)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].kind, "possible_ssrf")

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

    def test_source_scan_prioritizes_recent_paths_before_file_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a_safe.py").write_text('def safe():\n    return "ok"\n', encoding="utf-8")
            (root / "z_changed.py").write_text('import os\ndef run(request):\n    command = request.args["command"]\n    return os.system(command)\n', encoding="utf-8")
            findings, coverage = SourceScanAgent().run(root, "fixture/priority", "6" * 40, max_files=1, priority_paths={"z_changed.py"})
            self.assertEqual({item.path for item in findings}, {"z_changed.py"})
            self.assertEqual(coverage["eligible_files"], 2)
            self.assertEqual(coverage["priority_files_scanned"], 1)
            self.assertEqual(coverage["files_skipped_by_limit"], 1)

    def test_audit_reuses_only_clean_same_commit_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            repo = self._checkout(folder)
            first = audit(repo, "fixture/cache", folder / "research", max_files=50)
            original = (repo / "synthetic_app.py").read_text()
            self.assertFalse(json.loads(first.read_text())["scan_cache"]["reused"])
            second = audit(repo, "fixture/cache", folder / "research", max_files=50)
            self.assertTrue(json.loads(second.read_text())["scan_cache"]["reused"])
            (repo / "synthetic_app.py").write_text((repo / "synthetic_app.py").read_text() + "\n# dirty\n", encoding="utf-8")
            third = audit(repo, "fixture/cache", folder / "research", max_files=50)
            self.assertFalse(json.loads(third.read_text())["scan_cache"]["reused"])
            self.assertFalse(json.loads(third.read_text())["scan_cache"]["cacheable"])
            (repo / "synthetic_app.py").write_text(original, encoding="utf-8")
            fourth = audit(repo, "fixture/cache", folder / "research", max_files=50)
            self.assertFalse(json.loads(fourth.read_text())["scan_cache"]["reused"])
            fifth = audit(repo, "fixture/cache", folder / "research", max_files=50)
            self.assertTrue(json.loads(fifth.read_text())["scan_cache"]["reused"])

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
            self.assertIn(evidence["mode"], {"limited_process", "macos_sandbox"})
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
            tampered = json.loads((poc_dir / "manifest.json").read_text())
            tampered["attack"] = ["sh", "-c", "id"]
            (poc_dir / "manifest.json").write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "실행 명령"):
                PocValidatorAgent().run(poc_dir / "manifest.json")

    def test_manual_submission_state_requires_order_and_reference(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            finding_id = "FIND-MANUAL00001"
            audit_file = folder / "audit.json"
            audit_file.write_text(json.dumps({"commit": "a" * 40, "hypotheses": [{"id": finding_id}]}), encoding="utf-8")
            report = folder / finding_id
            report.mkdir()
            (report / "GHSA_CANDIDATE.md").write_text("# draft", encoding="utf-8")
            (report / "CVE_REQUEST_BRIEF.md").write_text("# brief", encoding="utf-8")
            self.assertEqual(submission_status(audit_file, finding_id)["status"], "draft_ready")
            mark_submission_status(audit_file, finding_id, "reviewed", note="Reviewed locally")
            with self.assertRaisesRegex(ValueError, "외부 참조"):
                mark_submission_status(audit_file, finding_id, "submitted")
            state_file = mark_submission_status(audit_file, finding_id, "submitted", "https://github.com/example/demo/security/advisories/1")
            state = json.loads(state_file.read_text())
            self.assertEqual(state["status"], "submitted")
            self.assertEqual(state["external_action"], "recorded_only")
            self.assertEqual([item["to"] for item in state["history"]], ["reviewed", "submitted"])
            with self.assertRaisesRegex(ValueError, "상태 전환"):
                mark_submission_status(audit_file, finding_id, "reviewed")

    def test_javascript_limited_poc_runs_real_default_export_with_contrast(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            repo = folder / "repo"
            repo.mkdir()
            (repo / "tool.mjs").write_text('''import { execSync } from "node:child_process";\n\nexport default function run(command) {\n  return execSync(command);\n}\n''', encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "tool.mjs"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], check=True)
            audit_file = audit(repo, "fixture/javascript-poc", folder / "research")
            audit_data = json.loads(audit_file.read_text())
            ranked = SemanticAnalysisAgent().run(audit_data["hypotheses"], audit_data["profile"])
            finding = next(item for item in ranked if item["kind"] == "command_injection")
            self.assertTrue(finding["auto_reproduction_supported"])
            environment = BuildEnvironmentAgent().run(repo, finding)
            self.assertEqual(environment["runtime"], "javascript")
            manifest_file = LimitedPocAgent().run(audit_file, finding, environment)
            evidence = json.loads(PocValidatorAgent().run(manifest_file).read_text())
            self.assertEqual(evidence["mechanical_result"], "contrast_matched")
            self.assertEqual(evidence["proof_file"], "proof.mjs")
            self.assertFalse(evidence["control_observable"])

    def test_go_limited_poc_runs_single_file_handler_with_contrast(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            repo = folder / "repo"
            repo.mkdir()
            (repo / "handler.go").write_text('''package fixture\n\nimport (\n    "net/http"\n    "os/exec"\n)\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n    command := r.FormValue("command")\n    exec.Command("sh", "-c", command).Run()\n}\n''', encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "handler.go"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], check=True)
            audit_file = audit(repo, "fixture/go-poc", folder / "research")
            audit_data = json.loads(audit_file.read_text())
            ranked = SemanticAnalysisAgent().run(audit_data["hypotheses"], audit_data["profile"])
            finding = next(item for item in ranked if item["kind"] == "command_injection")
            self.assertTrue(finding["auto_reproduction_supported"])
            environment = BuildEnvironmentAgent().run(repo, finding)
            self.assertEqual(environment["runtime"], "go")
            manifest_file = LimitedPocAgent().run(audit_file, finding, environment)
            evidence = json.loads(PocValidatorAgent().run(manifest_file).read_text())
            self.assertEqual(evidence["mechanical_result"], "contrast_matched")
            self.assertFalse(evidence["control_observable"])

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

    def test_duplicate_review_scores_cwe_code_path_and_commit_reference(self):
        finding = {"kind": "command_injection", "function": "execute_job", "path": "service/runner.py", "source_path": "service/api.py", "sink_path": "service/runner.py", "commit": "abc123456789"}
        audit_data = {"public_context": {"status": "snapshot", "fresh": True, "snapshot_age_hours": 1, "known_advisories": [{"id": "GHSA-aaaa-bbbb-cccc", "ghsa": "GHSA-aaaa-bbbb-cccc", "cve": "CVE-2026-1000", "summary": "Shell command injection in runner execute_job", "sources": '["GitHub"]', "cwe_ids": ["CWE-78"], "packages": [{"ecosystem": "pip", "name": "fixture"}], "references": ["https://github.com/example/demo/commit/abc123456789"]}]}}
        review = DuplicateReviewAgent().run(audit_data, finding)
        self.assertEqual(review["status"], "possible_duplicate")
        self.assertEqual(review["classification"], "known_duplicate")
        self.assertEqual(review["matches"][0]["relation"], "known_duplicate")
        self.assertGreaterEqual(review["matches"][0]["score"], 6)

    def test_duplicate_review_rejects_stale_snapshot(self):
        review = DuplicateReviewAgent().run({"public_context": {"status": "snapshot", "fresh": False, "snapshot_age_hours": 200, "known_advisories": []}}, {"kind": "command_injection"})
        self.assertEqual(review["status"], "stale_public_context")

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
