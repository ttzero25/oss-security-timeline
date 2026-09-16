from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .core import repo_name


IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "vendor", "__pycache__"}
JS_SOURCE = re.compile(r"\b(?:req|request)\.(?:query|body|params|headers)(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])?", re.I)
JS_SINKS = [
    ("command_injection", re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s*\(")),
    ("code_execution", re.compile(r"\beval\s*\(")),
]
C_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}
C_RETURN_SOURCE = re.compile(r"\b(?:getenv|getopt|getopt_long)\s*\(|\bargv\s*\[")
C_BUFFER_SOURCE = re.compile(r"\b(?:recv|recvfrom|read|fgets|gets|scanf|sscanf)\s*\(")
C_SINKS = [
    ("command_injection", re.compile(r"\b(?:system|popen|execl|execlp|execv|execvp)\s*\(([^;]*)")),
    ("format_string", re.compile(r"\b(?:printf|syslog)\s*\(([^;]*)")),
    ("unsafe_copy", re.compile(r"\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(([^;]*)")),
]


@dataclass
class Hypothesis:
    id: str
    repo: str
    commit: str
    kind: str
    path: str
    source_line: int
    sink_line: int
    source_code: str
    sink_code: str
    function: str
    status: str = "hypothesis"


def _qualified(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _qualified(node.value) + "." + node.attr
    return ""


def _request_source(node: ast.AST) -> bool:
    for child in ast.walk(node):
        qualified = _qualified(child)
        if qualified.startswith(("request.args", "request.form", "request.values", "request.json", "request.GET", "request.POST", "sys.argv")) or qualified == "request.get_json":
            return True
        if isinstance(child, ast.Call) and _qualified(child.func) == "input":
            return True
    return False


def _name_refs(node: ast.AST) -> set[str]:
    return {x.id for x in ast.walk(node) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}


def _sink_kind(node: ast.Call) -> tuple[str, ast.AST] | None:
    name = _qualified(node.func)
    if not node.args:
        return None
    if name in {"os.system", "eval", "exec"}:
        return "code_execution" if name in {"eval", "exec"} else "command_injection", node.args[0]
    if name in {"subprocess.run", "subprocess.call", "subprocess.check_output", "subprocess.Popen", "subprocess.check_call"}:
        if any(x.arg == "shell" and isinstance(x.value, ast.Constant) and x.value.value is True for x in node.keywords):
            return "command_injection", node.args[0]
    if name in {"pickle.loads", "pickle.load"}:
        return "unsafe_deserialization", node.args[0]
    if name in {"requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"}:
        return "possible_ssrf", node.args[0]
    return None


def _hypothesis(repo: str, commit: str, kind: str, path: str, source_line: int, sink_line: int, source_code: str, sink_code: str, function: str) -> Hypothesis:
    identity = f"{repo}|{commit}|{kind}|{path}|{source_line}|{sink_line}"
    return Hypothesis("FIND-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper(), repo, commit, kind, path, source_line, sink_line, source_code.strip()[:400], sink_code.strip()[:400], function)


def _python_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    try:
        text = filename.read_text(encoding="utf-8")
        tree = ast.parse(text)
    except (OSError, UnicodeError, SyntaxError):
        return []
    lines = text.splitlines()
    output = []
    path = filename.relative_to(root).as_posix()
    for function in (x for x in ast.walk(tree) if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))):
        assigned: dict[str, tuple[int, str]] = {}
        http_route = any(isinstance(decorator, ast.Call) and _qualified(decorator.func).rsplit(".", 1)[-1] in {"route", "get", "post", "put", "patch", "delete"} and decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str) and decorator.args[0].value.startswith("/") for decorator in function.decorator_list)
        if http_route:
            for argument in function.args.posonlyargs + function.args.args + function.args.kwonlyargs:
                if argument.arg not in {"self", "cls", "request"}:
                    assigned[argument.arg] = (function.lineno, lines[function.lineno - 1])
        for node in ast.walk(function):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if value is None:
                    continue
                origin = None
                if _request_source(value):
                    origin = (value.lineno, lines[value.lineno - 1])
                else:
                    origin = next((assigned[name] for name in _name_refs(value) if name in assigned), None)
                if origin:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        for sub in ast.walk(target):
                            if isinstance(sub, ast.Name):
                                assigned[sub.id] = origin
            if isinstance(node, ast.Call):
                sink = _sink_kind(node)
                if not sink:
                    continue
                kind, argument = sink
                if _request_source(argument):
                    source = (argument.lineno, lines[argument.lineno - 1])
                else:
                    source = next((assigned[name] for name in _name_refs(argument) if name in assigned), None)
                if source:
                    output.append(_hypothesis(repo, commit, kind, path, source[0], node.lineno, source[1], lines[node.lineno - 1], function.name))
    return output


def _javascript_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    try:
        lines = filename.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    path = filename.relative_to(root).as_posix()
    output = []
    recent: list[tuple[int, str, str | None]] = []
    for number, line in enumerate(lines, 1):
        if JS_SOURCE.search(line):
            match = re.search(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", line)
            recent.append((number, line, match.group(1) if match else None))
        recent = [x for x in recent if number - x[0] <= 40]
        for kind, sink in JS_SINKS:
            if not sink.search(line):
                continue
            source = next((x for x in reversed(recent) if JS_SOURCE.search(line) or x[2] and re.search(r"\b" + re.escape(x[2]) + r"\b", line)), None)
            if source:
                output.append(_hypothesis(repo, commit, kind, path, source[0], number, source[1], line, "javascript_scope_unknown"))
    return output


def _c_source_variable(line: str) -> str | None:
    assignment = re.search(r"\b([A-Za-z_]\w*)\s*=\s*[^;]*(?:getenv|getopt|getopt_long)\s*\(|\b([A-Za-z_]\w*)\s*=\s*argv\s*\[", line)
    if assignment:
        return assignment.group(1) or assignment.group(2)
    call = re.search(r"\b(?:recv|recvfrom|read)\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)", line)
    if call:
        return call.group(1)
    call = re.search(r"\b(?:fgets|gets)\s*\(\s*([A-Za-z_]\w*)", line)
    if call:
        return call.group(1)
    scan = re.search(r"\b(?:scanf|sscanf)\s*\([^;]*,\s*&?([A-Za-z_]\w*)\s*\)", line)
    return scan.group(1) if scan else None


def _c_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    try:
        lines = filename.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    path = filename.relative_to(root).as_posix()
    recent: list[tuple[int, str, str]] = []
    output = []
    for number, line in enumerate(lines, 1):
        source_variable = _c_source_variable(line)
        if source_variable and (C_RETURN_SOURCE.search(line) or C_BUFFER_SOURCE.search(line)):
            recent.append((number, line, source_variable))
        recent = [item for item in recent if number - item[0] <= 60]
        for kind, pattern in C_SINKS:
            match = pattern.search(line)
            if not match:
                continue
            arguments = match.group(1)
            if kind == "format_string":
                first = arguments.split(",", 1)[0].strip()
                if first.startswith('"'):
                    continue
            source = next((item for item in reversed(recent) if re.search(r"\b" + re.escape(item[2]) + r"\b", arguments)), None)
            if source:
                between = "\n".join(lines[source[0] : number - 1])
                length_guard = re.search(r"\bstrlen\s*\(\s*" + re.escape(source[2]) + r"\s*\)\s*(?:>=|>)\s*sizeof\s*\(", between)
                if kind == "unsafe_copy" and length_guard and re.search(r"\b(?:return|goto)\b", between[length_guard.start() :]):
                    continue
                output.append(_hypothesis(repo, commit, kind, path, source[0], number, source[1], line, "c_scope_unknown"))
    return output


class SourceScanAgent:
    """Conservative entry-to-sink hypotheses, not vulnerability verdicts."""
    def run(self, root: Path, repo: str, commit: str, max_files: int = 20_000) -> tuple[list[Hypothesis], dict]:
        root = root.resolve()
        if not root.is_dir():
            raise ValueError("조사 대상 디렉터리가 없습니다")
        output: list[Hypothesis] = []
        inspected = 0
        truncated = False
        for filename in root.rglob("*"):
            try:
                if any(x in IGNORED_DIRS for x in filename.relative_to(root).parts) or not filename.is_file() or filename.is_symlink() or filename.stat().st_size > 500_000:
                    continue
            except OSError:
                continue
            if filename.suffix not in {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", *C_EXTENSIONS}:
                continue
            inspected += 1
            if inspected > max_files:
                truncated = True
                break
            if filename.suffix == ".py":
                output.extend(_python_hypotheses(filename, root, repo, commit))
            elif filename.suffix in C_EXTENSIONS:
                output.extend(_c_hypotheses(filename, root, repo, commit))
            else:
                output.extend(_javascript_hypotheses(filename, root, repo, commit))
        return sorted({x.id: x for x in output}.values(), key=lambda x: (x.path, x.sink_line)), {"files_inspected": min(inspected, max_files), "truncated": truncated, "languages": ["python", "javascript/typescript", "c/c++"]}


def checkout(target: str, checkouts: Path) -> tuple[Path, str]:
    repo = repo_name(target)
    checkouts.mkdir(parents=True, exist_ok=True)
    folder = checkouts / (repo.replace("/", "_") + "-" + secrets.token_hex(5))
    command = ["git", "clone", "--depth", "1", "--single-branch", "https://github.com/" + repo + ".git", str(folder)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError("공개 저장소 복제 실패: " + result.stderr[-500:])
    return folder, repo


def commit_hash(root: Path) -> str:
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError("조사 대상에서 커밋을 확인할 수 없습니다")
    return result.stdout.strip()


def _public_context(timeline_db: Path | None, repo: str) -> dict:
    if not timeline_db or not timeline_db.is_file():
        return {"status": "not_available", "known_advisories": []}
    try:
        connection = sqlite3.connect(f"file:{timeline_db.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT last_sync,coverage FROM repositories WHERE name=?", (repo,)).fetchone()
        known = [dict(x) for x in connection.execute("SELECT a.id,a.ghsa,a.cve,a.summary,a.published_at FROM advisories a JOIN advisory_repos ar ON ar.advisory_id=a.id WHERE ar.repo=? ORDER BY a.published_at DESC", (repo,))]
        connection.close()
        return {"status": "snapshot" if row else "repo_not_synced", "last_sync": row["last_sync"] if row else None, "coverage": json.loads(row["coverage"]) if row else {}, "known_advisories": known}
    except sqlite3.DatabaseError:
        return {"status": "unreadable", "known_advisories": []}


def audit(root: Path, repo: str, output_root: Path, max_files: int = 20_000, timeline_db: Path | None = None) -> Path:
    canonical = repo_name(repo)
    commit = commit_hash(root)
    findings, coverage = SourceScanAgent().run(root, canonical, commit, max_files)
    destination = output_root / canonical.replace("/", "_") / commit
    destination.mkdir(parents=True, exist_ok=True)
    summary = {"repo": canonical, "commit": commit, "checkout": str(root.resolve()), "coverage": coverage, "public_context": _public_context(timeline_db, canonical), "hypotheses": [asdict(x) for x in findings], "generated_at": datetime.now(timezone.utc).isoformat()}
    (destination / "audit.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return destination / "audit.json"


def load_hypothesis(audit_file: Path, finding_id: str) -> tuple[dict, dict]:
    data = json.loads(audit_file.read_text(encoding="utf-8"))
    item = next((x for x in data["hypotheses"] if x["id"] == finding_id), None)
    if item is None:
        raise ValueError("조사 결과에 없는 후보 ID입니다")
    return data, item


def prepare_poc(audit_file: Path, finding_id: str) -> Path:
    data, finding = load_hypothesis(audit_file, finding_id)
    destination = audit_file.parent / finding_id
    destination.mkdir(parents=True, exist_ok=True)
    marker = "OSS_PROOF_" + secrets.token_hex(8)
    manifest = {"finding_id": finding_id, "repo_path": data["checkout"], "commit": data["commit"], "image": "python:3.11-slim", "attack": ["python3", "proof.py", "attack"], "control": ["python3", "proof.py", "control"], "observable": {"type": "stdout_contains", "value": marker}, "timeout_seconds": 30}
    script = f'''"""Local verification harness for {finding_id}. Fill the real application call."""
import os
import sys

REPO = os.environ["OSS_POC_REPO"]
SCRATCH = os.environ["OSS_POC_SCRATCH"]
MARKER = {marker!r}

def drive(case: str) -> None:
    # TODO: import and call the real entry point from {finding["path"]}:{finding["sink_line"]}.
    # TODO: use an attacker-controlled input for "attack" and a benign input for "control".
    # TODO: print MARKER only when the actual unsafe effect is observed in SCRATCH.
    raise NotImplementedError("Connect the harness to the unmodified target code")

if __name__ == "__main__":
    drive(sys.argv[1])
'''
    proof = destination / "proof.py"
    if proof.exists():
        raise ValueError("이미 PoC 파일이 있습니다. 기존 작업을 보존합니다")
    proof.write_text(script, encoding="utf-8")
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    claim = claim_template(finding)
    claim["known_advisory_ids_to_review"] = [x["id"] for x in data.get("public_context", {}).get("known_advisories", [])]
    (destination / "claim.example.json").write_text(json.dumps(claim, ensure_ascii=False, indent=2), encoding="utf-8")
    return destination


def claim_template(finding: dict) -> dict:
    return {"finding_id": finding["id"], "title": "", "summary": "", "vulnerability_class": finding["kind"], "cwe": "", "cvss_vector": "", "affected": {"ecosystem": "", "package": "", "versions": "", "patched_version": "Not yet available"}, "source": {"file": finding["path"], "line": finding["source_line"], "attacker_control": "", "evidence": finding["source_code"]}, "sink": {"file": finding["path"], "line": finding["sink_line"], "effect": "", "evidence": finding["sink_code"]}, "default_configuration_evidence": "", "upstream_guard_analysis": "", "impact": "", "root_cause": "", "reproduction_steps": [], "negative_control_explanation": "", "known_advisory_checks": {"github": "", "osv": "", "vendor_or_web": "", "duplicate_analysis": ""}, "remediation": ""}


class PocValidatorAgent:
    def _run(self, command: list[str], manifest: dict, poc_dir: Path, scratch: Path, local: bool) -> dict:
        repo = Path(manifest["repo_path"]).resolve()
        if local:
            args = command
            env = {**os.environ, "OSS_POC_REPO": str(repo), "OSS_POC_SCRATCH": str(scratch)}
        else:
            image = manifest.get("image", "python:3.11-slim")
            if not re.fullmatch(r"[A-Za-z0-9_./:-]+", image):
                raise ValueError("컨테이너 이미지 이름이 유효하지 않습니다")
            args = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only", "--pids-limit=64", "--memory=256m", "--cpus=1", "--security-opt", "no-new-privileges", "-v", f"{repo}:/repo:ro", "-v", f"{poc_dir.resolve()}:/poc:ro", "-v", f"{scratch}:/scratch:rw", "-e", "OSS_POC_REPO=/repo", "-e", "OSS_POC_SCRATCH=/scratch", "-e", "TMPDIR=/scratch", "-e", "PYTHONDONTWRITEBYTECODE=1", "-w", "/poc", image, *command]
            env = os.environ.copy()
        try:
            result = subprocess.run(args, cwd=poc_dir if local else None, env=env, capture_output=True, text=True, timeout=min(int(manifest.get("timeout_seconds", 30)), 120))
            return {"returncode": result.returncode, "stdout": result.stdout[:4000], "stderr": result.stderr[:4000], "timed_out": False}
        except subprocess.TimeoutExpired as exc:
            return {"returncode": None, "stdout": str(exc.stdout or "")[:4000], "stderr": str(exc.stderr or "")[:4000], "timed_out": True}

    def run(self, manifest_file: Path, local: bool = False) -> Path:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        poc_dir = manifest_file.parent.resolve()
        repo = Path(manifest["repo_path"]).resolve()
        if not repo.is_dir() or commit_hash(repo) != manifest["commit"]:
            raise ValueError("PoC 대상 체크아웃의 커밋이 조사 시점과 다릅니다")
        marker = manifest.get("observable", {}).get("value")
        if not marker or not isinstance(marker, str) or len(marker) > 100:
            raise ValueError("명확한 관측 마커가 필요합니다")
        if not (poc_dir / "proof.py").is_file() or "TODO" in (poc_dir / "proof.py").read_text(encoding="utf-8"):
            raise ValueError("PoC의 실제 호출·대조군 TODO를 완성해야 합니다")
        with tempfile.TemporaryDirectory(prefix="oss-poc-") as temporary:
            control_scratch = Path(temporary) / "control"
            attack_scratch = Path(temporary) / "attack"
            control_scratch.mkdir()
            attack_scratch.mkdir()
            control = self._run(manifest["control"], manifest, poc_dir, control_scratch, local)
            attack = self._run(manifest["attack"], manifest, poc_dir, attack_scratch, local)
        control_match = marker in control["stdout"]
        attack_match = marker in attack["stdout"]
        confirmed = attack_match and not control_match and attack["returncode"] == 0 and control["returncode"] == 0 and not attack["timed_out"] and not control["timed_out"]
        evidence = {"finding_id": manifest["finding_id"], "repo_path": str(repo), "commit": manifest["commit"], "proof_sha256": hashlib.sha256((poc_dir / "proof.py").read_bytes()).hexdigest(), "manifest_sha256": hashlib.sha256(manifest_file.read_bytes()).hexdigest(), "mode": "local" if local else "offline_container", "control": control, "attack": attack, "control_observable": control_match, "attack_observable": attack_match, "mechanical_result": "contrast_matched" if confirmed else "not_confirmed", "validated_at": datetime.now(timezone.utc).isoformat(), "note": "기계적 관측 결과입니다. 코드 경로와 보안 영향은 별도로 검토해야 합니다."}
        output = poc_dir / "evidence.json"
        output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        return output


def _require_claim(claim: dict, finding: dict) -> None:
    if claim.get("finding_id") != finding["id"]:
        raise ValueError("주장 문서의 후보 ID가 일치하지 않습니다")
    required = ["title", "summary", "vulnerability_class", "cwe", "impact", "root_cause", "default_configuration_evidence", "upstream_guard_analysis", "negative_control_explanation", "remediation"]
    if any(not str(claim.get(x) or "").strip() for x in required):
        raise ValueError("주장 문서의 핵심 검증 근거가 비어 있습니다")
    if not claim.get("reproduction_steps"):
        raise ValueError("재현 단계가 필요합니다")
    for part in ("source", "sink"):
        if any(not claim.get(part, {}).get(key) for key in ("file", "line", "evidence")):
            raise ValueError(f"{part} 코드 근거가 필요합니다")
    if not claim.get("source", {}).get("attacker_control") or not claim.get("sink", {}).get("effect"):
        raise ValueError("공격자 입력 통제와 실제 결과를 기술해야 합니다")
    if any(not str(claim.get("known_advisory_checks", {}).get(x) or "").strip() for x in ("github", "osv", "vendor_or_web", "duplicate_analysis")):
        raise ValueError("기존 공개 사례와 중복 여부 조사 근거가 필요합니다")
    affected = claim.get("affected", {})
    if any(not str(affected.get(x) or "").strip() for x in ("ecosystem", "package", "versions")):
        raise ValueError("영향 패키지와 버전 범위가 필요합니다")


class DisclosureAgent:
    def run(self, audit_file: Path, finding_id: str, claim_file: Path, evidence_file: Path) -> tuple[Path, Path]:
        audit_data, finding = load_hypothesis(audit_file, finding_id)
        claim = json.loads(claim_file.read_text(encoding="utf-8"))
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
        if evidence.get("finding_id") != finding_id or evidence.get("commit") != audit_data["commit"] or evidence.get("mechanical_result") != "contrast_matched":
            raise ValueError("동일 커밋의 정상 대조군 대비 재현 성공 근거가 필요합니다")
        _require_claim(claim, finding)
        repo = audit_data["repo"]
        checkout_path = Path(audit_data["checkout"])
        if commit_hash(checkout_path) != audit_data["commit"]:
            raise ValueError("조사한 커밋이 변경됐습니다")
        poc_dir = claim_file.parent
        if evidence.get("proof_sha256") != hashlib.sha256((poc_dir / "proof.py").read_bytes()).hexdigest() or evidence.get("manifest_sha256") != hashlib.sha256((poc_dir / "manifest.json").read_bytes()).hexdigest():
            raise ValueError("PoC 검증 이후 작업물 파일이 변경됐습니다")
        for field, expected_line in (("source", finding["source_line"]), ("sink", finding["sink_line"])):
            citation = claim[field]
            if citation["file"] != finding["path"] or int(citation["line"]) != expected_line:
                raise ValueError(f"{field} 인용 위치가 조사 가설과 다릅니다")
            source_file = (checkout_path / citation["file"]).resolve()
            if not source_file.is_relative_to(checkout_path.resolve()):
                raise ValueError("조사 체크아웃 밖의 코드 인용입니다")
            lines = source_file.read_text(encoding="utf-8").splitlines()
            if expected_line > len(lines) or citation["evidence"].strip() not in lines[expected_line - 1]:
                raise ValueError(f"{field} 코드 인용이 조사 커밋의 파일과 다릅니다")
        checks = claim["known_advisory_checks"]
        affected = claim["affected"]
        steps = "\n".join(f"{i}. {step}" for i, step in enumerate(claim["reproduction_steps"], 1))
        description = f'''# {claim["title"]}

| GHSA form field | Value |
| --- | --- |
| Ecosystem | {affected["ecosystem"]} |
| Package | `{affected["package"]}` |
| Affected versions | {affected["versions"]} |
| Patched version | {affected.get("patched_version") or "Not yet available"} |
| CWE | {claim["cwe"]} |
| CVSS vector | {claim.get("cvss_vector") or "Pending maintainer review"} |
| Analyzed commit | `{audit_data["commit"]}` |

## Summary

{claim["summary"]}

## Technical details

{claim["root_cause"]}

Attacker-controlled source: `{claim["source"]["file"]}:{claim["source"]["line"]}` — {claim["source"]["attacker_control"]}. Code: `{claim["source"]["evidence"]}`.

Dangerous sink: `{claim["sink"]["file"]}:{claim["sink"]["line"]}` — {claim["sink"]["effect"]}. Code: `{claim["sink"]["evidence"]}`.

Default configuration: {claim["default_configuration_evidence"]}

Upstream guards and rebuttal checks: {claim["upstream_guard_analysis"]}

## Proof of concept

The normal/attack PoC contrast matched against the checkout at `{audit_data["commit"]}`. PoC files: `{claim_file.parent / "proof.py"}` and `{claim_file.parent / "manifest.json"}`. Run `python3 -m oss_timeline poc-verify {claim_file.parent / "manifest.json"}` in an offline container.

{steps}

Attack observable: {evidence["attack"]["stdout"].strip()[:500]}

Benign control: {claim["negative_control_explanation"]}. Control output: {evidence["control"]["stdout"].strip()[:500]}

## Impact

{claim["impact"]}

## Novelty checks

- GitHub: {checks["github"]}
- OSV: {checks["osv"]}
- Vendor/other disclosures: {checks["vendor_or_web"]}
- Duplicate and variant analysis: {checks["duplicate_analysis"]}

## Suggested remediation

{claim["remediation"]}

Private reporting entry point: https://github.com/{repo}/security/advisories (use "Report a vulnerability" if available)
'''
        destination = audit_file.parent / finding_id
        ghsa = destination / "GHSA_CANDIDATE.md"
        cve = destination / "CVE_REQUEST_BRIEF.md"
        cve_text = f'''# CVE request brief: {claim["title"]}

Product/repository: https://github.com/{repo}

Affected package and versions: {affected["ecosystem"]} / {affected["package"]} / {affected["versions"]}

Weakness: {claim["cwe"]}

Impact: {claim["impact"]}

Root cause and reproducibility: {claim["root_cause"]} See `GHSA_CANDIDATE.md`, `proof.py`, `manifest.json`, and `evidence.json` for the full private report and local reproduction.

CVE ID: not assigned. Coordinate the request with the repository maintainer or an in-scope CNA after private triage.
'''
        ghsa.write_text(description, encoding="utf-8")
        cve.write_text(cve_text, encoding="utf-8")
        return ghsa, cve
