from __future__ import annotations

import ast
import hashlib
import json
import os
import posixpath
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .core import Store, repo_name


IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "vendor", "__pycache__"}
JS_SOURCE = re.compile(r"\b(?:req|request)\.(?:query|body|params|headers)(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])?", re.I)
JS_SINKS = [
    ("command_injection", re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s*\(")),
    ("code_execution", re.compile(r"\beval\s*\(")),
    ("possible_ssrf", re.compile(r"\b(?:fetch|axios\.(?:get|post|request)|https?\.(?:get|request))\s*\(")),
    ("sql_injection", re.compile(r"\b[A-Za-z_$][\w$]*\.(?:query|execute)\s*\(")),
    ("path_traversal", re.compile(r"\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(")),
    ("authentication_bypass", re.compile(r"\b(?:jwt|jsonwebtoken)\.decode\s*\(")),
]
GO_SOURCE = re.compile(r"\b(?:r\.(?:FormValue|PostFormValue)\s*\(|r\.URL\.Query\(\)\.Get\s*\(|r\.Header\.Get\s*\(|(?:c|ctx)\.(?:Query|QueryParam|Param|PostForm|FormValue)\s*\(|os\.Args\s*\[|flag\.Arg\s*\(|os\.Getenv\s*\()")
PUBLIC_INPUT_NAMES = {"args", "body", "command", "content", "data", "filename", "input", "limit", "params", "path", "payload", "query", "url"}
C_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}
C_RETURN_SOURCE = re.compile(r"\b(?:getenv|getopt|getopt_long)\s*\(|\bargv\s*\[|=\s*[A-Za-z_]\w*(?:receive|recv|read)[A-Za-z_]*\s*\(", re.I)
C_BUFFER_SOURCE = re.compile(r"\b(?:recv|recvfrom|read|fgets|gets|scanf|sscanf)\s*\(")
C_SINKS = [
    ("command_injection", re.compile(r"\b(?:system|popen|execl|execlp|execv|execvp)\s*\(([^;]*)")),
    ("format_string", re.compile(r"\b(?:printf|syslog)\s*\(([^;]*)")),
    ("unsafe_copy", re.compile(r"\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(([^;]*)")),
]
PROFILE_MANIFESTS = {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "Cargo.toml", "go.mod", "composer.json", "pom.xml", "build.gradle", "build.gradle.kts", "CMakeLists.txt", "Makefile"}
PROFILE_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "uv.lock", "Cargo.lock", "go.sum", "composer.lock", "gradle.lockfile"}
LANGUAGE_SUFFIXES = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".c": "c", ".h": "c/c++", ".cc": "c/c++", ".cpp": "c/c++", ".cxx": "c/c++", ".hpp": "c/c++", ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".php": "php", ".rb": "ruby"}
ENTRY_PATTERNS = [
    ("http", re.compile(r"@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete)\s*\(|\b(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\(|@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b")),
    ("cli", re.compile(r"if\s+__name__\s*==\s*['\"]__main__['\"]|\bfunc\s+main\s*\(|\bint\s+main\s*\(|\bconsole_scripts\b")),
    ("message", re.compile(r"\b(?:subscribe|consumer|on_message|addEventListener)\s*\(")),
]
FRAMEWORK_DEPENDENCIES = {
    "flask": "Flask", "django": "Django", "fastapi": "FastAPI", "starlette": "Starlette",
    "express": "Express", "koa": "Koa", "@nestjs/core": "NestJS", "next": "Next.js",
    "spring-boot": "Spring Boot", "org.springframework.boot": "Spring Boot",
    "github.com/gin-gonic/gin": "Gin", "github.com/labstack/echo": "Echo",
    "github.com/gofiber/fiber": "Fiber", "actix-web": "Actix Web", "rocket": "Rocket",
}


def _python_parse(text: str) -> ast.AST:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(text)


def _dependency_records(filename: str, text: str, path: str) -> list[dict]:
    records = []
    try:
        if filename in {"package.json", "package-lock.json"}:
            data = json.loads(text)
            if filename == "package.json":
                for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
                    for name, version in (data.get(section) or {}).items():
                        records.append({"ecosystem": "npm", "name": name, "version": str(version), "source": path, "scope": section})
            else:
                for key, value in (data.get("packages") or {}).items():
                    if key and "/node_modules/" in "/" + key and isinstance(value, dict):
                        package_name = value.get("name") or key.rsplit("node_modules/", 1)[-1]
                        records.append({"ecosystem": "npm", "name": package_name, "version": str(value.get("version") or ""), "source": path, "scope": "lock"})
        elif filename == "pyproject.toml":
            data = tomllib.loads(text)
            for requirement in (data.get("project", {}).get("dependencies") or []):
                match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
                if match:
                    records.append({"ecosystem": "pip", "name": match.group(1), "version": requirement[len(match.group(0)):].strip(), "source": path, "scope": "direct"})
            for name, version in (data.get("tool", {}).get("poetry", {}).get("dependencies") or {}).items():
                if name.lower() != "python":
                    records.append({"ecosystem": "pip", "name": name, "version": str(version), "source": path, "scope": "direct"})
        elif filename == "Cargo.lock":
            for package in tomllib.loads(text).get("package", []):
                records.append({"ecosystem": "rust", "name": package.get("name", ""), "version": str(package.get("version") or ""), "source": path, "scope": "lock"})
        elif filename == "go.sum":
            seen = set()
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] not in seen:
                    seen.add(parts[0])
                    records.append({"ecosystem": "go", "name": parts[0], "version": parts[1].removesuffix("/go.mod"), "source": path, "scope": "lock"})
        elif filename.startswith("requirements") and filename.endswith(".txt"):
            for line in text.splitlines():
                value = line.strip()
                if not value or value.startswith(("#", "-")):
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)(.*)", value)
                if match:
                    records.append({"ecosystem": "pip", "name": match.group(1), "version": match.group(2).strip(), "source": path, "scope": "direct"})
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError, AttributeError):
        return []
    return [item for item in records if item.get("name")]


@dataclass
class Hypothesis:
    id: str
    tracking_id: str
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
    source_path: str = ""
    sink_path: str = ""
    entry_kind: str = "modeled_external_input"
    trace: list[dict] = field(default_factory=list)


def _qualified(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _qualified(node.value) + "." + node.attr
    return ""


def _request_source(node: ast.AST) -> bool:
    for child in ast.walk(node):
        qualified = _qualified(child)
        if qualified.startswith(("request.args", "request.form", "request.values", "request.json", "request.headers", "request.cookies", "request.GET", "request.POST", "sys.argv")) or qualified == "request.get_json":
            return True
        if isinstance(child, ast.Call) and _qualified(child.func) == "input":
            return True
    return False


def _literal_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_literal_value(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and _literal_value(key) and _literal_value(value) for key, value in zip(node.keys, node.values))
    return False


def _constant_lookup_tables(tree: ast.Module) -> set[str]:
    """Find module-level literal mappings that are assigned once and never mutated."""
    assignments: dict[str, int] = {}
    candidates = set()
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {sub.id for target in targets for sub in ast.walk(target) if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store)}
            for name in names:
                assignments[name] = assignments.get(name, 0) + 1
                if isinstance(node.value, ast.Dict) and _literal_value(node.value):
                    candidates.add(name)
    mutators = {"clear", "pop", "popitem", "setdefault", "update", "__setitem__"}
    writes: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                        writes[sub.id] = writes.get(sub.id, 0) + 1
            value = node.value
            if isinstance(value, ast.Name) and value.id in candidates:
                candidates.discard(value.id)
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name):
            candidates.discard(node.value.id)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.attr in mutators:
            candidates.discard(node.func.value.id)
    return {name for name in candidates if assignments.get(name) == 1 and writes.get(name) == 1}


def _safe_allowlist_lookup(node: ast.AST, tables: set[str]) -> bool:
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        return node.value.id in tables
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        return node.func.value.id in tables and node.func.attr == "get"
    return False


def _safe_sql_placeholder_expression(node: ast.AST) -> bool:
    """Recognize a bounded DB-API placeholder builder such as ','.join('?' * len(values))."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "join" or len(node.args) != 1:
        return False
    value = node.args[0]
    if not isinstance(value, ast.BinOp) or not isinstance(value.op, ast.Mult):
        return False
    candidates = (value.left, value.right)
    return any(isinstance(item, ast.Constant) and item.value == "?" for item in candidates) and any(isinstance(item, ast.Call) and _qualified(item.func) == "len" for item in candidates)


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
    if name.endswith((".execute", ".executemany")) and not isinstance(node.args[0], ast.Constant):
        return "sql_injection", node.args[0]
    if name in {"render_template_string", "flask.render_template_string", "jinja2.Template"}:
        return "template_injection", node.args[0]
    if name == "os.open" and any(isinstance(item, ast.Attribute) and item.attr in {"O_EXCL", "O_NOFOLLOW"} for item in ast.walk(node)):
        return None
    if name in {"open", "os.open", "pathlib.Path", "Path"} or name.endswith((".read_text", ".read_bytes", ".write_text", ".write_bytes")):
        return "path_traversal", node.args[0]
    if name.endswith("jwt.decode"):
        disabled = any(keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False for keyword in node.keywords)
        for keyword in node.keywords:
            if keyword.arg != "options" or not isinstance(keyword.value, ast.Dict):
                continue
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if isinstance(key, ast.Constant) and key.value == "verify_signature" and isinstance(value, ast.Constant) and value.value is False:
                    disabled = True
        if disabled:
            return "authentication_bypass", node.args[0]
    return None


def _python_toctou_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    try:
        text = filename.read_text(encoding="utf-8")
        tree = _python_parse(text)
    except (OSError, UnicodeError, SyntaxError):
        return []
    lines = text.splitlines()
    path = filename.relative_to(root).as_posix()
    output = []
    checks = {"os.path.exists", "os.path.lexists", "os.path.isfile", "os.path.isdir", "os.access"}
    effects = {"open", "os.open", "os.remove", "os.unlink", "os.rename", "os.replace", "shutil.copy", "shutil.copyfile", "shutil.move"}
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        origins: dict[str, tuple[int, str, str, str]] = {}
        route = any(isinstance(decorator, ast.Call) and _qualified(decorator.func).rsplit(".", 1)[-1] in {"route", "get", "post", "put", "patch", "delete"} for decorator in function.decorator_list)
        if route or not function.name.startswith("_"):
            for argument in function.args.posonlyargs + function.args.args + function.args.kwonlyargs:
                lowered = argument.arg.lower()
                if (route and argument.arg not in {"self", "cls", "request"}) or lowered in PUBLIC_INPUT_NAMES or lowered.endswith(("_path", "_filename")):
                    origins[argument.arg] = (function.lineno, lines[function.lineno - 1], "http_route" if route else "modeled_public_api", f"argument:{argument.arg}")
        observed = []
        for node in sorted(ast.walk(function), key=lambda item: getattr(item, "lineno", 0)):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                origin = (node.value.lineno, lines[node.value.lineno - 1], "modeled_request", ast.dump(node.value, include_attributes=False)) if _request_source(node.value) else next((origins[name] for name in _name_refs(node.value) if name in origins), None)
                if origin:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            origins[target.id] = origin
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = _qualified(node.func)
            argument = node.args[0]
            origin = (argument.lineno, lines[argument.lineno - 1], "modeled_request", ast.dump(argument, include_attributes=False)) if _request_source(argument) else next((origins[item] for item in _name_refs(argument) if item in origins), None)
            if not origin:
                continue
            if name in checks:
                observed.append((origin, node.lineno, lines[node.lineno - 1]))
            elif name in effects and not (name == "os.open" and any(isinstance(item, ast.Attribute) and item.attr in {"O_EXCL", "O_NOFOLLOW"} for item in ast.walk(node))):
                check = next((item for item in reversed(observed) if item[0] == origin and item[1] < node.lineno), None)
                if check:
                    trace = [{"role": "source", "path": path, "line": origin[0], "function": function.name, "code": origin[1].strip()[:240]}, {"role": "check", "path": path, "line": check[1], "function": function.name, "code": check[2].strip()[:240]}, {"role": "sink", "path": path, "line": node.lineno, "function": function.name, "code": lines[node.lineno - 1].strip()[:240]}]
                    output.append(_hypothesis(repo, commit, "toctou_candidate", path, origin[0], node.lineno, origin[1], lines[node.lineno - 1], function.name, entry_kind=origin[2], trace=trace))
    return output


def _workflow_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    try:
        lines = filename.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    event = next((index for index, line in enumerate(lines, 1) if re.search(r"\bpull_request_target\s*:", line)), None)
    unsafe_checkout = next((index for index, line in enumerate(lines, 1) if "github.event.pull_request.head.sha" in line or "github.event.pull_request.head.repo.full_name" in line), None)
    checkout = max((index for index, line in enumerate(lines, 1) if unsafe_checkout and index < unsafe_checkout and re.search(r"\buses\s*:\s*actions/checkout@", line)), default=None)
    run = next((index for index, line in enumerate(lines, 1) if unsafe_checkout and index > unsafe_checkout and re.match(r"\s*-?\s*run\s*:", line)), None)
    intervening_step = checkout and unsafe_checkout and any(re.match(r"\s*-\s+(?:uses|run)\s*:", lines[index - 1]) for index in range(checkout + 1, unsafe_checkout))
    if not event or not checkout or not unsafe_checkout or not run or intervening_step:
        return []
    path = filename.relative_to(root).as_posix()
    trace = [{"role": "source", "path": path, "line": event, "function": "github_actions_workflow", "code": lines[event - 1].strip()[:240]}, {"role": "checkout", "path": path, "line": unsafe_checkout, "function": "github_actions_workflow", "code": lines[unsafe_checkout - 1].strip()[:240]}, {"role": "sink", "path": path, "line": run, "function": "github_actions_workflow", "code": lines[run - 1].strip()[:240]}]
    return [_hypothesis(repo, commit, "workflow_injection", path, event, run, lines[event - 1], lines[run - 1], "github_actions_workflow", entry_kind="pull_request_target", trace=trace)]


def _decorator_name(decorator: ast.AST) -> str:
    return _qualified(decorator.func if isinstance(decorator, ast.Call) else decorator).lower()


def _python_authorization_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    """Find narrow, evidence-backed privilege assignment and destructive IDOR candidates."""
    try:
        text = filename.read_text(encoding="utf-8")
        tree = _python_parse(text)
    except (OSError, UnicodeError, SyntaxError):
        return []
    lines = text.splitlines()
    path = filename.relative_to(root).as_posix()
    output = []
    privileged_terms = ("admin", "staff", "permission", "privilege", "owner")
    authentication_terms = ("login_required", "auth_required", "authenticated", "jwt_required", "require_auth")
    privilege_fields = {"role", "roles", "is_admin", "is_staff", "permission", "permissions", "access_level", "privilege", "privileges"}
    principal_terms = ("current_user", "request.user", "g.user", "owner_id", "user_id", "account_id", "tenant_id")
    lookup_terms = (".get(", ".get_or_404(", ".filter(", ".filter_by(", ".find(", ".find_by_id(")
    destructive_methods = {"delete", "destroy", "remove", "update"}

    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        decorators = [_decorator_name(item) for item in function.decorator_list]
        route = any(name.rsplit(".", 1)[-1] in {"route", "get", "post", "put", "patch", "delete"} for name in decorators)
        if not route:
            continue
        privileged_decorator = any(any(term in name for term in privileged_terms) for name in decorators)
        authenticated = any(any(term in name for term in authentication_terms) for name in decorators)
        function_text = ast.unparse(function).lower()
        inline_authorization = any(principal in function_text for principal in principal_terms) and any(term in function_text for term in privileged_terms)

        tainted: dict[str, tuple[int, str]] = {}
        for argument in function.args.posonlyargs + function.args.args + function.args.kwonlyargs:
            lowered = argument.arg.lower()
            if lowered not in {"self", "cls", "request"} and (lowered == "id" or lowered.endswith(("_id", "_key", "_uuid"))):
                tainted[argument.arg] = (function.lineno, lines[function.lineno - 1])

        object_lookups: dict[str, tuple[tuple[int, str], int, str]] = {}
        for node in sorted(ast.walk(function), key=lambda item: getattr(item, "lineno", 0)):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                simple_targets = [target.id for target in targets if isinstance(target, ast.Name)]
                origin = (node.value.lineno, lines[node.value.lineno - 1]) if _request_source(node.value) else next((tainted[name] for name in _name_refs(node.value) if name in tainted), None)
                if origin:
                    for name in simple_targets:
                        tainted[name] = origin
                value_text = ast.unparse(node.value).lower()
                tainted_origin = next((tainted[name] for name in _name_refs(node.value) if name in tainted), None)
                scoped = any(term in value_text for term in principal_terms)
                if authenticated and tainted_origin and any(term in value_text for term in lookup_terms) and not scoped:
                    for name in simple_targets:
                        object_lookups[name] = (tainted_origin, node.lineno, lines[node.lineno - 1])

                if not privileged_decorator and not inline_authorization and origin:
                    for target in targets:
                        field = target.attr.lower() if isinstance(target, ast.Attribute) else ""
                        if field not in privilege_fields:
                            continue
                        trace = [
                            {"role": "source", "path": path, "line": origin[0], "function": function.name, "code": origin[1].strip()[:240]},
                            {"role": "privilege_write", "path": path, "line": node.lineno, "function": function.name, "code": lines[node.lineno - 1].strip()[:240]},
                        ]
                        output.append(_hypothesis(repo, commit, "privilege_assignment", path, origin[0], node.lineno, origin[1], lines[node.lineno - 1], function.name, entry_kind="http_route", trace=trace))

                if authenticated and not inline_authorization and not privileged_decorator:
                    for target in targets:
                        affected = target.value.id if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) else None
                        if affected not in object_lookups:
                            continue
                        lookup_origin, lookup_line, lookup_code = object_lookups[affected]
                        trace = [
                            {"role": "source", "path": path, "line": lookup_origin[0], "function": function.name, "code": lookup_origin[1].strip()[:240]},
                            {"role": "unscoped_lookup", "path": path, "line": lookup_line, "function": function.name, "code": lookup_code.strip()[:240]},
                            {"role": "destructive_action", "path": path, "line": node.lineno, "function": function.name, "code": lines[node.lineno - 1].strip()[:240]},
                        ]
                        output.append(_hypothesis(repo, commit, "authorization_scope_candidate", path, lookup_origin[0], node.lineno, lookup_origin[1], lines[node.lineno - 1], function.name, entry_kind="http_route", trace=trace))

            if not authenticated or inline_authorization or privileged_decorator or not isinstance(node, ast.Call):
                continue
            called = _qualified(node.func)
            method = called.rsplit(".", 1)[-1].lower()
            affected = None
            if method in destructive_methods and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                affected = node.func.value.id
            elif method in destructive_methods and node.args and isinstance(node.args[0], ast.Name):
                affected = node.args[0].id
            if affected not in object_lookups:
                continue
            origin, lookup_line, lookup_code = object_lookups[affected]
            trace = [
                {"role": "source", "path": path, "line": origin[0], "function": function.name, "code": origin[1].strip()[:240]},
                {"role": "unscoped_lookup", "path": path, "line": lookup_line, "function": function.name, "code": lookup_code.strip()[:240]},
                {"role": "destructive_action", "path": path, "line": node.lineno, "function": function.name, "code": lines[node.lineno - 1].strip()[:240]},
            ]
            output.append(_hypothesis(repo, commit, "authorization_scope_candidate", path, origin[0], node.lineno, origin[1], lines[node.lineno - 1], function.name, entry_kind="http_route", trace=trace))
    return output


def _python_concurrency_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    """Find security-state check/act windows on module-level mutable containers."""
    try:
        text = filename.read_text(encoding="utf-8")
        tree = _python_parse(text)
    except (OSError, UnicodeError, SyntaxError):
        return []
    lines = text.splitlines()
    path = filename.relative_to(root).as_posix()
    security_terms = ("attempt", "quota", "limit", "balance", "credit", "nonce", "token", "replay", "session")
    mutable_calls = {"dict", "list", "set", "collections.defaultdict", "collections.counter", "defaultdict", "counter"}
    shared = set()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value_is_mutable = isinstance(node.value, (ast.Dict, ast.List, ast.Set)) or isinstance(node.value, ast.Call) and _qualified(node.value.func).lower() in mutable_calls
        if value_is_mutable:
            shared.update(target.id for target in targets if isinstance(target, ast.Name) and any(term in target.id.lower() for term in security_terms))
    if not shared:
        return []

    output = []
    mutating_methods = {"add", "append", "clear", "discard", "extend", "pop", "remove", "update"}
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        decorators = [_decorator_name(item) for item in function.decorator_list]
        route = any(name.rsplit(".", 1)[-1] in {"route", "get", "post", "put", "patch", "delete"} for name in decorators)
        concurrent_entry = route or isinstance(function, ast.AsyncFunctionDef)
        if not concurrent_entry:
            continue
        has_lock = any(
            isinstance(node, (ast.With, ast.AsyncWith)) and any(any(term in ast.unparse(item.context_expr).lower() for term in ("lock", "mutex", "semaphore")) for item in node.items)
            or isinstance(node, ast.Call) and _qualified(node.func).lower().endswith((".acquire", ".acquire_nowait"))
            for node in ast.walk(function)
        )
        if has_lock:
            continue

        checks = []
        mutations = []
        for node in ast.walk(function):
            if isinstance(node, ast.If):
                names = {name for name in shared if name in _name_refs(node.test)}
                for name in names:
                    checks.append((name, node.lineno, lines[node.lineno - 1]))
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Subscript) and isinstance(node.target.value, ast.Name) and node.target.value.id in shared:
                mutations.append((node.target.value.id, node.lineno, lines[node.lineno - 1]))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id in shared:
                        mutations.append((target.value.id, node.lineno, lines[node.lineno - 1]))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in shared and node.func.attr in mutating_methods:
                mutations.append((node.func.value.id, node.lineno, lines[node.lineno - 1]))

        source_line = function.lineno
        source_code = lines[source_line - 1]
        for node in sorted(ast.walk(function), key=lambda item: getattr(item, "lineno", 0)):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None and _request_source(node.value):
                source_line, source_code = node.lineno, lines[node.lineno - 1]
                break
        for name, check_line, check_code in checks:
            mutation = next((item for item in sorted(mutations, key=lambda item: item[1]) if item[0] == name and item[1] > check_line), None)
            if not mutation:
                continue
            _, mutation_line, mutation_code = mutation
            trace = [
                {"role": "source", "path": path, "line": source_line, "function": function.name, "code": source_code.strip()[:240]},
                {"role": "shared_state_check", "path": path, "line": check_line, "function": function.name, "code": check_code.strip()[:240]},
                {"role": "unsynchronized_mutation", "path": path, "line": mutation_line, "function": function.name, "code": mutation_code.strip()[:240]},
            ]
            output.append(_hypothesis(repo, commit, "concurrency_race_candidate", path, source_line, mutation_line, source_code, mutation_code, function.name, entry_kind="http_route" if route else "modeled_public_api", trace=trace))
    return output


def _hypothesis(repo: str, commit: str, kind: str, path: str, source_line: int, sink_line: int, source_code: str, sink_code: str, function: str, *, source_path: str | None = None, sink_path: str | None = None, entry_kind: str = "modeled_external_input", trace: list[dict] | None = None) -> Hypothesis:
    source_path = source_path or path
    sink_path = sink_path or path
    identity = f"{repo}|{commit}|{kind}|{source_path}|{source_line}|{sink_path}|{sink_line}"
    stable = f"{repo}|{kind}|{source_path}|{sink_path}|{function}|{source_code.strip()}|{sink_code.strip()}"
    path_trace = trace or [
        {"role": "source", "path": source_path, "line": source_line, "code": source_code.strip()[:240]},
        {"role": "sink", "path": sink_path, "line": sink_line, "code": sink_code.strip()[:240]},
    ]
    return Hypothesis("FIND-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper(), "TRACK-" + hashlib.sha256(stable.encode()).hexdigest()[:12].upper(), repo, commit, kind, path, source_line, sink_line, source_code.strip()[:400], sink_code.strip()[:400], function, "hypothesis", source_path, sink_path, entry_kind, path_trace)


def _recent_change_profile(root: Path, max_commits: int = 20) -> dict:
    """Return a bounded per-file change count without requiring a full clone."""
    try:
        count_result = subprocess.run(["git", "-C", str(root), "rev-list", "--count", "HEAD"], capture_output=True, text=True, timeout=10)
        commit_count = int(count_result.stdout.strip()) if count_result.returncode == 0 else 0
        if commit_count < 2:
            return {"commits_considered": 0, "files": {}}
        depth = min(max_commits, commit_count - 1)
        result = subprocess.run(["git", "-C", str(root), "log", "--format=", "--name-only", f"HEAD~{depth}..HEAD"], capture_output=True, text=True, timeout=20)
        if result.returncode:
            return {"commits_considered": 0, "files": {}}
        files: dict[str, int] = {}
        for value in result.stdout.splitlines():
            path = value.strip()
            if path and not path.startswith("/") and ".." not in Path(path).parts:
                files[path] = files.get(path, 0) + 1
        return {"commits_considered": depth, "files": dict(sorted(files.items(), key=lambda item: (-item[1], item[0]))[:1000])}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"commits_considered": 0, "files": {}}


def _frameworks(dependencies: list[dict], entrypoints: list[dict]) -> list[str]:
    detected = set()
    for item in dependencies:
        name = str(item.get("name") or "").lower()
        for marker, label in FRAMEWORK_DEPENDENCIES.items():
            if name == marker or name.startswith(marker + "/"):
                detected.add(label)
    for entry in entrypoints:
        code = str(entry.get("code") or "").lower()
        if "@app." in code or "@blueprint." in code:
            detected.add("Python web framework")
        if "router." in code or "app.get(" in code or "app.post(" in code:
            detected.add("JavaScript web framework")
    return sorted(detected)


class RepositoryProfilerAgent:
    """Build a bounded repository/package/entry-point coverage ledger."""
    def run(self, root: Path, max_files: int = 50_000) -> dict:
        root = root.resolve()
        languages: dict[str, int] = {}
        manifests, lockfiles, entrypoints, dependencies = [], [], [], []
        files_seen = code_files = unsupported_code_files = oversized = 0
        truncated = False
        for filename in root.rglob("*"):
            try:
                relative = filename.relative_to(root)
                if any(part in IGNORED_DIRS for part in relative.parts) or not filename.is_file() or filename.is_symlink():
                    continue
                files_seen += 1
                if files_seen > max_files:
                    truncated = True
                    break
                size = filename.stat().st_size
            except OSError:
                continue
            name, suffix, path = filename.name, filename.suffix.lower(), relative.as_posix()
            if name in PROFILE_MANIFESTS:
                manifests.append(path)
            is_requirement = name.startswith("requirements") and name.endswith(".txt")
            if name in PROFILE_LOCKFILES or is_requirement:
                lockfiles.append(path)
            if (name in PROFILE_MANIFESTS or name in PROFILE_LOCKFILES or is_requirement) and size <= 5_000_000 and len(dependencies) < 5_000:
                try:
                    dependencies.extend(_dependency_records(name, filename.read_text(encoding="utf-8", errors="replace"), path)[: 5_000 - len(dependencies)])
                except OSError:
                    pass
            language = LANGUAGE_SUFFIXES.get(suffix)
            if not language:
                continue
            code_files += 1
            languages[language] = languages.get(language, 0) + 1
            if suffix not in {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", *C_EXTENSIONS}:
                unsupported_code_files += 1
            if size > 500_000:
                oversized += 1
                continue
            try:
                lines = filename.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                if len(entrypoints) >= 500:
                    break
                for kind, pattern in ENTRY_PATTERNS:
                    if pattern.search(line):
                        entrypoints.append({"kind": kind, "path": path, "line": number, "code": line.strip()[:240]})
                        break
        ecosystem_counts: dict[str, int] = {}
        for item in dependencies:
            ecosystem_counts[item["ecosystem"]] = ecosystem_counts.get(item["ecosystem"], 0) + 1
        project_kind = "service" if any(item["kind"] in {"http", "message"} for item in entrypoints) else "cli" if any(item["kind"] == "cli" for item in entrypoints) else "library_or_unknown"
        return {"files_seen": min(files_seen, max_files), "code_files": code_files, "unsupported_code_files": unsupported_code_files, "oversized_code_files": oversized, "languages": dict(sorted(languages.items(), key=lambda item: (-item[1], item[0]))), "manifests": sorted(manifests), "lockfiles": sorted(lockfiles), "dependencies": dependencies, "dependency_count": len(dependencies), "dependency_ecosystems": ecosystem_counts, "frameworks": _frameworks(dependencies, entrypoints), "project_kind": project_kind, "recent_changes": _recent_change_profile(root), "dependencies_truncated": len(dependencies) >= 5_000, "entrypoints": entrypoints, "entrypoints_truncated": len(entrypoints) >= 500, "truncated": truncated, "scope": "default branch checkout excluding generated/vendor directories"}


def _python_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    try:
        text = filename.read_text(encoding="utf-8")
        tree = _python_parse(text)
    except (OSError, UnicodeError, SyntaxError):
        return []
    lines = text.splitlines()
    output = []
    path = filename.relative_to(root).as_posix()
    allowlists = _constant_lookup_tables(tree)
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
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if _safe_allowlist_lookup(value, allowlists):
                    for target in targets:
                        for sub in ast.walk(target):
                            if isinstance(sub, ast.Name):
                                assigned.pop(sub.id, None)
                    continue
                origin = None
                if _request_source(value):
                    origin = (value.lineno, lines[value.lineno - 1])
                else:
                    origin = next((assigned[name] for name in _name_refs(value) if name in assigned), None)
                if origin:
                    for target in targets:
                        for sub in ast.walk(target):
                            if isinstance(sub, ast.Name):
                                assigned[sub.id] = origin
            if isinstance(node, ast.Call):
                sink = _sink_kind(node)
                if not sink:
                    continue
                kind, argument = sink
                if _safe_allowlist_lookup(argument, allowlists):
                    continue
                if _request_source(argument):
                    source = (argument.lineno, lines[argument.lineno - 1])
                else:
                    source = next((assigned[name] for name in _name_refs(argument) if name in assigned), None)
                if source:
                    entry_kind = "http_route" if http_route and source[0] == function.lineno else "modeled_request"
                    output.append(_hypothesis(repo, commit, kind, path, source[0], node.lineno, source[1], lines[node.lineno - 1], function.name, entry_kind=entry_kind))
    return output


def _python_interprocedural_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    """Trace modeled external input through one same-module helper call."""
    try:
        text = filename.read_text(encoding="utf-8")
        tree = _python_parse(text)
    except (OSError, UnicodeError, SyntaxError):
        return []
    lines = text.splitlines()
    allowlists = _constant_lookup_tables(tree)
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    summaries: dict[str, list[dict]] = {}
    for function in functions:
        parameters = [argument.arg for argument in function.args.posonlyargs + function.args.args + function.args.kwonlyargs]
        origins = {name: name for name in parameters}
        for node in ast.walk(function):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                if _safe_allowlist_lookup(node.value, allowlists):
                    continue
                origin = next((origins[name] for name in _name_refs(node.value) if name in origins), None)
                if origin:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        for sub in ast.walk(target):
                            if isinstance(sub, ast.Name):
                                origins[sub.id] = origin
            if isinstance(node, ast.Call) and (sink := _sink_kind(node)):
                kind, argument = sink
                if _safe_allowlist_lookup(argument, allowlists):
                    continue
                parameter = next((origins[name] for name in _name_refs(argument) if name in origins), None)
                if parameter:
                    summaries.setdefault(function.name, []).append({"parameter": parameter, "kind": kind, "sink_line": node.lineno, "sink_code": lines[node.lineno - 1]})
    output = []
    path = filename.relative_to(root).as_posix()
    for caller in functions:
        external: dict[str, tuple[int, str]] = {}
        http_route = any(isinstance(decorator, ast.Call) and _qualified(decorator.func).rsplit(".", 1)[-1] in {"route", "get", "post", "put", "patch", "delete"} for decorator in caller.decorator_list)
        if http_route:
            for argument in caller.args.posonlyargs + caller.args.args + caller.args.kwonlyargs:
                if argument.arg not in {"self", "cls", "request"}:
                    external[argument.arg] = (caller.lineno, lines[caller.lineno - 1])
        for node in ast.walk(caller):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                origin = (node.value.lineno, lines[node.value.lineno - 1]) if _request_source(node.value) else next((external[name] for name in _name_refs(node.value) if name in external), None)
                if origin:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        for sub in ast.walk(target):
                            if isinstance(sub, ast.Name):
                                external[sub.id] = origin
            if not isinstance(node, ast.Call):
                continue
            callee = _qualified(node.func)
            if callee not in summaries or callee == caller.name:
                continue
            helper = next((item for item in functions if item.name == callee), None)
            if not helper:
                continue
            parameter_names = [argument.arg for argument in helper.args.posonlyargs + helper.args.args + helper.args.kwonlyargs]
            supplied = {parameter_names[index]: value for index, value in enumerate(node.args) if index < len(parameter_names)}
            supplied.update({keyword.arg: keyword.value for keyword in node.keywords if keyword.arg})
            for summary in summaries[callee]:
                argument = supplied.get(summary["parameter"])
                if argument is None:
                    continue
                source = (argument.lineno, lines[argument.lineno - 1]) if _request_source(argument) else next((external[name] for name in _name_refs(argument) if name in external), None)
                if source:
                    output.append(_hypothesis(repo, commit, summary["kind"], path, source[0], summary["sink_line"], source[1], summary["sink_code"], caller.name, entry_kind="http_route" if http_route else "modeled_request"))
    return output


def _python_module_name(path: Path) -> str:
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _python_multihop_hypotheses(files: list[Path], root: Path, repo: str, commit: str, max_depth: int = 4) -> list[Hypothesis]:
    """Trace route/request input through bounded functions and resolvable methods."""
    modules: dict[str, dict] = {}
    functions: dict[str, dict] = {}
    for filename in files:
        try:
            text = filename.read_text(encoding="utf-8")
            tree = _python_parse(text)
            relative = filename.relative_to(root)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            continue
        module = _python_module_name(relative)
        lines = text.splitlines()
        imports: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".", 1)[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                current_package = module.split(".") if filename.name == "__init__.py" else module.split(".")[:-1]
                if node.level:
                    keep = max(0, len(current_package) - node.level + 1)
                    base_parts = current_package[:keep]
                else:
                    base_parts = []
                if node.module:
                    base_parts.extend(node.module.split("."))
                base = ".".join(base_parts)
                for alias in node.names:
                    imports[alias.asname or alias.name] = ".".join(part for part in (base, alias.name) if part)
        classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
        instances: dict[str, str] = {}
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
                continue
            constructor = _qualified(node.value.func)
            class_path = None
            if constructor in classes:
                class_path = f"{module}.{constructor}"
            elif constructor in imports and constructor[:1].isupper():
                class_path = imports[constructor]
            elif "." in constructor:
                head, tail = constructor.split(".", 1)
                if head in imports and tail[:1].isupper():
                    class_path = f'{imports[head]}.{tail}'
            if class_path:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        instances[target.id] = class_path
        module_info = {"path": relative.as_posix(), "lines": lines, "imports": imports, "instances": instances, "allowlists": _constant_lookup_tables(tree)}
        modules[module] = module_info
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[f"{module}:{node.name}"] = {**module_info, "node": node, "module": module, "owner": None}
            elif isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        functions[f"{module}:{node.name}.{method.name}"] = {**module_info, "node": method, "module": module, "owner": node.name}

    def resolve_callee(info: dict, call: ast.Call) -> str | None:
        qualified = _qualified(call.func)
        if not qualified:
            return None
        module = info["module"]
        if "." not in qualified:
            local = f"{module}:{qualified}"
            if local in functions:
                return local
            imported = info["imports"].get(qualified)
            if imported and "." in imported:
                candidate = imported.rsplit(".", 1)
                return f"{candidate[0]}:{candidate[1]}"
            return None
        head, tail = qualified.split(".", 1)
        instance_class = info["instances"].get(head)
        if instance_class and "." in instance_class:
            class_module, class_name = instance_class.rsplit(".", 1)
            candidate = f"{class_module}:{class_name}.{tail}"
            if candidate in functions:
                return candidate
        if head == "self" and info.get("owner"):
            candidate = f'{module}:{info["owner"]}.{tail}'
            if candidate in functions:
                return candidate
        imported_module = info["imports"].get(head)
        if imported_module and "." not in tail:
            module_candidate = f"{imported_module}:{tail}"
            if module_candidate in functions:
                return module_candidate
            if "." in imported_module:
                class_module, class_name = imported_module.rsplit(".", 1)
                method_candidate = f"{class_module}:{class_name}.{tail}"
                if method_candidate in functions:
                    return method_candidate
        local_method = f"{module}:{head}.{tail}"
        if local_method in functions:
            return local_method
        return None

    def parameter_origins(info: dict) -> tuple[list[str], dict[str, str]]:
        node = info["node"]
        parameters = [argument.arg for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        origins = {name: name for name in parameters}
        for child in ast.walk(node):
            if isinstance(child, (ast.Assign, ast.AnnAssign)) and child.value is not None:
                if _safe_allowlist_lookup(child.value, info["allowlists"]):
                    continue
                if _safe_sql_placeholder_expression(child.value):
                    continue
                origin = next((origins[name] for name in _name_refs(child.value) if name in origins), None)
                if origin:
                    targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                    for target in targets:
                        for sub in ast.walk(target):
                            if isinstance(sub, ast.Name):
                                origins[sub.id] = origin
            elif isinstance(child, ast.AugAssign):
                origin = next((origins[name] for name in _name_refs(child.value) if name in origins), None)
                if origin and isinstance(child.target, ast.Name):
                    origins[child.target.id] = origin
        return parameters, origins

    summaries: dict[str, list[dict]] = {key: [] for key in functions}
    origins_by_function = {key: parameter_origins(info) for key, info in functions.items()}

    def callable_parameters(key: str) -> list[str]:
        parameters = origins_by_function[key][0]
        if functions[key].get("owner") and parameters and parameters[0] in {"self", "cls"}:
            return parameters[1:]
        return parameters

    for key, info in functions.items():
        _, origins = origins_by_function[key]
        for node in ast.walk(info["node"]):
            if not isinstance(node, ast.Call) or not (sink := _sink_kind(node)):
                continue
            kind, argument = sink
            if _safe_allowlist_lookup(argument, info["allowlists"]):
                continue
            parameter = next((origins[name] for name in _name_refs(argument) if name in origins), None)
            if parameter:
                summaries[key].append({"parameter": parameter, "kind": kind, "sink_path": info["path"], "sink_line": node.lineno, "sink_code": info["lines"][node.lineno - 1], "trace": [{"role": "sink", "path": info["path"], "line": node.lineno, "function": info["node"].name, "code": info["lines"][node.lineno - 1].strip()[:240]}]})

    for _ in range(max_depth):
        changed = False
        for key, info in functions.items():
            parameters, origins = origins_by_function[key]
            for call in (node for node in ast.walk(info["node"]) if isinstance(node, ast.Call)):
                callee = resolve_callee(info, call)
                if not callee or callee not in summaries or callee == key:
                    continue
                callee_parameters = callable_parameters(callee)
                supplied = {callee_parameters[index]: value for index, value in enumerate(call.args) if index < len(callee_parameters)}
                supplied.update({keyword.arg: keyword.value for keyword in call.keywords if keyword.arg})
                for downstream in list(summaries[callee]):
                    argument = supplied.get(downstream["parameter"])
                    if argument is None:
                        continue
                    parameter = next((origins[name] for name in _name_refs(argument) if name in origins), None)
                    if not parameter:
                        continue
                    trace = [{"role": "call", "path": info["path"], "line": call.lineno, "function": info["node"].name, "callee": callee, "code": info["lines"][call.lineno - 1].strip()[:240]}, *downstream["trace"]]
                    candidate = {**downstream, "parameter": parameter, "trace": trace}
                    signature = (candidate["parameter"], candidate["kind"], candidate["sink_path"], candidate["sink_line"], tuple((step["path"], step["line"]) for step in trace))
                    existing = {(item["parameter"], item["kind"], item["sink_path"], item["sink_line"], tuple((step["path"], step["line"]) for step in item["trace"])) for item in summaries[key]}
                    if signature not in existing and len(summaries[key]) < 100:
                        summaries[key].append(candidate)
                        changed = True
        if not changed:
            break

    output = []
    for key, info in functions.items():
        node = info["node"]
        parameters, origins = origins_by_function[key]
        route = any(isinstance(decorator, ast.Call) and _qualified(decorator.func).rsplit(".", 1)[-1] in {"route", "get", "post", "put", "patch", "delete"} for decorator in node.decorator_list)
        external: dict[str, tuple[int, str, str]] = {}
        if route:
            for parameter in parameters:
                if parameter not in {"self", "cls", "request"}:
                    external[parameter] = (node.lineno, info["lines"][node.lineno - 1], "http_route")
        elif not node.name.startswith("_"):
            for parameter in parameters:
                lowered = parameter.lower()
                if lowered in PUBLIC_INPUT_NAMES or lowered.endswith(("_filter", "_payload", "_url", "_path")):
                    external[parameter] = (node.lineno, info["lines"][node.lineno - 1], "modeled_public_api")
        for downstream in summaries[key]:
            source = external.get(downstream["parameter"])
            if not source:
                continue
            trace = [{"role": "source", "path": info["path"], "line": source[0], "function": node.name, "code": source[1].strip()[:240]}, *downstream["trace"]]
            output.append(_hypothesis(repo, commit, downstream["kind"], info["path"], source[0], downstream["sink_line"], source[1], downstream["sink_code"], node.name, source_path=info["path"], sink_path=downstream["sink_path"], entry_kind=source[2], trace=trace))
        for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
            callee = resolve_callee(info, call)
            if not callee or callee not in summaries:
                continue
            callee_parameters = callable_parameters(callee)
            supplied = {callee_parameters[index]: value for index, value in enumerate(call.args) if index < len(callee_parameters)}
            supplied.update({keyword.arg: keyword.value for keyword in call.keywords if keyword.arg})
            for downstream in summaries[callee]:
                argument = supplied.get(downstream["parameter"])
                if argument is None:
                    continue
                if _request_source(argument):
                    source = (argument.lineno, info["lines"][argument.lineno - 1], "modeled_request")
                else:
                    source = next((external[name] for name in _name_refs(argument) if name in external), None)
                    if not source:
                        parameter = next((origins[name] for name in _name_refs(argument) if name in origins), None)
                        source = external.get(parameter) if parameter else None
                if not source:
                    continue
                trace = [{"role": "source", "path": info["path"], "line": source[0], "function": node.name, "code": source[1].strip()[:240]}, {"role": "call", "path": info["path"], "line": call.lineno, "function": node.name, "callee": callee, "code": info["lines"][call.lineno - 1].strip()[:240]}, *downstream["trace"]]
                output.append(_hypothesis(repo, commit, downstream["kind"], info["path"], source[0], downstream["sink_line"], source[1], downstream["sink_code"], node.name, source_path=info["path"], sink_path=downstream["sink_path"], entry_kind=source[2], trace=trace))
                if len(output) >= 10_000:
                    return output
    return output


def _js_refs(value: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\b[A-Za-z_$][\w$]*\b", re.sub(r"(['\"]).*?\1", "", value))))


def _js_function_blocks(lines: list[str]) -> list[dict]:
    """Extract ordinary named function bodies without pretending to be a full JS parser."""
    starts = [
        re.compile(r"\b(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", re.S),
        re.compile(r"\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>", re.S),
    ]
    output = []
    for index, line in enumerate(lines):
        header = "\n".join(lines[index : min(len(lines), index + 16)])
        match = None
        for candidate in starts:
            match = candidate.search(header)
            if match:
                break
        if not match:
            continue
        if match.start() and "\n" in header[:match.start()]:
            continue
        remainder = header[match.end():]
        body_offset = remainder.find("{")
        if body_offset < 0:
            continue
        before_body = header[: match.end() + body_offset]
        body_line = index + before_body.count("\n")
        body_column = len(before_body.rsplit("\n", 1)[-1])
        depth = 0
        end = body_line
        for cursor in range(body_line, len(lines)):
            raw = lines[cursor][body_column:] if cursor == body_line else lines[cursor]
            code = re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", "", raw.split("//", 1)[0])
            depth += code.count("{") - code.count("}")
            end = cursor
            if depth <= 0:
                break
        parameters = []
        raw_parameters = match.group(2)
        if raw_parameters.lstrip().startswith("{"):
            destructured = raw_parameters.split("}:", 1)[0]
            parameters = list(dict.fromkeys(re.findall(r"\b[A-Za-z_$][\w$]*\b", destructured)))
        else:
            for raw in raw_parameters.split(","):
                name = re.match(r"\s*([A-Za-z_$][\w$]*)", raw)
                if name:
                    parameters.append(name.group(1))
        external_parameters = parameters if re.search(r"\bexport\s+default\b", match.group(0)) else []
        output.append({"name": match.group(1), "parameters": parameters, "external_parameters": external_parameters, "start": index, "end": end})
    return output


def _js_module_name(path: Path, root: Path) -> str:
    return path.relative_to(root).with_suffix("").as_posix()


def _javascript_multihop_hypotheses(files: list[Path], root: Path, repo: str, commit: str, max_depth: int = 4) -> list[Hypothesis]:
    """Trace a bounded subset of ESM/CommonJS calls with function-local taint."""
    modules: dict[str, dict] = {}
    functions: dict[str, dict] = {}
    available_modules = {_js_module_name(item, root) for item in files}
    for filename in files:
        try:
            lines = filename.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        module = _js_module_name(filename, root)
        imports: dict[str, tuple[str, str | None]] = {}

        def target_module(specifier: str) -> str | None:
            if not specifier.startswith("."):
                return None
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(module), specifier))
            if posixpath.splitext(resolved)[1] in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}:
                resolved = posixpath.splitext(resolved)[0]
            if resolved in available_modules:
                return resolved
            index = posixpath.join(resolved, "index")
            return index if index in available_modules else resolved

        for line in lines:
            named = re.search(r"\bimport\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]", line)
            if named and (target := target_module(named.group(2))):
                for item in named.group(1).split(","):
                    parts = re.split(r"\s+as\s+", item.strip())
                    if parts and parts[0]:
                        imports[parts[-1]] = (target, parts[0])
            namespace = re.search(r"\bimport\s+\*\s+as\s+([\w$]+)\s+from\s*['\"]([^'\"]+)['\"]", line)
            if namespace and (target := target_module(namespace.group(2))):
                imports[namespace.group(1)] = (target, None)
            common_named = re.search(r"\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]", line)
            if common_named and (target := target_module(common_named.group(2))):
                for item in common_named.group(1).split(","):
                    parts = re.split(r"\s*:\s*", item.strip())
                    if parts and parts[0]:
                        imports[parts[-1]] = (target, parts[0])
            common_namespace = re.search(r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]", line)
            if common_namespace and (target := target_module(common_namespace.group(2))):
                imports[common_namespace.group(1)] = (target, None)
        modules[module] = {"path": filename.relative_to(root).as_posix(), "lines": lines, "imports": imports}
        for block in _js_function_blocks(lines):
            functions[f'{module}:{block["name"]}'] = {**modules[module], **block, "module": module}

    def resolve(info: dict, name: str) -> str | None:
        if "." in name:
            head, tail = name.split(".", 1)
            imported = info["imports"].get(head)
            return f"{imported[0]}:{tail}" if imported and imported[1] is None else None
        imported = info["imports"].get(name)
        if imported and imported[1]:
            return f"{imported[0]}:{imported[1]}"
        local = f'{info["module"]}:{name}'
        return local if local in functions else None

    def analyze(info: dict) -> tuple[dict[str, tuple[str, int, str]], list[dict], list[dict]]:
        external = set(info.get("external_parameters", []))
        origins = {name: ("__external__" if name in external else name, info["start"] + 1, info["lines"][info["start"]]) for name in info["parameters"]}
        sinks, calls = [], []
        for offset in range(info["start"], info["end"] + 1):
            line, number = info["lines"][offset], offset + 1
            assignment = re.search(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)", line)
            if assignment:
                value = assignment.group(2)
                if JS_SOURCE.search(value):
                    origins[assignment.group(1)] = ("__external__", number, line)
                else:
                    inherited = next((origins[name] for name in _js_refs(value) if name in origins), None)
                    if inherited:
                        origins[assignment.group(1)] = inherited
            for kind, pattern in JS_SINKS:
                match = pattern.search(line)
                if match:
                    argument = line[match.end():]
                    origin = ("__external__", number, line) if JS_SOURCE.search(argument) else next((origins[name] for name in _js_refs(argument) if name in origins), None)
                    if origin:
                        sinks.append({"parameter": origin[0], "source_line": origin[1], "source_code": origin[2], "kind": kind, "sink_line": number, "sink_code": line, "sink_path": info["path"], "trace": [{"role": "sink", "path": info["path"], "line": number, "function": info["name"], "code": line.strip()[:240]}]})
            for call in re.finditer(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(([^;]*)\)", line):
                callee = resolve(info, call.group(1))
                if callee and callee != f'{info["module"]}:{info["name"]}':
                    calls.append({"callee": callee, "arguments": [item.strip() for item in call.group(2).split(",")], "line": number, "code": line})
        return origins, sinks, calls

    analyzed = {key: analyze(info) for key, info in functions.items()}
    summaries = {key: list(value[1]) for key, value in analyzed.items()}
    for _ in range(max_depth):
        changed = False
        for key, info in functions.items():
            origins, _, calls = analyzed[key]
            for call in calls:
                if call["callee"] not in functions:
                    continue
                parameters = functions[call["callee"]]["parameters"]
                supplied = {parameters[index]: value for index, value in enumerate(call["arguments"]) if index < len(parameters)}
                for downstream in summaries[call["callee"]]:
                    argument = supplied.get(downstream["parameter"])
                    if argument is None:
                        continue
                    origin = ("__external__", call["line"], call["code"]) if JS_SOURCE.search(argument) else next((origins[name] for name in _js_refs(argument) if name in origins), None)
                    if not origin:
                        continue
                    propagated = {**downstream, "parameter": origin[0], "source_line": origin[1], "source_code": origin[2], "trace": [{"role": "call", "path": info["path"], "line": call["line"], "function": info["name"], "callee": call["callee"], "code": call["code"].strip()[:240]}, *downstream["trace"]]}
                    identity = (propagated["parameter"], propagated["kind"], propagated["sink_path"], propagated["sink_line"], tuple(step.get("callee") for step in propagated["trace"]))
                    existing = {(item["parameter"], item["kind"], item["sink_path"], item["sink_line"], tuple(step.get("callee") for step in item["trace"])) for item in summaries[key]}
                    if identity not in existing:
                        summaries[key].append(propagated)
                        changed = True
        if not changed:
            break

    output = []
    for key, info in functions.items():
        for finding in summaries[key]:
            if finding["parameter"] != "__external__":
                continue
            trace = [{"role": "source", "path": info["path"], "line": finding["source_line"], "function": info["name"], "code": finding["source_code"].strip()[:240]}, *finding["trace"]]
            output.append(_hypothesis(repo, commit, finding["kind"], info["path"], finding["source_line"], finding["sink_line"], finding["source_code"], finding["sink_code"], info["name"], source_path=info["path"], sink_path=finding["sink_path"], entry_kind="modeled_request", trace=trace))
    return output


def _go_function_blocks(lines: list[str]) -> list[dict]:
    pattern = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)[^{]*\{")
    output = []
    for index, line in enumerate(lines):
        match = pattern.search(line)
        if not match:
            continue
        depth, end = 0, index
        for cursor in range(index, len(lines)):
            code = re.sub(r'`[^`]*`|"(?:\\.|[^"\\])*"', "", lines[cursor].split("//", 1)[0])
            depth += code.count("{") - code.count("}")
            end = cursor
            if depth <= 0:
                break
        parameters = []
        external_parameters = []
        pending = []
        for raw in match.group(2).split(","):
            parts = raw.strip().split()
            if len(parts) == 1 and parts[0]:
                pending.append(parts[0])
            elif len(parts) >= 2:
                parameters.extend(pending)
                if re.search(r"(?:^|[.*])(?:[A-Za-z_]\w*)?Request$", parts[-1]):
                    external_parameters.extend(pending)
                    external_parameters.append(parts[0])
                pending = []
                parameters.append(parts[0])
        output.append({"name": match.group(1), "parameters": parameters, "external_parameters": external_parameters, "start": index, "end": end})
    return output


def _go_refs(value: str) -> list[str]:
    without_literals = re.sub(r'`[^`]*`|"(?:\\.|[^"\\])*"', "", value)
    return list(dict.fromkeys(re.findall(r"\b[A-Za-z_]\w*\b", without_literals)))


def _go_arguments(value: str) -> list[str]:
    arguments, current, depth, quote, escaped = [], [], 0, None, False
    for char in value:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\" and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
        elif char in {'"', '`'}:
            quote = char
            current.append(char)
        elif char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            if depth == 0 and char == ")":
                break
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        arguments.append("".join(current).strip())
    return arguments


def _go_multihop_hypotheses(files: list[Path], root: Path, repo: str, commit: str, max_depth: int = 4) -> list[Hypothesis]:
    """Trace bounded local Go calls from modeled HTTP/CLI inputs to selected sinks."""
    module_path = ""
    try:
        module_match = re.search(r"(?m)^\s*module\s+(\S+)", (root / "go.mod").read_text(encoding="utf-8"))
        module_path = module_match.group(1) if module_match else ""
    except (OSError, UnicodeError):
        pass
    functions: dict[str, dict] = {}
    file_records = []
    for filename in files:
        try:
            lines = filename.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        directory = filename.relative_to(root).parent.as_posix()
        if directory == ".":
            directory = ""
        imports: dict[str, str] = {}
        package_imports: dict[str, str] = {}
        import_block = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("import ("):
                import_block = True
                payload = stripped[len("import "):]
            elif stripped.startswith("import "):
                payload = stripped[len("import "):]
            elif import_block:
                payload = stripped
            else:
                continue
            if ")" in payload:
                import_block = False
            for match in re.finditer(r'(?:([A-Za-z_]\w*|[._])\s+)?"([^"]+)"', payload):
                imported = match.group(2)
                alias = match.group(1) or imported.rsplit("/", 1)[-1]
                if alias not in {"_", "."}:
                    package_imports[alias] = imported
                if module_path and alias not in {"_", "."} and (imported == module_path or imported.startswith(module_path + "/")):
                    local = imported[len(module_path):].lstrip("/")
                    imports[alias] = local
        path = filename.relative_to(root).as_posix()
        record = {"path": path, "lines": lines, "directory": directory, "imports": imports, "package_imports": package_imports}
        file_records.append(record)
        for block in _go_function_blocks(lines):
            functions[f'{directory}:{block["name"]}'] = {**record, **block}

    def resolve(info: dict, name: str) -> str | None:
        if "." in name:
            head, tail = name.split(".", 1)
            target = info["imports"].get(head)
            return f"{target}:{tail}" if target is not None else None
        local = f'{info["directory"]}:{name}'
        return local if local in functions else None

    def imported_call(info: dict, package: str, functions: str, line: str, shadowed: set[str]) -> re.Match | None:
        aliases = [alias for alias, imported in info["package_imports"].items() if imported == package and alias not in shadowed]
        if not aliases:
            return None
        return re.search(rf"\b(?:{'|'.join(map(re.escape, aliases))})\.(?:{functions})\s*\((.*)", line)

    def sink_for(info: dict, line: str, shadowed: set[str]) -> tuple[str, str] | None:
        unverified = re.search(r"\b(?:[A-Za-z_]\w*\.)?ParseUnverified\s*\((.*)", line)
        if unverified:
            arguments = _go_arguments(unverified.group(1))
            if arguments:
                return "authentication_bypass", arguments[0]
        shell = imported_call(info, "os/exec", r"Command(?:Context)?", line, shadowed)
        if shell:
            arguments = _go_arguments(shell.group(1))
            offset = 1 if "CommandContext" in shell.group(0) else 0
            if len(arguments) >= offset + 3 and arguments[offset].strip('`"') in {"sh", "/bin/sh", "bash", "/bin/bash"} and arguments[offset + 1].strip('`"') in {"-c", "-lc"}:
                return "command_injection", arguments[offset + 2]
        request = imported_call(info, "net/http", r"Get|Post|Head", line, shadowed)
        if request:
            arguments = _go_arguments(request.group(1))
            if arguments:
                return "possible_ssrf", arguments[0]
        new_request = imported_call(info, "net/http", r"NewRequest(?:WithContext)?", line, shadowed)
        if new_request:
            arguments = _go_arguments(new_request.group(1))
            url_index = 2 if "WithContext" in new_request.group(0) else 1
            if len(arguments) > url_index:
                return "possible_ssrf", arguments[url_index]
        sql = re.search(r"\b(?:Query|QueryRow|Exec)(Context)?\s*\((.*)", line)
        if sql:
            arguments = _go_arguments(sql.group(2))
            query_index = 1 if sql.group(1) else 0
            if len(arguments) > query_index and not arguments[query_index].lstrip().startswith(('"', '`')):
                return "sql_injection", arguments[query_index]
        filesystem = imported_call(info, "os", r"Open|ReadFile|WriteFile|Create", line, shadowed)
        if filesystem:
            arguments = _go_arguments(filesystem.group(1))
            if arguments:
                return "path_traversal", arguments[0]
        return None

    def analyze(info: dict) -> tuple[dict[str, tuple[str, int, str]], list[dict], list[dict]]:
        external = set(info.get("external_parameters", []))
        origins = {name: ("__external__" if name in external else name, info["start"] + 1, info["lines"][info["start"]]) for name in info["parameters"]}
        sinks, calls = [], []
        shadowed = set(info["parameters"]) & set(info["package_imports"])
        for offset in range(info["start"], info["end"] + 1):
            line, number = info["lines"][offset], offset + 1
            local_declaration = re.search(r"\b([A-Za-z_]\w*)\s*:=|\bvar\s+([A-Za-z_]\w*)\b", line)
            if local_declaration:
                local_name = local_declaration.group(1) or local_declaration.group(2)
                if local_name in info["package_imports"]:
                    shadowed.add(local_name)
            assignment = re.search(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*(.+)", line)
            if assignment:
                value = assignment.group(2)
                if GO_SOURCE.search(value):
                    origins[assignment.group(1)] = ("__external__", number, line)
                else:
                    inherited = next((origins[name] for name in _go_refs(value) if name in origins), None)
                    if inherited:
                        origins[assignment.group(1)] = inherited
            sink = sink_for(info, line, shadowed)
            if sink:
                kind, argument = sink
                origin = ("__external__", number, line) if GO_SOURCE.search(argument) else next((origins[name] for name in _go_refs(argument) if name in origins), None)
                if origin:
                    sinks.append({"parameter": origin[0], "source_line": origin[1], "source_code": origin[2], "kind": kind, "sink_line": number, "sink_code": line, "sink_path": info["path"], "trace": [{"role": "sink", "path": info["path"], "line": number, "function": info["name"], "code": line.strip()[:240]}]})
            for call in re.finditer(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\((.*)", line):
                callee = resolve(info, call.group(1))
                if callee and callee != f'{info["directory"]}:{info["name"]}':
                    calls.append({"callee": callee, "arguments": _go_arguments(call.group(2)), "line": number, "code": line})
        return origins, sinks, calls

    analyzed = {key: analyze(info) for key, info in functions.items()}
    summaries = {key: list(result[1]) for key, result in analyzed.items()}
    for _ in range(max_depth):
        changed = False
        for key, info in functions.items():
            origins, _, calls = analyzed[key]
            for call in calls:
                if call["callee"] not in functions:
                    continue
                parameters = functions[call["callee"]]["parameters"]
                supplied = {parameters[index]: value for index, value in enumerate(call["arguments"]) if index < len(parameters)}
                for downstream in summaries[call["callee"]]:
                    argument = supplied.get(downstream["parameter"])
                    if argument is None:
                        continue
                    origin = ("__external__", call["line"], call["code"]) if GO_SOURCE.search(argument) else next((origins[name] for name in _go_refs(argument) if name in origins), None)
                    if not origin:
                        continue
                    propagated = {**downstream, "parameter": origin[0], "source_line": origin[1], "source_code": origin[2], "trace": [{"role": "call", "path": info["path"], "line": call["line"], "function": info["name"], "callee": call["callee"], "code": call["code"].strip()[:240]}, *downstream["trace"]]}
                    identity = (propagated["parameter"], propagated["kind"], propagated["sink_path"], propagated["sink_line"], tuple(step.get("callee") for step in propagated["trace"]))
                    existing = {(item["parameter"], item["kind"], item["sink_path"], item["sink_line"], tuple(step.get("callee") for step in item["trace"])) for item in summaries[key]}
                    if identity not in existing:
                        summaries[key].append(propagated)
                        changed = True
        if not changed:
            break

    output = []
    for key, info in functions.items():
        for finding in summaries[key]:
            if finding["parameter"] != "__external__":
                continue
            trace = [{"role": "source", "path": info["path"], "line": finding["source_line"], "function": info["name"], "code": finding["source_code"].strip()[:240]}, *finding["trace"]]
            output.append(_hypothesis(repo, commit, finding["kind"], info["path"], finding["source_line"], finding["sink_line"], finding["source_code"], finding["sink_code"], info["name"], source_path=info["path"], sink_path=finding["sink_path"], entry_kind="modeled_request", trace=trace))
    return output


def _c_source_variable(line: str) -> str | None:
    assignment = re.search(r"\b([A-Za-z_]\w*)\s*=\s*[^;]*(?:getenv|getopt|getopt_long)\s*\(|\b([A-Za-z_]\w*)\s*=\s*argv\s*\[", line)
    if assignment:
        return assignment.group(1) or assignment.group(2)
    received = re.search(r"\b([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*(?:receive|recv|read)[A-Za-z_]*\s*\(", line, re.I)
    if received:
        return received.group(1)
    call = re.search(r"\b(?:recv|recvfrom|read)\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)", line)
    if call:
        return call.group(1)
    call = re.search(r"\b(?:fgets|gets)\s*\(\s*([A-Za-z_]\w*)", line)
    if call:
        return call.group(1)
    scan = re.search(r"\b(?:scanf|sscanf)\s*\([^;]*,\s*&?([A-Za-z_]\w*)\s*\)", line)
    return scan.group(1) if scan else None


def _c_bounded_size(expression: str, destination: str, capacity: int) -> bool:
    compact = re.sub(r"\s+", "", expression)
    if compact in {f"sizeof({destination})", f"sizeof{destination}"}:
        return True
    return compact.isdigit() and int(compact) <= capacity


def _c_length_guarded(lines: list[str], start: int, end: int, length: str, destination: str, capacity: int) -> bool:
    if not re.fullmatch(r"[A-Za-z_]\w*", length.strip()):
        return False
    window = "\n".join(lines[start:end])
    limit = rf"(?:sizeof\s*\(\s*{re.escape(destination)}\s*\)|{capacity})"
    check = re.search(rf"\b{re.escape(length.strip())}\b\s*(?:>|>=)\s*{limit}", window)
    return bool(check and re.search(r"\b(?:return|goto|break)\b", window[check.end():]))


def _c_memory_hypotheses(lines: list[str], path: str, repo: str, commit: str) -> list[Hypothesis]:
    output = []
    recent: list[tuple[int, str, str]] = []
    buffers: dict[str, tuple[int, int]] = {}
    function = "c_scope_unknown"
    function_start = 0
    brace_depth = 0
    signature = re.compile(r"^\s*(?!if\b|for\b|while\b|switch\b)(?:[A-Za-z_]\w*[\s*&]+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{")
    for number, line in enumerate(lines, 1):
        match = signature.search(line)
        if match:
            function = match.group(1)
            function_start = number - 1
            recent = []
            buffers = {}
            brace_depth = 0
        brace_depth += line.count("{") - line.count("}")
        declaration = re.search(r"\b(?:char|unsigned\s+char|uint8_t)\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]", line)
        if declaration:
            buffers[declaration.group(1)] = (int(declaration.group(2)), number)
        source_variable = _c_source_variable(line)
        if source_variable and (C_RETURN_SOURCE.search(line) or C_BUFFER_SOURCE.search(line)):
            recent.append((number, line, source_variable))
        recent = [item for item in recent if number - item[0] <= 80]

        call = re.search(r"\b(memcpy|memmove|read|recv|recvfrom|fgets|gets|scanf)\s*\((.*)", line)
        if call:
            name, arguments = call.group(1), _go_arguments(call.group(2))
            destination = ""
            length = ""
            if name in {"memcpy", "memmove", "read", "recv", "recvfrom"} and len(arguments) >= 3:
                destination, length = arguments[0 if name in {"memcpy", "memmove"} else 1], arguments[2]
            elif name == "fgets" and len(arguments) >= 2:
                destination, length = arguments[0], arguments[1]
            elif name == "gets" and arguments:
                destination = arguments[0]
            elif name == "scanf" and len(arguments) >= 2:
                destination = arguments[1].lstrip("&").strip()
                format_value = arguments[0].strip()
                width = re.search(r"%(\d+)s", format_value)
                if "%s" not in format_value and not width:
                    destination = ""
                elif width:
                    length = width.group(1)
            destination = destination.strip()
            if destination in buffers:
                capacity, declaration_line = buffers[destination]
                source = next((item for item in reversed(recent) if item[2] in _go_refs(" ".join(arguments[1:]))), None)
                unsafe = name == "gets"
                if name == "scanf":
                    unsafe = not length or int(length) >= capacity
                elif name in {"read", "recv", "recvfrom", "fgets"}:
                    compact = re.sub(r"\s+", "", length)
                    unsafe = compact.isdigit() and int(compact) > capacity or compact.startswith(f"sizeof({destination})+")
                    length_source = next((item for item in reversed(recent) if item[2] != destination and item[2] in _go_refs(length)), None)
                    if not unsafe and length_source and not _c_length_guarded(lines, function_start, number - 1, length, destination, capacity):
                        unsafe = True
                elif name in {"memcpy", "memmove"}:
                    tainted = source is not None
                    unsafe = tainted and not _c_bounded_size(length, destination, capacity) and not _c_length_guarded(lines, max(function_start, (source or (declaration_line, "", ""))[0] - 1), number - 1, length, destination, capacity)
                if unsafe:
                    source_line, source_code = (source[0], source[1]) if source else (number, line)
                    trace = [
                        {"role": "source", "path": path, "line": source_line, "function": function, "code": source_code.strip()[:240]},
                        {"role": "fixed_buffer", "path": path, "line": declaration_line, "function": function, "code": lines[declaration_line - 1].strip()[:240]},
                        {"role": "write", "path": path, "line": number, "function": function, "code": line.strip()[:240]},
                    ]
                    output.append(_hypothesis(repo, commit, "buffer_overflow", path, source_line, number, source_code, line, function, entry_kind="modeled_external_input", trace=trace))
        propagation = re.search(r"\b[A-Za-z_]\w*\s*\((.*)", line)
        if propagation:
            references = _go_refs(re.sub(r"\bsizeof\s*\([^)]*\)", "", propagation.group(1)))
            if any(item[2] in references for item in recent):
                excluded = {"char", "const", "int", "long", "null", "short", "signed", "size_t", "sizeof", "strlen", "struct", "unsigned", "void"}
                for candidate in references:
                    if candidate.lower() not in excluded and not any(item[2] == candidate for item in recent):
                        recent.append((number, line, candidate))
        if function != "c_scope_unknown" and brace_depth <= 0:
            function = "c_scope_unknown"
            buffers = {}
            recent = []
    return output


def _c_hypotheses(filename: Path, root: Path, repo: str, commit: str) -> list[Hypothesis]:
    try:
        lines = filename.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    path = filename.relative_to(root).as_posix()
    recent: list[tuple[int, str, str]] = []
    output = []
    function = "c_scope_unknown"
    brace_depth = 0
    signature = re.compile(r"^\s*(?!if\b|for\b|while\b|switch\b)(?:[A-Za-z_]\w*[\s*&]+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{")
    for number, line in enumerate(lines, 1):
        function_match = signature.search(line)
        if function_match:
            function = function_match.group(1)
            recent = []
            brace_depth = 0
        brace_depth += line.count("{") - line.count("}")
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
                length_guard = re.search(r"\bstrlen\s*\(\s*(?:\([^)]*\)\s*)?" + re.escape(source[2]) + r"\s*\)[^;\n]{0,160}(?:>=|>)\s*sizeof\s*\(", between)
                if kind == "unsafe_copy" and length_guard and re.search(r"\b(?:return|goto)\b", between[length_guard.start() :]):
                    continue
                output.append(_hypothesis(repo, commit, kind, path, source[0], number, source[1], line, function))
        propagation = re.search(r"\b[A-Za-z_]\w*\s*\((.*)", line)
        if propagation:
            references = _go_refs(re.sub(r"\bsizeof\s*\([^)]*\)", "", propagation.group(1)))
            if any(item[2] in references for item in recent):
                excluded = {"char", "const", "int", "long", "null", "short", "signed", "size_t", "sizeof", "strlen", "struct", "unsigned", "void"}
                for candidate in references:
                    if candidate.lower() not in excluded and not any(item[2] == candidate for item in recent):
                        recent.append((number, line, candidate))
        if function != "c_scope_unknown" and brace_depth <= 0:
            function = "c_scope_unknown"
            recent = []
    output.extend(_c_memory_hypotheses(lines, path, repo, commit))
    return output


class SourceScanAgent:
    """Conservative entry-to-sink hypotheses, not vulnerability verdicts."""
    def run(self, root: Path, repo: str, commit: str, max_files: int = 20_000, priority_paths: set[str] | None = None) -> tuple[list[Hypothesis], dict]:
        root = root.resolve()
        if not root.is_dir():
            raise ValueError("조사 대상 디렉터리가 없습니다")
        output: list[Hypothesis] = []
        python_files: list[Path] = []
        javascript_files: list[Path] = []
        go_files: list[Path] = []
        supported_files = []
        for filename in root.rglob("*"):
            try:
                if any(x in IGNORED_DIRS for x in filename.relative_to(root).parts) or not filename.is_file() or filename.is_symlink() or filename.stat().st_size > 500_000:
                    continue
            except OSError:
                continue
            workflow = filename.suffix in {".yml", ".yaml"} and ".github" in filename.relative_to(root).parts and "workflows" in filename.relative_to(root).parts
            if filename.suffix not in {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".go", *C_EXTENSIONS} and not workflow:
                continue
            supported_files.append(filename)
        priority_paths = {Path(path).as_posix() for path in (priority_paths or set())}
        supported_files.sort(key=lambda item: (item.relative_to(root).as_posix() not in priority_paths, item.relative_to(root).as_posix()))
        selected_files = supported_files[:max(0, max_files)]
        truncated = len(selected_files) < len(supported_files)
        priority_scanned = 0
        for filename in selected_files:
            if filename.relative_to(root).as_posix() in priority_paths:
                priority_scanned += 1
            if filename.suffix == ".py":
                python_files.append(filename)
                output.extend(_python_hypotheses(filename, root, repo, commit))
                output.extend(_python_interprocedural_hypotheses(filename, root, repo, commit))
                output.extend(_python_toctou_hypotheses(filename, root, repo, commit))
                output.extend(_python_authorization_hypotheses(filename, root, repo, commit))
                output.extend(_python_concurrency_hypotheses(filename, root, repo, commit))
            elif filename.suffix in C_EXTENSIONS:
                output.extend(_c_hypotheses(filename, root, repo, commit))
            elif filename.suffix == ".go":
                go_files.append(filename)
            elif filename.suffix in {".yml", ".yaml"}:
                output.extend(_workflow_hypotheses(filename, root, repo, commit))
            else:
                javascript_files.append(filename)
        multihop_limit = min(len(python_files), 5_000)
        javascript_limit = min(len(javascript_files), 5_000)
        go_limit = min(len(go_files), 5_000)
        output.extend(_python_multihop_hypotheses(python_files[:multihop_limit], root, repo, commit))
        output.extend(_javascript_multihop_hypotheses(javascript_files[:javascript_limit], root, repo, commit))
        output.extend(_go_multihop_hypotheses(go_files[:go_limit], root, repo, commit))
        return sorted({x.id: x for x in output}.values(), key=lambda x: (x.path, x.sink_line)), {"files_inspected": len(selected_files), "eligible_files": len(supported_files), "files_skipped_by_limit": len(supported_files) - len(selected_files), "truncated": truncated, "priority_files_requested": len(priority_paths), "priority_files_scanned": priority_scanned, "selection_strategy": "recent_changes_first_then_path", "languages": ["python", "javascript/typescript", "go", "c/c++", "github-actions"], "python_multihop_files": multihop_limit, "python_multihop_truncated": len(python_files) > multihop_limit, "javascript_multihop_files": javascript_limit, "javascript_multihop_truncated": len(javascript_files) > javascript_limit, "go_multihop_files": go_limit, "go_multihop_truncated": len(go_files) > go_limit, "go_symbol_resolution": "import_path_alias_and_conservative_shadowing", "c_memory_model": "fixed_stack_buffers_and_bounded_writes"}


class SemanticAnalysisAgent:
    """Prioritize hypotheses and allow automatic reproduction only for bounded safe templates."""
    SCORES = {"buffer_overflow": 92, "command_injection": 90, "workflow_injection": 88, "authentication_bypass": 85, "code_execution": 85, "privilege_assignment": 84, "authorization_scope_candidate": 82, "template_injection": 80, "sql_injection": 75, "concurrency_race_candidate": 72, "unsafe_deserialization": 70, "toctou_candidate": 68, "path_traversal": 65, "possible_ssrf": 60, "format_string": 55, "unsafe_copy": 50}

    def run(self, hypotheses: list[dict], profile: dict | None = None) -> list[dict]:
        changed = (profile or {}).get("recent_changes", {}).get("files", {})
        output = []
        for finding in hypotheses:
            suffix = Path(finding.get("path", "")).suffix
            python_supported = suffix == ".py" and (
                finding.get("kind") in {"command_injection", "code_execution"}
                or finding.get("kind") == "possible_ssrf" and (finding.get("source_path") or finding.get("path")) == (finding.get("sink_path") or finding.get("path"))
            )
            javascript_supported = suffix in {".js", ".mjs", ".cjs"} and finding.get("kind") in {"command_injection", "code_execution"} and (finding.get("source_path") or finding.get("path")) == (finding.get("sink_path") or finding.get("path"))
            go_supported = suffix == ".go" and finding.get("kind") == "command_injection" and (finding.get("source_path") or finding.get("path")) == (finding.get("sink_path") or finding.get("path"))
            supported = python_supported or javascript_supported or go_supported
            score = self.SCORES.get(finding.get("kind"), 40)
            reasons = [f"{finding.get('kind')} 기본 위험도 {score}"]
            if finding.get("function") and finding["function"] != "javascript_scope_unknown":
                score += 5
                reasons.append("함수 경계 식별 +5")
            touched = max(changed.get(finding.get("source_path") or finding.get("path"), 0), changed.get(finding.get("sink_path") or finding.get("path"), 0))
            if touched:
                boost = min(10, 4 + touched)
                score += boost
                reasons.append(f"최근 커밋 변경 경로 +{boost}")
            if len(finding.get("trace", [])) >= 3:
                score += 3
                reasons.append("호출 경로 근거 +3")
            runtime = "Python" if python_supported else "JavaScript" if javascript_supported else "Go" if go_supported else ""
            output.append({**finding, "priority": min(score, 100), "priority_reasons": reasons, "auto_reproduction_supported": supported, "automation_reason": f"제한된 {runtime} 실제 함수 호출 템플릿 지원" if supported else "이 언어·취약점 유형의 안전한 자동 PoC 템플릿이 없음"})
        return sorted(output, key=lambda item: (-item["priority"], item.get("path", ""), item.get("sink_line", 0)))


class ReachabilityGateAgent:
    """Require a cited external entry and reject clearly disconnected hypotheses."""
    def run(self, finding: dict, profile: dict) -> dict:
        trace = finding.get("trace") or []
        source = trace[0] if trace else {}
        entry_kind = finding.get("entry_kind", "")
        matching_entry = next((item for item in profile.get("entrypoints", []) if item.get("path") == source.get("path") and abs(int(item.get("line", 0)) - int(source.get("line", 0))) <= 5), None)
        if entry_kind == "http_route" or matching_entry and matching_entry.get("kind") in {"http", "cli", "message"}:
            return {"status": "pass", "verdict": "DEFAULT_REACHABLE", "entry_kind": entry_kind or matching_entry["kind"], "evidence": source, "reason": "기본 코드 경로의 외부 엔트리포인트에서 위험 동작까지 추적됨"}
        if entry_kind == "modeled_request" and source:
            return {"status": "pass", "verdict": "EXTERNAL_INPUT_REACHABLE", "entry_kind": entry_kind, "evidence": source, "reason": "지원되는 request/CLI 입력 모델에서 위험 동작까지 추적됨"}
        return {"status": "uncertain", "verdict": "REVIEW_REQUIRED", "entry_kind": entry_kind or "unknown", "evidence": source, "reason": "기본 설정에서 호출되는 외부 엔트리포인트를 기계적으로 확인하지 못함"}


class EvidenceGateAgent:
    """Apply explicit evidence gates before a private draft can be generated."""
    HIGH_IMPACT = {"buffer_overflow", "command_injection", "workflow_injection", "authentication_bypass", "privilege_assignment", "authorization_scope_candidate", "concurrency_race_candidate", "code_execution", "template_injection", "sql_injection", "unsafe_deserialization", "unsafe_copy", "format_string"}

    def run(self, audit_data: dict, finding: dict, reachability: dict, evidence: dict, duplicate_review: dict) -> dict:
        trace = finding.get("trace") or []
        external = reachability.get("status") == "pass"
        criteria = {
            "C1_external_reachability": "PASS" if external and len(trace) >= 2 else "UNCERTAIN",
            "C2_default_configuration": "PASS" if reachability.get("verdict") == "DEFAULT_REACHABLE" else "PARTIAL" if external else "UNCERTAIN",
            "C3_attacker_control": "PASS" if evidence.get("mechanical_result") == "contrast_matched" and external else "UNCERTAIN",
            "C4_security_impact": "PASS" if finding.get("kind") in self.HIGH_IMPACT else "PARTIAL",
            "C5_no_known_duplicate": "PASS" if duplicate_review.get("status") == "no_match_in_collected_snapshot" and audit_data.get("public_context", {}).get("status") == "snapshot" else "FAIL" if duplicate_review.get("status") == "possible_duplicate" else "UNCERTAIN",
        }
        if "FAIL" in criteria.values():
            verdict = "REBUTTED"
        elif "UNCERTAIN" in criteria.values():
            verdict = "NEEDS_MORE_EVIDENCE"
        elif "PARTIAL" in criteria.values():
            verdict = "CONFIRMED_LOW"
        else:
            verdict = "CONFIRMED"
        return {"status": "complete", "verdict": verdict, "criteria": criteria, "manual_review_required": True}


class BuildEnvironmentAgent:
    """Resolve a pinned local runtime without installing target dependencies."""
    def run(self, checkout_root: Path, finding: dict) -> dict:
        suffix = Path(finding["path"]).suffix
        if suffix == ".py":
            manifests = [name for name in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt") if (checkout_root / name).is_file()]
            return {"status": "ready", "runtime": "python", "executable": sys.executable, "image": "python:3.11-slim", "manifests": manifests, "default_execution": "limited_process", "dependency_install": "disabled"}
        if suffix in {".js", ".mjs", ".cjs"}:
            executable = shutil.which("node")
            if not executable:
                return {"status": "unsupported", "reason": "로컬 Node.js 런타임을 찾지 못했습니다"}
            manifests = [name for name in ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml") if (checkout_root / name).is_file()]
            return {"status": "ready", "runtime": "javascript", "executable": executable, "image": "node:22-slim", "manifests": manifests, "default_execution": "limited_process", "dependency_install": "disabled"}
        if suffix == ".go":
            executable = shutil.which("go")
            if not executable:
                return {"status": "unsupported", "reason": "로컬 Go 런타임을 찾지 못했습니다"}
            manifests = [name for name in ("go.mod", "go.sum") if (checkout_root / name).is_file()]
            return {"status": "ready", "runtime": "go", "executable": executable, "image": "golang:1.26-alpine", "manifests": manifests, "default_execution": "limited_process", "dependency_install": "disabled"}
        return {"status": "unsupported", "reason": "현재 자동 빌드 환경은 제한된 Python·JavaScript 후보만 지원합니다"}


class LimitedPocAgent:
    """Generate harmless marker-based reproductions for a small runtime allowlist."""
    def run(self, audit_file: Path, finding: dict, environment: dict) -> Path:
        audit_data, current = load_hypothesis(audit_file, finding["id"])
        if current["path"] != finding["path"] or not finding.get("auto_reproduction_supported"):
            raise ValueError("자동 PoC 허용 범위 밖의 후보입니다")
        checkout_root = Path(audit_data["checkout"]).resolve()
        source_file = (checkout_root / finding["path"]).resolve()
        if not source_file.is_relative_to(checkout_root) or not source_file.is_file():
            raise ValueError("PoC 대상 파일이 조사 체크아웃 안에 없습니다")
        destination = audit_file.parent / finding["id"]
        destination.mkdir(parents=True, exist_ok=True)
        manifest_path = destination / "manifest.json"
        if manifest_path.exists():
            raise ValueError("기존 PoC 작업물이 있어 자동 생성으로 덮어쓰지 않습니다")
        marker = "OSS_PROOF_" + secrets.token_hex(8)
        kind = finding["kind"]
        if environment.get("runtime") == "go":
            try:
                source_text = source_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise ValueError("PoC 대상 Go 파일을 읽을 수 없습니다") from exc
            blocks = _go_function_blocks(source_text.splitlines())
            target = [block for block in blocks if block["name"] == finding["function"]]
            import_sections = re.findall(r"\bimport\s*(?:\((.*?)\)|\"([^\"]+)\")", source_text, re.S)
            imports = []
            for grouped, single in import_sections:
                imports.extend(re.findall(r'"([^"]+)"', grouped) if grouped else [single])
            signature = re.search(rf"\bfunc\s+{re.escape(finding['function'])}\s*\([^)]*\*http\.Request[^)]*\)", source_text, re.S)
            form_key = re.search(r'\br\.(?:FormValue|PostFormValue)\s*\(\s*"([^"]+)"', source_text)
            if len(blocks) != 1 or len(target) != 1 or not signature or not form_key or any("." in value.split("/", 1)[0] for value in imports):
                raise ValueError("자동 Go PoC는 표준 라이브러리만 쓰는 단일 함수 HTTP 핸들러로 제한됩니다")
            package_match = re.search(r"(?m)^\s*package\s+([A-Za-z_]\w*)", source_text)
            if not package_match:
                raise ValueError("Go 패키지 이름을 확인할 수 없습니다")
            proof = destination / "proof.py"
            if proof.exists():
                raise ValueError("기존 PoC 작업물이 있어 자동 생성으로 덮어쓰지 않습니다")
            go_test = f'''package {package_match.group(1)}

import (
    "fmt"
    "net/http/httptest"
    "net/url"
    "os"
    "strconv"
    "strings"
    "testing"
)

func TestOSSSecurityTimelineContrast(t *testing.T) {{
    markerPath := os.Getenv("OSS_POC_SCRATCH") + "/go-marker"
    payload := "printf OSS_BENIGN_CONTROL"
    if os.Args[len(os.Args)-1] == "attack" {{
        payload = "printf {marker} > " + strconv.Quote(markerPath)
    }}
    values := url.Values{{{json.dumps(form_key.group(1))}: []string{{payload}}}}
    request := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
    request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    {finding["function"]}(httptest.NewRecorder(), request)
    if data, err := os.ReadFile(markerPath); err == nil {{
        fmt.Println(string(data))
    }}
}}
'''
            source_sha = hashlib.sha256(source_text.encode()).hexdigest()
            script = f'''import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

repo = Path(os.environ["OSS_POC_REPO"])
scratch = Path(os.environ["OSS_POC_SCRATCH"])
source = repo / {finding["path"]!r}
if hashlib.sha256(source.read_bytes()).hexdigest() != {source_sha!r}:
    raise SystemExit("target source changed")
shutil.copy2(source, scratch / source.name)
(scratch / "oss_security_poc_test.go").write_text({go_test!r}, encoding="utf-8")
go_cache = scratch / "go-cache"
go_tmp = scratch / "go-tmp"
go_cache.mkdir()
go_tmp.mkdir()
env = {{"PATH": os.environ.get("PATH", ""), "OSS_POC_SCRATCH": str(scratch), "GOCACHE": str(go_cache), "GOTMPDIR": str(go_tmp), "GOPROXY": "off", "GOSUMDB": "off", "GO111MODULE": "off"}}
result = subprocess.run(["go", "test", "-v", "-run", "^TestOSSSecurityTimelineContrast$", "-count=1", "-args", sys.argv[1]], cwd=scratch, env=env, capture_output=True, text=True, timeout=20)
print(result.stdout, end="")
print(result.stderr, end="", file=sys.stderr)
raise SystemExit(result.returncode)
'''
            manifest = {"finding_id": finding["id"], "repo_path": audit_data["checkout"], "commit": audit_data["commit"], "image": environment["image"], "proof_file": "proof.py", "attack": ["python3", "proof.py", "attack"], "control": ["python3", "proof.py", "control"], "observable": {"type": "stdout_contains", "value": marker}, "timeout_seconds": 30, "generator": "bounded_go_v1", "target_source_sha256": source_sha}
            proof.write_text(script, encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            return manifest_path
        if environment.get("runtime") == "javascript":
            try:
                source_text = source_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise ValueError("PoC 대상 JavaScript 파일을 읽을 수 없습니다") from exc
            blocks = [block for block in _js_function_blocks(source_text.splitlines()) if block["name"] == finding["function"]]
            imports = re.findall(r"\bfrom\s*['\"]([^'\"]+)['\"]|\brequire\s*\(\s*['\"]([^'\"]+)['\"]", source_text)
            specifiers = [left or right for left, right in imports]
            allowed_builtins = {"child_process", "url", "path", "util", "buffer"}
            if len(blocks) != 1 or not re.search(rf"\bexport\s+default\b[\s\S]{{0,80}}\bfunction\s+{re.escape(finding['function'])}\b", source_text) or any(not value.startswith("node:") and value not in allowed_builtins for value in specifiers):
                raise ValueError("자동 JavaScript PoC는 Node 내장 모듈만 사용하는 단일 default export 함수로 제한됩니다")
            block = blocks[0]
            outside = source_text.splitlines()
            outside = outside[:block["start"]] + outside[block["end"] + 1:]
            if any(line.strip() and not line.lstrip().startswith(("import ", "//")) for line in outside):
                raise ValueError("자동 JavaScript PoC는 import 외 최상위 실행문이 없는 모듈만 호출합니다")
            proof = destination / "proof.mjs"
            if proof.exists():
                raise ValueError("기존 PoC 작업물이 있어 자동 생성으로 덮어쓰지 않습니다")
            attack_value = f"printf {marker}" if kind == "command_injection" else f'console.log("{marker}")'
            source_header = "\n".join(source_text.splitlines()[block["start"] : min(block["end"] + 1, block["start"] + 8)])
            use_proxy = "({" in source_header or bool(JS_SOURCE.search(finding.get("source_code", "")))
            script = f'''import {{ pathToFileURL }} from "node:url";

const repo = process.env.OSS_POC_REPO;
const targetUrl = pathToFileURL(`${{repo}}/{finding["path"]}`).href;
const module = await import(targetUrl);
const target = module.default;
const value = process.argv[2] === "attack" ? {attack_value!r} : "printf OSS_BENIGN_CONTROL";
let proxy;
proxy = new Proxy({{}}, {{ get: (_target, key) => key === Symbol.toPrimitive || key === "toString" ? () => value : proxy }});
const argument = {"proxy" if use_proxy else "value"};
const result = await target(...Array(Math.max(target.length, 1)).fill(argument));
if (result !== undefined) console.log(Buffer.isBuffer(result) ? result.toString() : String(result));
'''
            manifest = {"finding_id": finding["id"], "repo_path": audit_data["checkout"], "commit": audit_data["commit"], "image": environment["image"], "proof_file": "proof.mjs", "attack": ["node", "proof.mjs", "attack"], "control": ["node", "proof.mjs", "control"], "observable": {"type": "stdout_contains", "value": marker}, "timeout_seconds": 30, "generator": "bounded_javascript_v1"}
            proof.write_text(script, encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            return manifest_path
        try:
            syntax = _python_parse(source_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise ValueError("PoC 대상 Python 파일을 다시 분석할 수 없습니다") from exc
        top_level = [node for node in syntax.body if isinstance(node, ast.FunctionDef) and node.name == finding["function"]]
        if len(top_level) != 1:
            raise ValueError("자동 PoC는 모듈 최상위 동기 함수만 호출합니다")
        proof = destination / "proof.py"
        if proof.exists():
            raise ValueError("기존 PoC 작업물이 있어 자동 생성으로 덮어쓰지 않습니다")
        if kind == "possible_ssrf":
            target = top_level[0]
            positional = [*target.args.posonlyargs, *target.args.args]
            allowed_imports = {"requests", "httpx", "urllib", "urllib.request"}
            imports = []
            safe_top_level = True
            for node in syntax.body:
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append(node.module or "")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defaults = [*node.args.defaults, *(value for value in node.args.kw_defaults if value is not None)]
                    annotations = [argument.annotation for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs] if argument.annotation is not None]
                    if node.args.vararg and node.args.vararg.annotation is not None:
                        annotations.append(node.args.vararg.annotation)
                    if node.args.kwarg and node.args.kwarg.annotation is not None:
                        annotations.append(node.args.kwarg.annotation)
                    if node.returns is not None:
                        annotations.append(node.returns)
                    safe_top_level = safe_top_level and not node.decorator_list and not annotations and all(isinstance(value, ast.Constant) for value in defaults)
                elif not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                    safe_top_level = False
            allowed_sinks = {"requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"}
            direct_calls = [node for node in ast.walk(target) if isinstance(node, ast.Call)]
            direct_sink = len(direct_calls) == 1 and _qualified(direct_calls[0].func) in allowed_sinks
            single_call_body = len(target.body) == 1 and isinstance(target.body[0], (ast.Return, ast.Expr)) and getattr(target.body[0], "value", None) is direct_calls[0] if direct_calls else False
            parameter_name = positional[0].arg if len(positional) == 1 else ""
            direct_input = bool(direct_calls and direct_calls[0].args and isinstance(direct_calls[0].args[0], ast.Name) and direct_calls[0].args[0].id == parameter_name)
            if (
                not safe_top_level
                or any(name not in allowed_imports for name in imports)
                or isinstance(target, ast.AsyncFunctionDef)
                or len(positional) != 1
                or target.args.vararg
                or target.args.kwarg
                or target.args.kwonlyargs
                or not direct_sink
                or not single_call_body
                or not direct_input
            ):
                raise ValueError("자동 Python SSRF PoC는 허용된 HTTP import와 단일 직접 sink return을 쓰는 단일 인자 동기 함수로 제한됩니다")
            source_bytes = source_file.read_bytes()
            source_sha = hashlib.sha256(source_bytes).hexdigest()
            script = f'''"""Network-blocked bounded SSRF reproduction for {finding["id"]}."""
import hashlib
import importlib.util
import os
import sys
import types

REPO = os.environ["OSS_POC_REPO"]
MARKER = {marker!r}
TARGET = os.path.join(REPO, {finding["path"]!r})

class DummyResponse:
    status_code = 200
    text = ""
    content = b""
    def json(self):
        return {{}}
    def read(self, *_args, **_kwargs):
        return b""
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False

def blocked_request(url, *_args, **_kwargs):
    value = str(url)
    print(MARKER if MARKER in value else "OSS_BENIGN_CONTROL")
    return DummyResponse()

def install_network_stubs():
    for name in ("requests", "httpx"):
        module = types.ModuleType(name)
        module.get = blocked_request
        module.post = blocked_request
        module.request = lambda _method, url, *_args, **_kwargs: blocked_request(url)
        sys.modules[name] = module
    import urllib.request
    urllib.request.urlopen = blocked_request

def drive(case):
    if hashlib.sha256(open(TARGET, "rb").read()).hexdigest() != {source_sha!r}:
        raise SystemExit("target source changed")
    install_network_stubs()
    spec = importlib.util.spec_from_file_location("oss_target", TARGET)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = "http://127.0.0.1/" + MARKER if case == "attack" else "https://example.invalid/benign"
    getattr(module, {finding["function"]!r})(payload)

if __name__ == "__main__":
    drive(sys.argv[1])
'''
            manifest = {"finding_id": finding["id"], "repo_path": audit_data["checkout"], "commit": audit_data["commit"], "image": environment["image"], "proof_file": "proof.py", "attack": ["python3", "proof.py", "attack"], "control": ["python3", "proof.py", "control"], "observable": {"type": "stdout_contains", "value": marker}, "timeout_seconds": 30, "generator": "bounded_python_ssrf_v1", "target_source_sha256": source_sha, "network_policy": "stubbed_no_real_requests"}
            proof.write_text(script, encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            return manifest_path
        if kind == "command_injection":
            attack_expression = '"printf " + MARKER'
            control_expression = '"printf OSS_BENIGN_CONTROL"'
        else:
            sink_text = finding.get("sink_code", "")
            attack_expression = '("print(" + repr(MARKER) + ")") if "exec(" in SINK else repr(MARKER)'
            control_expression = '"None" if "exec(" in SINK else repr("OSS_BENIGN_CONTROL")'
        script = f'''"""Auto-generated bounded reproduction for {finding["id"]}."""
import importlib.util
import inspect
import os
import sys

REPO = os.environ["OSS_POC_REPO"]
sys.path.insert(0, REPO)
MARKER = {marker!r}
SINK = {finding.get("sink_code", "")!r}

class InputProxy:
    def __init__(self, value):
        self.value = value
    def __getitem__(self, _key):
        return self.value
    def get(self, _key, default=None):
        return self.value
    def getlist(self, _key):
        return [self.value]
    def __getattr__(self, _name):
        return self

def drive(case):
    value = {attack_expression} if case == "attack" else {control_expression}
    target_path = os.path.join(REPO, {finding["path"]!r})
    spec = importlib.util.spec_from_file_location("oss_target", target_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = getattr(module, {finding["function"]!r})
    arguments = []
    for parameter in inspect.signature(target).parameters.values():
        arguments.append(InputProxy(value) if parameter.name.lower() in {{"request", "req"}} else value)
    result = target(*arguments)
    output = getattr(result, "stdout", result)
    if output is not None:
        print(output)

if __name__ == "__main__":
    drive(sys.argv[1])
'''
        manifest = {"finding_id": finding["id"], "repo_path": audit_data["checkout"], "commit": audit_data["commit"], "image": environment["image"], "proof_file": "proof.py", "attack": ["python3", "proof.py", "attack"], "control": ["python3", "proof.py", "control"], "observable": {"type": "stdout_contains", "value": marker}, "timeout_seconds": 30, "generator": "bounded_python_v1"}
        proof.write_text(script, encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        return manifest_path


def checkout(target: str, checkouts: Path) -> tuple[Path, str]:
    repo = repo_name(target)
    checkouts.mkdir(parents=True, exist_ok=True)
    folder = checkouts / (repo.replace("/", "_") + "-" + secrets.token_hex(5))
    command = ["git", "clone", "--depth", "50", "--single-branch", "https://github.com/" + repo + ".git", str(folder)]
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
        known = [dict(x) for x in connection.execute("SELECT a.id,a.ghsa,a.cve,a.summary,a.published_at,a.modified_at,a.cwe_ids,a.url,a.sources,a.references_json FROM advisories a JOIN advisory_repos ar ON ar.advisory_id=a.id WHERE ar.repo=? ORDER BY a.published_at DESC", (repo,))]
        for advisory in known:
            advisory["cwe_ids"] = json.loads(advisory.get("cwe_ids") or "[]")
            advisory["references"] = json.loads(advisory.pop("references_json", "[]") or "[]")
            advisory["packages"] = [dict(item) for item in connection.execute("SELECT ecosystem,name,version_range,patched FROM advisory_packages WHERE advisory_id=? AND repo=?", (advisory["id"], repo))]
        connection.close()
        age_hours = None
        if row and row["last_sync"]:
            try:
                synchronized = datetime.fromisoformat(row["last_sync"].replace("Z", "+00:00"))
                age_hours = round((datetime.now(timezone.utc) - synchronized).total_seconds() / 3600, 2)
            except ValueError:
                pass
        return {"status": "snapshot" if row else "repo_not_synced", "last_sync": row["last_sync"] if row else None, "snapshot_age_hours": age_hours, "fresh": age_hours is not None and age_hours <= 168, "coverage": json.loads(row["coverage"]) if row else {}, "known_advisories": known}
    except sqlite3.DatabaseError:
        return {"status": "unreadable", "known_advisories": []}


def audit(root: Path, repo: str, output_root: Path, max_files: int = 20_000, timeline_db: Path | None = None) -> Path:
    canonical = repo_name(repo)
    commit = commit_hash(root)
    destination = output_root / canonical.replace("/", "_") / commit
    destination.mkdir(parents=True, exist_ok=True)
    audit_file = destination / "audit.json"
    try:
        clean = not subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        clean = False
    if clean and audit_file.is_file():
        try:
            cached = json.loads(audit_file.read_text(encoding="utf-8"))
            if cached.get("schema_version") == 2 and cached.get("commit") == commit and cached.get("scan_cache", {}).get("cacheable") is True and Path(cached.get("checkout", "")).resolve() == root.resolve() and int(cached.get("scan_cache", {}).get("max_files", -1)) == max_files:
                cached["public_context"] = _public_context(timeline_db, canonical)
                cached["scan_cache"] = {**cached["scan_cache"], "reused": True, "reused_at": datetime.now(timezone.utc).isoformat()}
                audit_file.write_text(json.dumps(cached, ensure_ascii=False, indent=2), encoding="utf-8")
                return audit_file
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
    profile = RepositoryProfilerAgent().run(root, max(max_files, 50_000))
    priority_paths = set(profile.get("recent_changes", {}).get("files", {}))
    findings, coverage = SourceScanAgent().run(root, canonical, commit, max_files, priority_paths)
    coverage["repository_profile_complete"] = not profile["truncated"]
    coverage["unsupported_code_files"] = profile["unsupported_code_files"]
    summary = {"schema_version": 2, "repo": canonical, "commit": commit, "checkout": str(root.resolve()), "profile": profile, "coverage": coverage, "scan_cache": {"reused": False, "cacheable": clean, "key": f"{canonical}@{commit}", "max_files": max_files, "strategy": coverage["selection_strategy"]}, "public_context": _public_context(timeline_db, canonical), "hypotheses": [asdict(x) for x in findings], "generated_at": datetime.now(timezone.utc).isoformat()}
    audit_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return audit_file


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
    return {"finding_id": finding["id"], "title": "", "summary": "", "vulnerability_class": finding["kind"], "cwe": "", "cvss_vector": "", "affected": {"ecosystem": "", "package": "", "versions": "", "patched_version": "Not yet available"}, "source": {"file": finding.get("source_path") or finding["path"], "line": finding["source_line"], "attacker_control": "", "evidence": finding["source_code"]}, "sink": {"file": finding.get("sink_path") or finding["path"], "line": finding["sink_line"], "effect": "", "evidence": finding["sink_code"]}, "trace": finding.get("trace", []), "default_configuration_evidence": "", "upstream_guard_analysis": "", "impact": "", "root_cause": "", "reproduction_steps": [], "negative_control_explanation": "", "known_advisory_checks": {"github": "", "osv": "", "vendor_or_web": "", "duplicate_analysis": ""}, "remediation": ""}


class PocValidatorAgent:
    @staticmethod
    def _limits() -> None:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
            if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
                resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
        except (ImportError, OSError, ValueError):
            pass

    def _run(self, command: list[str], manifest: dict, poc_dir: Path, scratch: Path, container: bool) -> dict:
        repo = Path(manifest["repo_path"]).resolve()
        isolation = "container" if container else "resource_limits"
        if not container:
            args = command
            scratch = scratch.resolve()
            env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if os.environ.get(key)}
            env.update({"OSS_POC_REPO": str(repo), "OSS_POC_SCRATCH": str(scratch), "TMPDIR": str(scratch), "PYTHONDONTWRITEBYTECODE": "1"})
            sandbox = shutil.which("sandbox-exec") if sys.platform == "darwin" else None
            if sandbox:
                escaped_scratch = str(scratch).replace("\\", "\\\\").replace('"', '\\"')
                profile = scratch / "sandbox.sb"
                profile.write_text(f'''(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath "{escaped_scratch}"))
(allow file-write* (literal "/dev/null"))
''', encoding="utf-8")
                args = [sandbox, "-f", str(profile), *command]
                isolation = "macos_sandbox_no_network"
        else:
            image = manifest.get("image", "python:3.11-slim")
            if not re.fullmatch(r"[A-Za-z0-9_./:-]+", image):
                raise ValueError("컨테이너 이미지 이름이 유효하지 않습니다")
            args = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only", "--pids-limit=64", "--memory=256m", "--cpus=1", "--security-opt", "no-new-privileges", "-v", f"{repo}:/repo:ro", "-v", f"{poc_dir.resolve()}:/poc:ro", "-v", f"{scratch}:/scratch:rw", "-e", "OSS_POC_REPO=/repo", "-e", "OSS_POC_SCRATCH=/scratch", "-e", "TMPDIR=/scratch", "-e", "PYTHONDONTWRITEBYTECODE=1", "-w", "/poc", image, *command]
            env = os.environ.copy()
        try:
            limit_process = not container and os.name == "posix"
            process = subprocess.Popen(args, cwd=None if container else poc_dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, preexec_fn=self._limits if limit_process else None)
            stdout, stderr = process.communicate(timeout=min(int(manifest.get("timeout_seconds", 30)), 120))
            return {"returncode": process.returncode, "stdout": stdout[:4000], "stderr": stderr[:4000], "timed_out": False, "isolation": isolation}
        except subprocess.TimeoutExpired as exc:
            if "process" in locals() and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, AttributeError):
                    process.kill()
                stdout, stderr = process.communicate()
            else:
                stdout, stderr = str(exc.stdout or ""), str(exc.stderr or "")
            return {"returncode": None, "stdout": str(stdout or "")[:4000], "stderr": str(stderr or "")[:4000], "timed_out": True, "isolation": isolation}

    def run(self, manifest_file: Path, container: bool = False) -> Path:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        poc_dir = manifest_file.parent.resolve()
        repo = Path(manifest["repo_path"]).resolve()
        if not repo.is_dir() or commit_hash(repo) != manifest["commit"]:
            raise ValueError("PoC 대상 체크아웃의 커밋이 조사 시점과 다릅니다")
        marker = manifest.get("observable", {}).get("value")
        if not marker or not isinstance(marker, str) or len(marker) > 100:
            raise ValueError("명확한 관측 마커가 필요합니다")
        proof_name = manifest.get("proof_file", "proof.py")
        if not isinstance(proof_name, str) or not re.fullmatch(r"proof\.(?:py|mjs)", proof_name):
            raise ValueError("PoC 증명 파일 이름이 허용 범위를 벗어났습니다")
        proof_file = poc_dir / proof_name
        if not proof_file.is_file() or "TODO" in proof_file.read_text(encoding="utf-8"):
            raise ValueError("PoC의 실제 호출·대조군 TODO를 완성해야 합니다")
        expected_runtime = "node" if proof_name.endswith(".mjs") else "python3"
        for case in ("control", "attack"):
            command = manifest.get(case)
            if not isinstance(command, list) or len(command) != 3 or Path(str(command[0])).name not in {expected_runtime, "python" if expected_runtime == "python3" else expected_runtime} or command[1:] != [proof_name, case]:
                raise ValueError("PoC 실행 명령이 생성기가 허용한 형식을 벗어났습니다")
        with tempfile.TemporaryDirectory(prefix="oss-poc-") as temporary:
            control_scratch = Path(temporary) / "control"
            attack_scratch = Path(temporary) / "attack"
            control_scratch.mkdir()
            attack_scratch.mkdir()
            control = self._run(manifest["control"], manifest, poc_dir, control_scratch, container)
            attack = self._run(manifest["attack"], manifest, poc_dir, attack_scratch, container)
        control_match = marker in control["stdout"]
        attack_match = marker in attack["stdout"]
        confirmed = attack_match and not control_match and attack["returncode"] == 0 and control["returncode"] == 0 and not attack["timed_out"] and not control["timed_out"]
        mode = "offline_container" if container else "macos_sandbox" if control.get("isolation") == attack.get("isolation") == "macos_sandbox_no_network" else "limited_process"
        note = "기계적 관측 결과입니다. macOS sandbox 또는 컨테이너가 네트워크와 쓰기 범위를 제한했습니다. 코드 경로와 보안 영향은 별도로 검토해야 합니다." if mode != "limited_process" else "기계적 관측 결과입니다. 로컬 제한 프로세스는 완전한 파일·네트워크 격리를 제공하지 않으며 코드 경로와 보안 영향은 별도로 검토해야 합니다."
        evidence = {"finding_id": manifest["finding_id"], "repo_path": str(repo), "commit": manifest["commit"], "proof_file": proof_name, "proof_sha256": hashlib.sha256(proof_file.read_bytes()).hexdigest(), "manifest_sha256": hashlib.sha256(manifest_file.read_bytes()).hexdigest(), "mode": mode, "isolation": {"control": control.get("isolation"), "attack": attack.get("isolation")}, "control": control, "attack": attack, "control_observable": control_match, "attack_observable": attack_match, "mechanical_result": "contrast_matched" if confirmed else "not_confirmed", "validated_at": datetime.now(timezone.utc).isoformat(), "note": note}
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
        proof_name = evidence.get("proof_file", "proof.py")
        proof_file = poc_dir / proof_name
        if not proof_file.is_file() or evidence.get("proof_sha256") != hashlib.sha256(proof_file.read_bytes()).hexdigest() or evidence.get("manifest_sha256") != hashlib.sha256((poc_dir / "manifest.json").read_bytes()).hexdigest():
            raise ValueError("PoC 검증 이후 작업물 파일이 변경됐습니다")
        for field, expected_line, expected_path in (("source", finding["source_line"], finding.get("source_path") or finding["path"]), ("sink", finding["sink_line"], finding.get("sink_path") or finding["path"])):
            citation = claim[field]
            if citation["file"] != expected_path or int(citation["line"]) != expected_line:
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
        gate = claim.get("evidence_gate", {})
        gate_rows = "\n".join(f"| {name} | {value} |" for name, value in gate.get("criteria", {}).items()) or "| Manual review | Required |"
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

## Evidence gate

Overall verdict: **{gate.get("verdict", "manual review required")}**

| Criterion | Result |
| --- | --- |
{gate_rows}

## Proof of concept

The normal/attack PoC contrast matched against the checkout at `{audit_data["commit"]}`. PoC files: `{proof_file}` and `{claim_file.parent / "manifest.json"}`. Run `python3 -m oss_timeline poc-verify {claim_file.parent / "manifest.json"}` with the limited local runner, or add `--container` for stronger isolation.

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

Root cause and reproducibility: {claim["root_cause"]} See `GHSA_CANDIDATE.md`, `{proof_name}`, `manifest.json`, and `evidence.json` for the full private report and local reproduction.

CVE ID: not assigned. Coordinate the request with the repository maintainer or an in-scope CNA after private triage.
'''
        ghsa.write_text(description, encoding="utf-8")
        cve.write_text(cve_text, encoding="utf-8")
        return ghsa, cve


SUBMISSION_TRANSITIONS = {
    "draft_ready": {"reviewed"},
    "reviewed": {"submitted", "rejected"},
    "submitted": {"accepted", "rejected"},
    "accepted": set(),
    "rejected": set(),
}


def submission_status(audit_file: Path, finding_id: str) -> dict:
    audit_data, _ = load_hypothesis(audit_file, finding_id)
    folder = audit_file.parent / finding_id
    if not (folder / "GHSA_CANDIDATE.md").is_file() or not (folder / "CVE_REQUEST_BRIEF.md").is_file():
        raise ValueError("수동 제출 상태를 기록할 제보 초안이 없습니다")
    state_file = folder / "submission.json"
    if state_file.is_file():
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if state.get("finding_id") != finding_id or state.get("commit") != audit_data["commit"]:
            raise ValueError("제출 상태가 현재 후보·커밋과 일치하지 않습니다")
        return state
    return {"schema_version": 1, "finding_id": finding_id, "commit": audit_data["commit"], "status": "draft_ready", "external_action": "none", "reference": "", "note": "", "history": []}


def mark_submission_status(audit_file: Path, finding_id: str, status: str, reference: str = "", note: str = "") -> Path:
    current = submission_status(audit_file, finding_id)
    previous = current["status"]
    if status not in SUBMISSION_TRANSITIONS.get(previous, set()):
        raise ValueError(f"허용되지 않은 제출 상태 전환입니다: {previous} → {status}")
    reference = reference.strip()
    note = note.strip()
    if status in {"submitted", "accepted"} and not reference:
        raise ValueError("제출 또는 접수 상태에는 사람이 확인한 외부 참조가 필요합니다")
    if any("\n" in value or len(value) > 500 for value in (reference, note)):
        raise ValueError("제출 상태 참조와 메모는 한 줄 500자 이하여야 합니다")
    stamp = datetime.now(timezone.utc).isoformat()
    event = {"from": previous, "to": status, "at": stamp, "reference": reference, "note": note, "recorded_by": "human_cli"}
    updated = {**current, "status": status, "external_action": "recorded_only", "reference": reference or current.get("reference", ""), "note": note, "updated_at": stamp, "history": [*current.get("history", []), event]}
    destination = audit_file.parent / finding_id / "submission.json"
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(updated, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(destination)
    return destination


class DuplicateReviewAgent:
    """Compare a candidate with the collected public advisory snapshot; never submits externally."""
    KEYWORDS = {
        "command_injection": {"command", "shell", "injection", "CWE-78"},
        "code_execution": {"code execution", "eval", "injection", "CWE-94"},
        "unsafe_deserialization": {"deserialization", "pickle", "CWE-502"},
        "possible_ssrf": {"SSRF", "server-side request", "CWE-918"},
        "sql_injection": {"SQL injection", "query injection", "CWE-89"},
        "template_injection": {"template injection", "SSTI", "CWE-1336"},
        "path_traversal": {"path traversal", "directory traversal", "CWE-22"},
        "authentication_bypass": {"authentication bypass", "signature verification", "CWE-347"},
        "privilege_assignment": {"privilege assignment", "role assignment", "privilege escalation", "CWE-266"},
        "authorization_scope_candidate": {"authorization bypass", "IDOR", "BOLA", "user-controlled key", "CWE-639"},
        "concurrency_race_candidate": {"race condition", "improper synchronization", "concurrent execution", "CWE-362"},
        "toctou_candidate": {"TOCTOU", "race condition", "CWE-367"},
        "workflow_injection": {"GitHub Actions", "workflow injection", "pull_request_target", "CWE-829"},
        "buffer_overflow": {"stack buffer overflow", "out-of-bounds write", "memory corruption", "CWE-121"},
    }
    CWE = {"buffer_overflow": "CWE-121", "command_injection": "CWE-78", "workflow_injection": "CWE-829", "authentication_bypass": "CWE-347", "privilege_assignment": "CWE-266", "authorization_scope_candidate": "CWE-639", "concurrency_race_candidate": "CWE-362", "toctou_candidate": "CWE-367", "code_execution": "CWE-94", "unsafe_deserialization": "CWE-502", "possible_ssrf": "CWE-918", "sql_injection": "CWE-89", "template_injection": "CWE-1336", "path_traversal": "CWE-22"}

    def run(self, audit_data: dict, finding: dict) -> dict:
        context = audit_data.get("public_context", {})
        advisories = context.get("known_advisories", [])
        if context.get("status") != "snapshot":
            return {"status": "insufficient_public_context", "checked": 0, "matches": [], "scope": "수집된 GitHub·OSV 공개 공지 스냅샷", "manual_review_required": True}
        if context.get("fresh") is False:
            return {"status": "stale_public_context", "checked": len(advisories), "matches": [], "scope": "수집 후 7일이 지난 GitHub·OSV 공개 공지 스냅샷", "snapshot_age_hours": context.get("snapshot_age_hours"), "manual_review_required": True}
        terms = self.KEYWORDS.get(finding.get("kind"), {finding.get("kind", "")})
        expected_cwe = self.CWE.get(finding.get("kind"))
        code_tokens = {finding.get("function", ""), Path(finding.get("source_path") or finding.get("path", "")).stem, Path(finding.get("sink_path") or finding.get("path", "")).stem}
        code_tokens = {token.lower() for token in code_tokens if len(token) >= 4 and token not in {"handle", "handler", "route", "main"}}
        matches = []
        for advisory in advisories:
            references = advisory.get("references") or []
            haystack = " ".join([*(str(advisory.get(key) or "") for key in ("id", "ghsa", "cve", "summary", "sources", "url")), *map(str, references)]).lower()
            reasons, score = [], 0
            matched_terms = sorted(term for term in terms if term and term.lower() in haystack)
            if matched_terms:
                score += 2
                reasons.append("취약점 유형 용어: " + ", ".join(matched_terms))
            if expected_cwe and expected_cwe in set(advisory.get("cwe_ids") or []):
                score += 4
                reasons.append("동일 CWE " + expected_cwe)
            matched_tokens = sorted(token for token in code_tokens if token in haystack)
            if matched_tokens:
                score += min(4, len(matched_tokens) * 2)
                reasons.append("코드 경로/함수 토큰: " + ", ".join(matched_tokens))
            commit = str(finding.get("commit") or "").lower()
            if len(commit) >= 7 and any(commit in str(reference).lower() for reference in references):
                score += 8
                reasons.append("분석 커밋이 공지 참조에 포함됨")
            if score:
                relation = "known_duplicate" if score >= 6 else "possible_variant"
                matches.append({**{key: advisory.get(key) for key in ("id", "ghsa", "cve", "summary", "sources", "cwe_ids", "packages", "references")}, "score": score, "relation": relation, "reasons": reasons})
        matches.sort(key=lambda item: (-item["score"], str(item.get("id") or "")))
        return {
            "status": "possible_duplicate" if matches else "no_match_in_collected_snapshot",
            "classification": "known_duplicate" if any(item["relation"] == "known_duplicate" for item in matches) else "possible_variant" if matches else "no_structured_match",
            "checked": len(advisories),
            "matches": matches[:20],
            "scope": "수집된 GitHub·OSV 공개 공지 스냅샷",
            "snapshot_age_hours": context.get("snapshot_age_hours"),
            "manual_review_required": True,
        }


def _automatic_claim(finding: dict, duplicate_review: dict, reachability: dict, evidence_gate: dict) -> dict:
    cwe = {"buffer_overflow": "CWE-121", "command_injection": "CWE-78", "workflow_injection": "CWE-829", "authentication_bypass": "CWE-347", "privilege_assignment": "CWE-266", "authorization_scope_candidate": "CWE-639", "concurrency_race_candidate": "CWE-362", "toctou_candidate": "CWE-367", "code_execution": "CWE-94", "sql_injection": "CWE-89", "unsafe_deserialization": "CWE-502", "possible_ssrf": "CWE-918", "path_traversal": "CWE-22"}.get(finding["kind"], "CWE pending review")
    label = {"buffer_overflow": "Stack buffer overflow candidate", "command_injection": "Command injection", "workflow_injection": "Workflow trust-boundary injection", "authentication_bypass": "Authentication verification bypass", "privilege_assignment": "Untrusted privilege assignment", "authorization_scope_candidate": "Authorization scope bypass candidate", "concurrency_race_candidate": "Unsynchronized security-state race candidate", "toctou_candidate": "TOCTOU race candidate", "code_execution": "Code execution"}.get(finding["kind"], finding["kind"])
    claim = claim_template(finding)
    matches = ", ".join(item.get("id") or item.get("ghsa") or item.get("cve") or "unknown" for item in duplicate_review["matches"])
    duplicate_text = f"Potential matches require human comparison: {matches}" if matches else f'No keyword match among {duplicate_review["checked"]} collected advisories; broader manual search is still required.'
    claim.update({
        "title": f"{label} candidate in {finding['function']}",
        "summary": f"A bounded offline reproduction reached the {finding['kind']} sink from the modeled external input path.",
        "cwe": cwe,
        "impact": "The isolated marker-based reproduction demonstrates control of the modeled dangerous operation. Real deployment reachability and impact require maintainer review.",
        "root_cause": f"Input tracked from line {finding['source_line']} reaches the dangerous operation at line {finding['sink_line']} without a modeled transformation that removes attacker control.",
        "default_configuration_evidence": f'{reachability.get("verdict")}: {reachability.get("reason")}',
        "upstream_guard_analysis": "The bounded semantic scan did not model a sanitizing transformation on the cited path. Framework middleware, alternate callers, and guards still require maintainer review.",
        "negative_control_explanation": "The benign input completed without the unique attack marker; only the crafted input produced it.",
        "remediation": "Avoid interpreting attacker-controlled text as code or a shell command; use fixed operations and validated structured arguments.",
        "reproduction_steps": ["Use the pinned analyzed commit", "Run the supplied resource-limited PoC verifier", "Compare benign and crafted observations"],
    })
    claim["affected"] = {"ecosystem": "source", "package": finding["repo"], "versions": f'analyzed commit {finding["commit"]}', "patched_version": "Not yet available"}
    claim["source"]["attacker_control"] = "The scanner traced this expression from a modeled request, CLI, or route input."
    claim["sink"]["effect"] = "The crafted value controls the recorded dangerous operation in the isolated reproduction."
    claim["known_advisory_checks"] = {
        "github": duplicate_text,
        "osv": duplicate_text,
        "vendor_or_web": "Not automatically queried beyond the collected snapshot; manual review is required before submission.",
        "duplicate_analysis": duplicate_text,
    }
    claim["evidence_gate"] = evidence_gate
    return claim


class ResearchOrchestrator:
    """Run bounded reproduction stages and leave all external report submission to a human."""
    def run(self, audit_file: Path, max_candidates: int = 3, container: bool = False, timeline_db: Path | None = None) -> Path:
        audit_data = json.loads(audit_file.read_text(encoding="utf-8"))
        ranked = SemanticAnalysisAgent().run(audit_data.get("hypotheses", []), audit_data.get("profile", {}))
        results = []
        for finding in ranked[:max_candidates]:
            result = {"finding_id": finding["id"], "priority": finding["priority"], "stages": {}, "status": "blocked"}
            result["stages"]["semantic_analysis"] = {"status": "ready" if finding["auto_reproduction_supported"] else "unsupported", "reason": finding["automation_reason"], "priority_reasons": finding.get("priority_reasons", []), "trace": finding.get("trace", [])}
            if not finding["auto_reproduction_supported"]:
                results.append(result)
                continue
            reachability = ReachabilityGateAgent().run(finding, audit_data.get("profile", {}))
            result["stages"]["reachability_gate"] = reachability
            if reachability["status"] != "pass":
                result["status"] = "reachability_review_required"
                results.append(result)
                continue
            environment = BuildEnvironmentAgent().run(Path(audit_data["checkout"]), finding)
            result["stages"]["build_environment"] = environment
            if environment["status"] != "ready":
                results.append(result)
                continue
            destination = audit_file.parent / finding["id"]
            if (destination / "GHSA_CANDIDATE.md").is_file() and (destination / "CVE_REQUEST_BRIEF.md").is_file():
                evidence_path = destination / "evidence.json"
                duplicate_review = DuplicateReviewAgent().run(audit_data, finding)
                result["stages"]["duplicate_review"] = duplicate_review
                if evidence_path.is_file():
                    evidence_gate = EvidenceGateAgent().run(audit_data, finding, reachability, json.loads(evidence_path.read_text(encoding="utf-8")), duplicate_review)
                    result["stages"]["evidence_gate"] = evidence_gate
                    result["status"] = "draft_ready" if evidence_gate["verdict"] in {"CONFIRMED", "CONFIRMED_LOW"} else "review_required"
                result["stages"]["disclosure"] = {"status": "already_generated", "submission": "manual_only"}
                results.append(result)
                continue
            try:
                manifest_file = destination / "manifest.json"
                if manifest_file.is_file():
                    existing_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                    proof_name = existing_manifest.get("proof_file", "proof.py")
                    reusable = existing_manifest.get("generator") in {"bounded_python_v1", "bounded_python_ssrf_v1", "bounded_javascript_v1", "bounded_go_v1"} and existing_manifest.get("finding_id") == finding["id"] and existing_manifest.get("commit") == audit_data["commit"] and (destination / proof_name).is_file()
                    if not reusable:
                        raise ValueError("기존 수동 PoC 작업물이 있어 자동 생성으로 덮어쓰지 않습니다")
                    generation_status = "reused"
                else:
                    manifest_file = LimitedPocAgent().run(audit_file, finding, environment)
                    generation_status = "generated"
                result["stages"]["poc_generation"] = {"status": generation_status, "manifest": str(manifest_file)}
                evidence_file = PocValidatorAgent().run(manifest_file, container=container)
                evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
                result["stages"]["isolated_contrast"] = {"status": evidence["mechanical_result"], "mode": evidence["mode"], "evidence": str(evidence_file)}
                if evidence["mechanical_result"] != "contrast_matched":
                    result["status"] = "not_reproduced"
                    results.append(result)
                    continue
                duplicate_review = DuplicateReviewAgent().run(audit_data, finding)
                result["stages"]["duplicate_review"] = duplicate_review
                if duplicate_review["status"] != "no_match_in_collected_snapshot":
                    result["status"] = "duplicate_review_required"
                    results.append(result)
                    continue
                evidence_gate = EvidenceGateAgent().run(audit_data, finding, reachability, evidence, duplicate_review)
                result["stages"]["evidence_gate"] = evidence_gate
                if evidence_gate["verdict"] not in {"CONFIRMED", "CONFIRMED_LOW"}:
                    result["status"] = "review_required"
                    results.append(result)
                    continue
                claim = _automatic_claim(finding, duplicate_review, reachability, evidence_gate)
                claim_file = destination / "claim.json"
                claim_file.write_text(json.dumps(claim, ensure_ascii=False, indent=2), encoding="utf-8")
                ghsa, cve = DisclosureAgent().run(audit_file, finding["id"], claim_file, evidence_file)
                result["stages"]["disclosure"] = {"status": "draft_generated", "ghsa": str(ghsa), "cve": str(cve), "submission": "manual_only"}
                result["status"] = "draft_ready"
            except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
                result["stages"]["error"] = {"status": "blocked", "message": str(exc)[-500:]}
            results.append(result)
        summary = {
            "repo": audit_data["repo"],
            "commit": audit_data["commit"],
            "audit_file": str(audit_file),
            "execution_mode": "offline_container" if container else "limited_process",
            "external_submission": "disabled_manual_only",
            "ranked_candidates": len(ranked),
            "processed_candidates": len(results),
            "results": results,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        output = audit_file.parent / "orchestration.json"
        output.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        if timeline_db:
            store = Store(timeline_db)
            try:
                store.save_research(audit_data, summary, output)
            finally:
                store.db.close()
        return output
