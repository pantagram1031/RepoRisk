"""AST-based detectors for selected Python rules.

These detectors are still heuristic, but they understand Python call syntax and
simple import aliases better than line-oriented regular expressions.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call"}
REQUESTS_FUNCS = {"get", "post", "put", "delete", "patch", "head", "request"}
WEAK_HASH_FUNCS = {"md5", "sha1"}
PICKLE_FUNCS = {"load", "loads"}


class ImportResolver(ast.NodeVisitor):
    """Resolve simple import aliases used by the AST detectors."""

    def __init__(self) -> None:
        self.module_aliases: dict[str, str] = {}
        self.function_aliases: dict[str, tuple[str, str]] = {}
        self.imported_names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root_name = alias.name.split(".")[0]
            local_name = alias.asname or root_name
            self.module_aliases[local_name] = root_name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        module = node.module.split(".")[0]
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            self.function_aliases[local_name] = (module, alias.name)
            self.imported_names.add(local_name)


def _resolver(tree: ast.AST) -> ImportResolver:
    resolver = ImportResolver()
    resolver.visit(tree)
    return resolver


def _iter_calls(tree: ast.AST) -> Iterable[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def _is_name_call(node: ast.Call, name: str) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id == name


def _is_module_attr_call(node: ast.Call, resolver: ImportResolver, module: str, functions: set[str]) -> bool:
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        resolved_module = resolver.module_aliases.get(node.func.value.id, node.func.value.id)
        return resolved_module == module and node.func.attr in functions
    if isinstance(node.func, ast.Name):
        resolved = resolver.function_aliases.get(node.func.id)
        return resolved is not None and resolved[0] == module and resolved[1] in functions
    return False


def _keyword_is_bool(node: ast.Call, keyword_name: str, value: bool) -> bool:
    return any(
        keyword.arg == keyword_name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is value
        for keyword in node.keywords
    )


def _loader_is_safe(node: ast.Call, resolver: ImportResolver) -> bool:
    for keyword in node.keywords:
        if keyword.arg != "Loader":
            continue
        value = keyword.value
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            resolved_module = resolver.module_aliases.get(value.value.id, value.value.id)
            if resolved_module == "yaml" and value.attr in {"SafeLoader", "CSafeLoader"}:
                return True
        if isinstance(value, ast.Name):
            if value.id in {"SafeLoader", "CSafeLoader"}:
                return True
            resolved = resolver.function_aliases.get(value.id)
            if resolved == ("yaml", "SafeLoader") or resolved == ("yaml", "CSafeLoader"):
                return True
    return False


def detect_eval(tree: ast.AST) -> list[int]:
    return [node.lineno for node in _iter_calls(tree) if _is_name_call(node, "eval")]


def detect_exec(tree: ast.AST) -> list[int]:
    return [node.lineno for node in _iter_calls(tree) if _is_name_call(node, "exec")]


def detect_subprocess_shell_true(tree: ast.AST) -> list[int]:
    resolver = _resolver(tree)
    return [
        node.lineno
        for node in _iter_calls(tree)
        if _is_module_attr_call(node, resolver, "subprocess", SUBPROCESS_FUNCS)
        and _keyword_is_bool(node, "shell", True)
    ]


def detect_requests_verify_false(tree: ast.AST) -> list[int]:
    resolver = _resolver(tree)
    return [
        node.lineno
        for node in _iter_calls(tree)
        if _is_module_attr_call(node, resolver, "requests", REQUESTS_FUNCS)
        and _keyword_is_bool(node, "verify", False)
    ]


def detect_weak_hash(tree: ast.AST) -> list[int]:
    resolver = _resolver(tree)
    return [
        node.lineno
        for node in _iter_calls(tree)
        if _is_module_attr_call(node, resolver, "hashlib", WEAK_HASH_FUNCS)
    ]


def detect_yaml_load_without_safe_loader(tree: ast.AST) -> list[int]:
    resolver = _resolver(tree)
    findings: list[int] = []
    for node in _iter_calls(tree):
        if _is_module_attr_call(node, resolver, "yaml", {"load"}) and not _loader_is_safe(node, resolver):
            findings.append(node.lineno)
    return findings


def detect_pickle_load(tree: ast.AST) -> list[int]:
    resolver = _resolver(tree)
    return [
        node.lineno
        for node in _iter_calls(tree)
        if _is_module_attr_call(node, resolver, "pickle", PICKLE_FUNCS)
    ]
