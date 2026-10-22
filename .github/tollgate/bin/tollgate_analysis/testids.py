"""Identificativi dei test per analisi statica, nella forma del JUnit di ogni strumento (7.5)."""
from __future__ import annotations

import ast
import posixpath
import re

from .scan import js_tokens

JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
_GROUPS = {"describe", "suite", "context", "xdescribe"}
_CASES = {"it", "test", "xit", "xtest"}
_SKIP_MODS = {"skip", "todo", "fixme"}
_GO_TEST = re.compile(r"^func\s+(Test\w+)\s*\(", re.MULTILINE)


def language(path: str) -> str | None:
    if path.endswith(JS_EXT):
        return "js"
    if path.endswith(".py"):
        return "py"
    if path.endswith(".go"):
        return "go"
    if path.endswith((".java", ".kt")):
        return "java"
    if path.endswith(".rs"):
        return "rust"
    return None


def _js(text: str, rel: str, joiner: str):
    toks = list(js_tokens(text, jsx=rel.endswith((".jsx", ".tsx"))))
    active: dict[str, str] = {}
    skipped: set[str] = set()
    frames: list[tuple[str, int, bool]] = []
    depth, i = 0, 0
    while i < len(toks):
        kind, val = toks[i]
        if kind == "p":
            if val == "{":
                depth += 1
            elif val == "}":
                depth -= 1
                while frames and frames[-1][1] >= depth:
                    frames.pop()
            i += 1
            continue
        if kind == "id" and (val in _GROUPS or val in _CASES):
            j, mods = i + 1, []
            while j + 1 < len(toks) and toks[j] == ("p", ".") and toks[j + 1][0] == "id":
                mods.append(toks[j + 1][1])
                j += 2
            if j + 1 < len(toks) and toks[j] == ("p", "(") and toks[j + 1][0] == "str":
                title = toks[j + 1][1]
                skip = (val.startswith("x") or any(m in _SKIP_MODS for m in mods)
                        or any(f[2] for f in frames))
                if val in _GROUPS:
                    frames.append((title, depth, skip))
                else:
                    local = joiner.join([f[0] for f in frames] + [title])
                    if skip:
                        skipped.add(local)
                    else:
                        active[local] = f"{rel}::{local}"
                i = j + 2
                continue
        i += 1
    return active, skipped


def _is_skip(decorators) -> bool:
    return any(re.search(r"skip|xfail", ast.unparse(d)) for d in decorators)


def _py(text: str, rel: str):
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    module = rel[:-3].replace("/", ".")
    active: dict[str, str] = {}
    skipped: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            if _is_skip(node.decorator_list):
                skipped.add(node.name)
            else:
                active[node.name] = f"{module}::{node.name}"
        elif isinstance(node, ast.ClassDef):
            bases = {ast.unparse(b) for b in node.bases}
            if not (node.name.startswith("Test") or any(b.endswith("TestCase") for b in bases)):
                continue
            cls_skip = _is_skip(node.decorator_list)
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name.startswith("test"):
                    local = f"{node.name}::{m.name}"
                    if cls_skip or _is_skip(m.decorator_list):
                        skipped.add(local)
                    else:
                        active[local] = f"{module}.{node.name}::{m.name}"
    return active, skipped


def _go(text: str, rel: str):
    pkg = posixpath.dirname(rel) or "."
    return {name: f"{pkg}::{name}" for name in _GO_TEST.findall(text)}, set()


def test_ids(text: str, rel: str, *, js_form: str):
    lang = language(rel)
    if lang == "js":
        return _js(text, rel, " > " if js_form == "vitest" else " ")
    if lang == "py":
        return _py(text, rel)
    if lang == "go":
        return _go(text, rel)
    return {}, set()
