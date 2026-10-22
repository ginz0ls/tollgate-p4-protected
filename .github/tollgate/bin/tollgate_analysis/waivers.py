"""Deroghe in .tollgate/waivers/<N>.toml (spec 8.3, 18.2)."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from typing import Callable

from . import globs

TYPES = ("scope", "test", "ci", "threshold", "command")
_ID = re.compile(r"^w-(\d+)-(\d+)$")
IMMEDIATE_SCOPE = 2


@dataclass
class Waiver:
    id: str
    type: str
    file: str | None
    pattern: str | None
    tests: list[str]
    choice: str
    why: str
    cost: str
    declared_by: str = "agent"


@dataclass
class WaiverFile:
    issue: int
    branch: str
    waivers: list[Waiver] = field(default_factory=list)
    schema_version: int = 1


def path_for(issue: int) -> str:
    return f".tollgate/waivers/{issue}.toml"


def _str(d: dict, k: str, required=True) -> str | None:
    v = d.get(k)
    if v is None and not required:
        return None
    if not isinstance(v, str):
        raise ValueError(f"campo {k} mancante o non stringa")
    return v


def parse(text: str) -> WaiverFile:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"TOML non valido: {e}") from e
    if raw.get("schema_version") != 1:
        raise ValueError("schema_version mancante o non supportata")
    issue, branch = raw.get("issue"), raw.get("branch")
    if not isinstance(issue, int) or isinstance(issue, bool) or not isinstance(branch, str):
        raise ValueError("issue o branch non validi")
    items = raw.get("waiver", [])
    if not isinstance(items, list):
        raise ValueError("waiver deve essere una lista di tabelle [[waiver]]")
    out, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("[[waiver]] non è una tabella")
        wid, type_ = _str(item, "id"), _str(item, "type")
        if not _ID.match(wid) or type_ not in TYPES:
            raise ValueError(f"deroga non valida: {wid} {type_}")
        if wid in seen:
            raise ValueError(f"id duplicato: {wid}")
        seen.add(wid)
        file, pattern = _str(item, "file", False), _str(item, "pattern", False)
        if (file is None) == (pattern is None):
            raise ValueError(f"{wid}: serve file oppure pattern")
        tests = item.get("tests", [])
        if not isinstance(tests, list) or not all(isinstance(t, str) for t in tests):
            raise ValueError(f"{wid}: tests deve essere una lista di stringhe")
        out.append(Waiver(wid, type_, file, pattern, tests, _str(item, "choice"),
                          _str(item, "why"), _str(item, "cost"),
                          _str(item, "declared_by", False) or "agent"))
    return WaiverFile(issue, branch, out, 1)


def _q(s: str) -> str:
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def dumps(wf: WaiverFile) -> str:
    lines = [f"schema_version = {wf.schema_version}", f"issue = {wf.issue}",
             f"branch = {_q(wf.branch)}"]
    for w in wf.waivers:
        lines += ["", "[[waiver]]", f"id = {_q(w.id)}", f"type = {_q(w.type)}"]
        lines.append(f"file = {_q(w.file)}" if w.file is not None
                     else f"pattern = {_q(w.pattern)}")
        lines.append("tests = [" + ", ".join(_q(t) for t in w.tests) + "]")
        for k in ("choice", "why", "cost", "declared_by"):
            lines.append(f"{k} = {_q(getattr(w, k))}")
    return "\n".join(lines) + "\n"


def next_id(wf: WaiverFile) -> str:
    nums = [int(m.group(2)) for w in wf.waivers if (m := _ID.match(w.id))]
    return f"w-{wf.issue}-{max(nums, default=0) + 1}"


def status(wf: WaiverFile, *, approved_ids, sensitive: Callable[[str], bool]) -> dict[str, str]:
    """Le prime 2 deroghe scope su file non sensibili valgono subito; command vale subito;
    il resto (test, ci, threshold, pattern, scope oltre la seconda) aspetta approve waiver."""
    out: dict[str, str] = {}
    scope_seen = 0
    for w in wf.waivers:
        immediate = False
        if w.type == "scope" and w.pattern is None and not sensitive(w.file):
            scope_seen += 1
            immediate = scope_seen <= IMMEDIATE_SCOPE
        elif w.type == "command" and w.pattern is None:
            immediate = True
        out[w.id] = "valid" if (immediate or w.id in approved_ids) else "pending"
    return out


def covers(w: Waiver, v) -> bool:
    """Una deroga copre una violazione se ha lo stesso tipo e lo stesso file o pattern.
    Se la violazione ha identificativi di test (`ids`), la deroga deve elencarli tutti."""
    if w.type != v.waiver_type:
        return False
    ok = globs.match(w.pattern, v.path) if w.pattern is not None else w.file == v.path
    if not ok:
        return False
    if v.ids:
        return set(v.ids) <= set(w.tests)
    return True


def unresolved(violations, wf: WaiverFile | None) -> list:
    """Violazioni non coperte da alcuna deroga. Decisione 9 del piano: in locale anche una
    deroga `pending` scioglie la violazione; il blocco su ciò che è in attesa arriva da
    `open-pr` in P3, non da qui."""
    if wf is None:
        return list(violations)
    return [v for v in violations if not any(covers(w, v) for w in wf.waivers)]
