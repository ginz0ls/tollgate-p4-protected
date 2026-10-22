"""Lettura del report JUnit (spec 7.5, 8.1): identificativi classname::name, niente entità.

Il parser è expat, pilotato direttamente: gli handler di DOCTYPE, entità ed entità esterne
sollevano `JunitError` prima che qualunque entità venga espansa, con qualunque codifica
(UTF-8, UTF-16, con o senza BOM). Il controllo sui byte resta come primo filtro, non come
unica protezione.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from xml.parsers import expat

MAX_BYTES = 32 * 1024 * 1024
_ROOTS = ("testsuite", "testsuites")
_DANGER = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class JunitError(ValueError):
    pass


@dataclass
class Junit:
    total: int = 0
    skipped: int = 0
    failed: int = 0
    ids_run: list[str] = field(default_factory=list)
    ids_skipped: list[str] = field(default_factory=list)
    ids_failed: list[str] = field(default_factory=list)


def _refuse(*_args):
    raise JunitError("XML con DOCTYPE o entità: report rifiutato")


class _Collect:
    """Raccoglie i testcase. `case` vale (identificativo, figli diretti, profondità)."""

    def __init__(self):
        self.j = Junit()
        self.root: str | None = None
        self.depth = 0
        self.case: tuple[str, set[str], int] | None = None

    def start(self, name, attrs):
        self.depth += 1
        if self.root is None:
            if name not in _ROOTS:
                raise JunitError(f"radice <{name}> inattesa: atteso testsuite o testsuites")
            self.root = name
        if name == "testcase":
            if self.case is not None:
                raise JunitError("testcase annidato in un altro testcase")
            tid = f"{attrs.get('classname', '')}::{attrs.get('name', '')}"
            self.case = (tid, set(), self.depth)
        elif self.case is not None and self.depth == self.case[2] + 1:
            self.case[1].add(name)

    def end(self, name):
        if name == "testcase":
            tid, kinds, _ = self.case
            self.case = None
            self._record(tid, kinds)
        self.depth -= 1

    def _record(self, tid: str, kinds: set[str]):
        j = self.j
        j.total += 1
        if "skipped" in kinds:
            j.skipped += 1
            j.ids_skipped.append(tid)
            return
        j.ids_run.append(tid)
        if kinds & {"failure", "error"}:
            j.failed += 1
            j.ids_failed.append(tid)


def parse_junit(data: bytes, *, max_bytes: int = MAX_BYTES) -> Junit:
    if len(data) > max_bytes:
        raise JunitError(f"report JUnit troppo grande: {len(data)} byte (limite {max_bytes})")
    if _DANGER.search(data):
        _refuse()
    collect = _Collect()
    parser = expat.ParserCreate()
    parser.StartDoctypeDeclHandler = _refuse
    parser.EntityDeclHandler = _refuse
    parser.ExternalEntityRefHandler = _refuse
    parser.StartElementHandler = collect.start
    parser.EndElementHandler = collect.end
    try:
        parser.Parse(data, True)
    except JunitError:
        raise
    except (expat.ExpatError, LookupError, UnicodeError) as e:    # codifica sconosciuta o rotta
        raise JunitError(f"XML non valido: {e}") from e
    return collect.j
