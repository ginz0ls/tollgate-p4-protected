"""Forma della spec L2 (spec 6.2): fette previste e sezioni da «pitch»."""
from __future__ import annotations

import re

from .plan import _Fences

SLICES_SECTION = "Fette previste"
PITCH_SECTIONS = ("Tane di coniglio", "Cosa non fare")
_H2 = re.compile(r"^## (.+?)\s*$")
_ITEM = re.compile(r"^\d+\.\s+(\S.*?)\s*$")


def _sections(text: str) -> list[tuple[str, list[str]]]:
    """Le sezioni `##` fuori dai recinti, con le righe che le seguono (anch'esse fuori dai
    recinti)."""
    out: list[tuple[str, list[str]]] = []
    fences = _Fences()
    for line in text.splitlines():
        if fences.inside(line):
            continue
        m = _H2.match(line)
        if m:
            out.append((m.group(1), []))
        elif out:
            out[-1][1].append(line)
    return out


def slice_titles(text: str) -> list[str]:
    """Il testo delle voci numerate («1. titolo») della sezione `## Fette previste`."""
    for title, lines in _sections(text):
        if title == SLICES_SECTION:
            return [m.group(1) for m in map(_ITEM.match, lines) if m]
    return []


def slices(text: str) -> int:
    """Il numero di fette previste; senza sezione o senza voci è una."""
    return len(slice_titles(text)) or 1


def pitch_problems(text: str) -> list[str]:
    """Una riga per ogni sezione di `PITCH_SECTIONS` che manca."""
    present = {title for title, _ in _sections(text)}
    return [f"manca la sezione «## {s}» (spec L2, 6.2)" for s in PITCH_SECTIONS
            if s not in present]
