"""Pattern nel dialetto di .gitignore (spec 3.2), su percorsi relativi alla radice del repo.

Segue wildmatch di git: `*` e `?` non attraversano `/`; `**` è speciale solo come segmento
intero (`**/`, `/**`, `**` da solo), altrove vale `*`; `[...]` con `!`/`^` per la negazione,
`]` in testa letterale, classi POSIX, `\\` escape; `!` iniziale è una negazione (si applica
in `match_any`, ultimo pattern che corrisponde vince). Un pattern non valido non corrisponde
mai e non solleva eccezioni.
"""
from __future__ import annotations

import re
from functools import lru_cache

_GLOB_CHARS = set("*?[")

# Classi POSIX come intervalli di regex già escapati (ASCII).
_POSIX = {
    "alpha": "a-zA-Z", "digit": "0-9", "alnum": "0-9A-Za-z", "upper": "A-Z", "lower": "a-z",
    "xdigit": "0-9A-Fa-f", "space": r"\x20\x09-\x0d", "blank": r"\x20\x09",
    "cntrl": r"\x00-\x1f\x7f", "print": r"\x20-\x7e", "graph": r"\x21-\x7e",
    "punct": r"\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e",
}


class _Invalid(Exception):
    """Pattern non valido: non corrisponde a nulla."""


def is_pattern(s: str) -> bool:
    """Vero solo per `*` o `?`: le parentesi quadre sono nomi letterali (es. `app/[id]/page.tsx`)."""
    return "*" in s or "?" in s


def literal_segments(pattern: str) -> int:
    return sum(1 for seg in pattern.strip("/").split("/")
               if seg and not (_GLOB_CHARS & set(seg)))


def _lit(ch: str) -> str:
    """Carattere come escape di regex, sicuro dentro e fuori da una classe."""
    if ch.isascii() and ch.isalnum():
        return ch
    if ord(ch) < 256:
        return f"\\x{ord(ch):02x}"
    return f"\\U{ord(ch):08x}"


def _class_char(p: str, j: int) -> tuple[str, int]:
    if p[j] == "\\":
        if j + 1 >= len(p):
            raise _Invalid
        return p[j + 1], j + 2
    return p[j], j + 1


def _parse_class(p: str, i: int) -> tuple[str, int]:
    """Classe `[...]` che inizia in `i`. Ritorna (regex, indice dopo `]`)."""
    n = len(p)
    j = i + 1
    negate = j < n and p[j] in "!^"
    if negate:
        j += 1
    parts: list[str] = []
    first = True
    while True:
        if j >= n:
            raise _Invalid
        c = p[j]
        if c == "]" and not first:
            j += 1
            break
        first = False
        if p.startswith("[:", j):
            end = p.find(":]", j + 2)
            if end != -1:
                name = p[j + 2:end]
                if name not in _POSIX:
                    raise _Invalid
                parts.append(_POSIX[name])
                j = end + 2
                continue
        lo, j = _class_char(p, j)
        if j + 1 < n and p[j] == "-" and p[j + 1] != "]":
            hi, j = _class_char(p, j + 1)
            if ord(lo) <= ord(hi):  # intervallo vuoto: non corrisponde a nulla
                parts.append(f"{_lit(lo)}-{_lit(hi)}")
        else:
            parts.append(_lit(lo))
    body = "".join(parts)
    if not body:
        return ("[^\\x2f]" if negate else "(?!)"), j
    # Il separatore `/` non è mai parte di una classe (spec 3.2, come git).
    return "(?!/)" + ("[^" if negate else "[") + body + "]", j


def _translate(p: str) -> str:
    out: list[str] = []
    i, n = 0, len(p)
    while i < n:
        c = p[i]
        if c == "/" and p.startswith("/**", i) and i + 3 == n:
            out.append("/.*")
            i += 3
        elif c == "*" and p.startswith("**/", i) and (i == 0 or p[i - 1] == "/"):
            out.append("(?:.*/)?")
            i += 3
        elif c == "*" and p == "**":
            out.append(".*")
            i += 2
        elif c == "*":
            j = i
            while j < n and p[j] == "*":
                j += 1
            out.append("[^/]*")
            i = j
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            regex, i = _parse_class(p, i)
            out.append(regex)
        elif c == "\\":
            if i + 1 >= n:
                raise _Invalid
            out.append(_lit(p[i + 1]))
            i += 2
        else:
            out.append(_lit(c))
            i += 1
    return "".join(out)


@lru_cache(maxsize=1024)
def compile(pattern: str):  # noqa: A001 - nome voluto, come re.compile
    """Regex del pattern, o None se il pattern non è valido (non corrisponde a nulla)."""
    p = pattern
    dir_only = p.endswith("/")
    p = p.rstrip("/")
    anchored = p.startswith("/") or "/" in p
    p = p.lstrip("/")
    try:
        body = _translate(p)
    except _Invalid:
        return None
    prefix = "" if anchored else "(?:.*/)?"
    suffix = "/.*" if dir_only else "(?:/.*)?"
    return re.compile(prefix + body + suffix, re.DOTALL)


def match(pattern: str, path: str) -> bool:
    """Corrispondenza di un pattern positivo. Un pattern che comincia con `!` è una
    negazione: da solo non seleziona nulla (vedi `match_any`)."""
    if pattern.startswith("!"):
        return False
    rx = compile(pattern)
    if rx is None:
        return False
    return rx.fullmatch(path[2:] if path.startswith("./") else path) is not None


def match_any(patterns, path: str) -> bool:
    """Regola di git: decide l'ultimo pattern che corrisponde; un `!` che corrisponde esclude."""
    hit = False
    for pat in patterns:
        if pat.startswith("!"):
            if match(pat[1:], path):
                hit = False
        elif match(pat, path):
            hit = True
    return hit


def escape(path: str) -> str:
    """Pattern che corrisponde solo a `path` (percorso relativo alla radice del repo).

    Fa l'escape di `*?[]\\`; un `!` iniziale è escapato. Un percorso senza `/` viene
    ancorato alla radice con `/` iniziale, altrimenti corrisponderebbe anche in sottocartelle.
    """
    body = "".join("\\" + c if c in "*?[]\\" else c for c in path)
    if "/" not in path:
        return "/" + body
    if path.startswith("!"):
        return "\\" + body
    return body
