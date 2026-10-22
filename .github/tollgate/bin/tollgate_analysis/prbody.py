"""Corpo della PR (spec 6.4, decisione 10 di P3b).

Ogni testo che non scrive tollgate (rilievi dei revisori, deroghe, esiti dei comandi) entra solo
tramite `neutralize`: recinto più lungo di ogni sequenza di backtick, menzioni spente, nessun
commento HTML, lunghezza massima. Il blocco JSON di 18.1 sta per ultimo."""
from __future__ import annotations

from . import brief, prblock

MAX_TEXT = 2000
# Tetto del corpo intero (GitHub accetta 65536 caratteri): il commento del gate lo importa da qui.
MAX_BODY = 60000
CAPS = (MAX_TEXT, 1000, 500, 250, 120, 60, 30)
TRUNCATED = "… (troncato)"
ZWSP = "\u200b"


def cap(text, max_len: int = MAX_TEXT) -> str:
    text = str(text)
    return text[:max_len].rstrip() + TRUNCATED if len(text) > max_len else text


def defuse(text: str) -> str:
    """Menzioni spente e nessun marcatore di commento HTML."""
    return (text.replace("@", "@" + ZWSP).replace("<!--", "<!" + ZWSP + "--")
            .replace("-->", "--" + ZWSP + ">")
            .replace("--!>", "--" + ZWSP + "!>"))


def neutralize(text: str, max_len: int = MAX_TEXT) -> str:
    text = defuse(cap(text, max_len))
    fence = brief.fence(text)
    return f"{fence}\n{text}\n{fence}"


def _section(title: str, lines: list[str], limit: int = MAX_TEXT) -> list[str]:
    """Il tetto vale per ogni voce, non per la sezione: una voce lunga non nasconde le altre."""
    joined = "\n".join(cap(x, limit) for x in lines)
    return [f"## {title}", neutralize(joined, len(joined)), ""]


def _note(n: dict) -> str:
    file, line = n.get("file") or "(file non indicato)", n.get("line")
    where = f"{file}:{line}" if line is not None else file
    return f"[{n.get('severity') or '?'}] {where} ({n.get('rule') or 'senza regola'}): {n.get('text')}"


def _unverified(n: dict) -> str:
    why = n.get("verification_reason")
    return _note(n) + (f" [non verificato: {why}]" if why else " [non verificato]")


def _render(issue, level, sections, block) -> str:
    out = [f"Closes #{int(issue)}", "", f"Livello: {level}", ""]
    for title, lines, limit in sections:
        out += _section(title, lines, limit)
    out.append(prblock.render(block))
    return "\n".join(out) + "\n"


def render(*, issue: int, level: str, dod_lines: list[str], notes: list[dict],
           waivers: list[str], warnings: list[str], block: dict,
           unverified: list[dict] = ()) -> str:
    """Il corpo sta entro `MAX_BODY`: se lo supera, le voci si accorciano (tetto per voce sempre
    più basso) e, in ultima istanza, si tolgono dalla coda con una nota. Il blocco JSON di 18.1
    resta intero e ultimo."""
    parts = [("Definition of Done", list(dod_lines))]
    if notes:
        parts.append(("Note della revisione (non bloccanti)", [_note(n) for n in notes]))
    if unverified:
        parts.append(("Rilievi non verificati", [_unverified(n) for n in unverified]))
    if waivers:
        parts.append(("Deroghe", list(waivers)))
    if warnings:
        parts.append(("Avvisi", list(warnings)))
    for limit in CAPS:
        body = _render(issue, level, [(t, ls, limit) for t, ls in parts], block)
        if len(body) <= MAX_BODY:
            return body
    keep = max(len(ls) for _, ls in parts)
    while keep > 1:
        keep //= 2
        cut = [(t, ls[:keep] + ([f"… (troncato: altre {len(ls) - keep} voci omesse)"]
                                 if len(ls) > keep else []), 60) for t, ls in parts]
        body = _render(issue, level, cut, block)
        if len(body) <= MAX_BODY:
            return body
    # ultimo taglio: nessuna voce, solo la nota; il blocco JSON resta intero
    return _render(issue, level, [("Definition of Done", ["… (troncato: voci omesse)"], 60)], block)
