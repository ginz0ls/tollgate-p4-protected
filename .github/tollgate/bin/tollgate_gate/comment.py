"""Il commento del gate sulla PR (spec 9.2, criterio 27).

Riporta lo SHA giudicato nel marcatore della prima riga: la CLI lo legge (`fixtask.GATE_MARKER`)
e lega il task di correzione a quello SHA. Le voci «da leggere» stanno in cima, le informative in
un blocco richiudibile. Il testo che non scrive tollgate (`Item.data`, elenco `watch`, `errors`)
passa solo da `prbody.neutralize`; tutto il commento sta entro `MAX_BODY`."""
from __future__ import annotations

import re

from tollgate_analysis import prbody
from tollgate_analysis.prbody import MAX_BODY

from . import attention
from .model import Evaluation, Item

MARKER_PREFIX = "<!-- tollgate-verdict"     # uguale a fixtask.GATE_MARKER (lo controlla un test)
GUARD_PREFIX = "<!-- tollgate-guard"
_SHA = re.compile(r"[0-9a-f]{40}")
_MARKER = re.compile(re.escape(MARKER_PREFIX) + r" sha=([0-9a-f]{40}) -->")
_TICKS = re.compile(r"`{3,}")


def _check_sha(sha: str) -> str:
    if not _SHA.fullmatch(sha):
        raise ValueError(f"SHA non valido: {sha!r}")
    return sha


def marker(sha: str) -> str:
    return f"{MARKER_PREFIX} sha={_check_sha(sha)} -->"


def marker_sha(body: str) -> str | None:
    """Lo SHA nel marcatore in testa al commento, `None` se manca o non è di 40 esadecimali."""
    m = _MARKER.match(body.lstrip())
    return m.group(1) if m else None


def _one_line(text: str, cap: int) -> str:
    """`Item.text` lo scrive tollgate, ma può portare un valore letto altrove (difesa in
    profondità, D19): una riga sola, senza recinti né tag, menzioni e commenti spenti."""
    line = " ".join(text.split()).replace("<", "&lt;")
    return prbody.defuse(_TICKS.sub(lambda m: "'" * len(m.group()), prbody.cap(line, cap)))


def _item(item: Item, cap: int) -> list[str]:
    out = [f"- {_one_line(item.text, cap)}"]
    if item.data:
        out += ["", prbody.neutralize(item.data, cap), ""]
    return out


def _lines(items: list[str], cap: int) -> list[str]:
    """Un solo recinto per un elenco di stringhe: il tetto vale per ogni voce."""
    joined = "\n".join(prbody.cap(x, cap) for x in items)
    return ["", prbody.neutralize(joined, len(joined)), ""]


def _build(sha: str, ev: Evaluation, cap: int, keep: int | None) -> str:
    def limited(items: list) -> tuple[list, list[str]]:
        if keep is None or len(items) <= keep:
            return items, []
        return items[:keep], [f"… (troncato: altre {len(items) - keep} voci omesse)", ""]

    out = [marker(sha), "", f"## tollgate: verdetto sullo SHA `{sha}`", ""]
    if ev.errors:
        out += ["**Errore nel calcolo del gate**", ""]
        shown, note = limited(ev.errors)
        out += _lines(shown, cap) + note
    if ev.red:
        out += ["### Da correggere", ""]
        shown, note = limited(ev.red)
        for it in shown:
            out += _item(it, cap)
        out += note
    read = [i for i in ev.attention if attention.group(i.key) == attention.READ]
    info = [i for i in ev.attention if attention.group(i.key) == attention.INFO]
    if read:
        out += ["### Da leggere", ""]
        shown, note = limited(read)
        for it in shown:
            out += _item(it, cap)
        out += note
    if info:
        out += ["<details>", f"<summary>Informative ({len(info)})</summary>", ""]
        shown, note = limited(info)
        for it in shown:
            out += _item(it, cap)
        out += note + ["</details>", ""]
    if ev.watch:
        out += ["### File da tenere d'occhio", ""]
        shown, note = limited(ev.watch)
        out += _lines(shown, cap) + note
    if not (ev.errors or ev.red or read or info or ev.watch):
        out += ["Nessuna voce.", ""]
    return "\n".join(out).rstrip() + "\n"


def _fit(build, count: int, last_resort: str) -> str:
    """Il primo testo entro `MAX_BODY`: prima si accorciano le voci (`prbody.CAPS`), poi si
    tolgono dalla coda con una nota; in ultimo `last_resort`, che sta sempre nel tetto."""
    for cap in prbody.CAPS:
        body = build(cap, None)
        if len(body) <= MAX_BODY:
            return body
    keep = count
    while keep > 1:
        keep //= 2
        body = build(prbody.CAPS[-1], keep)
        if len(body) <= MAX_BODY:
            return body
    return last_resort


def render(sha: str, ev: Evaluation) -> str:
    """Il commento del gate per lo SHA `sha`, sempre entro `MAX_BODY`."""
    _check_sha(sha)
    count = max(len(ev.errors), len(ev.red), len(ev.attention), len(ev.watch))
    minimal = (f"{marker(sha)}\n\n## tollgate: verdetto sullo SHA `{sha}`\n\n"
               f"… (troncato: commento ridotto, {len(ev.errors)} errori, {len(ev.red)} voci rosse, "
               f"{len(ev.attention)} di attenzione)\n")
    return _fit(lambda cap, keep: _build(sha, ev, cap, keep), count, minimal)


def _guard_build(sha: str, problems: list[str], cap: int, keep: int | None) -> str:
    out = [f"{GUARD_PREFIX} sha={sha} -->", "", f"## tollgate/guard: rosso sullo SHA `{sha}`", ""]
    shown = problems if keep is None else problems[:keep]
    if shown:
        out += _lines(shown, cap)
    if len(shown) < len(problems):
        out += [f"… (troncato: altri {len(problems) - len(shown)} problemi omessi)", ""]
    return "\n".join(out).rstrip() + "\n"


def render_guard(sha: str, problems: list[str]) -> str:
    """Il commento di `tollgate-guard` quando `tollgate/guard` è rosso: spiega i problemi.
    Stesso tetto totale del commento del gate."""
    _check_sha(sha)
    minimal = _guard_build(sha, problems, 0, 0)
    return _fit(lambda cap, keep: _guard_build(sha, problems, cap, keep), len(problems), minimal)
