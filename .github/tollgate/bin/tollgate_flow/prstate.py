"""Merge e chiusura della PR rilevati con `gh` (spec 6.5, decisione 12 di P3b).

`detect` legge la PR di `work_items.pr_number`: `MERGED` chiude il lavoro da qualunque fase
(evento `merge_detected`), `CLOSED` senza merge è lasciata a chi chiama, che offre le due strade
di `CLOSED_HINT`. Senza rete (o con un errore di `gh`) non si decide nulla e si avvisa."""
from __future__ import annotations

from dataclasses import dataclass

from tollgate_core import db, events, phases
from tollgate_core.paths import program_command

from . import gh

CLOSED_HINT = (
    "due strade: /tollgate:abandon #<N> abbandona il lavoro, oppure "
    f"{program_command(db.BIN_PATH)} start <N> --confirm scollega la PR chiusa e "
    "`finish open-pr` ne aprirà una nuova (<N> è il numero dell'issue)")


@dataclass(frozen=True)
class Detection:
    """`kind`: `merged`, `closed`, `open` oppure `None` (nessuna PR nota, o stato non letto:
    in quel caso `error` dice perché)."""
    kind: str | None
    pr: dict | None
    error: str | None = None


def closed_line(pr: dict) -> str:
    return f"PR #{pr.get('number')} chiusa senza merge: {CLOSED_HINT}"


def detect(state, conn, work, repo, *, now, session=None) -> Detection:
    number = work["pr_number"]
    if number is None:
        return Detection(None, None)
    try:
        pr = gh.pr_view(state, repo, number)
    except gh.GhError as e:
        return Detection(None, None, f"PR #{number}: stato non letto ({e})")
    if pr.get("state") == "MERGED" or pr.get("mergedAt"):
        if work["phase"] != "closed":
            events.record_event(conn, "merge_detected",
                                {"pr": number, "merged_at": pr.get("mergedAt")},
                                now=now, session=session, work=work["id"])
            phases.set_phase(conn, state, work["id"], "closed", "merged", now=now,
                             session=session)
        return Detection("merged", pr)
    if pr.get("state") == "CLOSED":
        return Detection("closed", pr)
    return Detection("open", pr)
