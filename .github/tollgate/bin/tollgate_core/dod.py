"""Definition of Done per livello (spec 8.7): ogni voce viene da un dato, mai da un giudizio."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping

from . import receipts, reviews
from .phases import get_work
from .verify import counts_green

EXTERNAL_KEYS = ("guard_scope", "must_have", "approvals", "specialists")
ITEMS_BY_LEVEL = {
    "L0": ("receipt", "guard_scope"),
    "L1": ("receipt", "guard_scope", "tasks_approved", "findings", "must_have", "skills"),
    "L2": ("receipt", "guard_scope", "tasks_approved", "findings", "must_have", "skills",
           "approvals", "specialists"),
}
SKIPPED_DETAIL = "dopo la revisione"
LABELS = {
    "receipt": "Ricevuta green sullo SHA",
    "guard_scope": "test-guard e scope senza violazioni non derogate",
    "tasks_approved": "Ogni task done con verdetto approved",
    "findings": "Nessun rilievo blocker o major confermato senza approve finding",
    "must_have": "Ogni must-have ha i suoi test eseguiti e verdi",
    "skills": "Skill dei profili usate",
    "approvals": "Spec e piano approvati, report avversariali presenti",
    "specialists": "Specialisti finali passati",
}


@dataclass(frozen=True)
class DodItem:
    key: str
    label: str
    ok: bool | None
    detail: str = ""


def receipt_verdict(rows, head_sha: str, allow_no_tests: bool, required_commands: list[str],
                    allow_unverified: bool = False) -> tuple[bool, str]:
    """Un solo punto per DoD e SubagentStop: i comandi richiesti del gate ci sono tutti e ogni
    ricevuta (ultima per comando) conta green. Con `allow_unverified` (un `approve
    unverified-tests`) anche `unverified` conta green."""
    if not required_commands:
        return False, "nessun comando richiesto"
    if not rows:
        return False, f"nessuna ricevuta su {head_sha}"
    bad = [f"{r['command']}={r['state']}" for r in rows
           if not (allow_unverified and r["state"] == "unverified")
           and not counts_green(r["state"], r["exit"], allow_no_tests)]
    have = {r["command"] for r in rows}
    missing = [c for c in required_commands if c not in have]
    if missing:
        bad.append("mancano: " + ", ".join(missing))
    return (not bad), ", ".join(bad)


def _receipt(conn, work: int, head_sha: str, allow_no_tests: bool, required_commands: list[str],
             allow_unverified: bool) -> tuple[bool, str]:
    # La ricevuta `related` è del test correlato (come in SubagentStop): non è un comando del gate.
    rows = [r for r in receipts.latest(conn, work, head_sha) if r["command"] != "related"]
    return receipt_verdict(rows, head_sha, allow_no_tests, required_commands, allow_unverified)


def _tasks(conn, work: int) -> tuple[bool, str]:
    rows = conn.execute("SELECT number, state, verdict FROM tasks WHERE work = ? ORDER BY number",
                        (work,)).fetchall()
    if not rows:
        return False, "nessun task"
    bad = [str(r["number"]) for r in rows if r["state"] != "done" or r["verdict"] != "approved"]
    return (not bad), ("task non chiusi: " + ", ".join(bad)) if bad else ""


def _findings(conn, work: int, cycle: int | None) -> tuple[bool, str]:
    """Rilievi confermati e bloccanti di gravità effettiva blocker o major, non archiviati
    (decisione 15). Con `cycle` solo quel ciclo, altrimenti tutti."""
    rows = reviews.blocking_open(conn, work, cycle)
    return (not rows), ", ".join(r["id"] for r in rows)


def _specialists(conn, work: int, expected: list[str], cycle: int | None) -> tuple[bool, str]:
    """Ogni specialista finale atteso ha riportato nel ciclo (l'ultimo se `cycle` è None)."""
    if not expected:
        return True, ""
    row = (conn.execute("SELECT reported FROM review_cycles WHERE work = ? AND number = ?",
                        (work, cycle)).fetchone() if cycle is not None
           else reviews.latest(conn, work))
    if row is None:
        return False, "nessun ciclo di revisione"
    reported = json.loads(row["reported"])
    missing = [s for s in expected if s not in reported]
    return (not missing), ("mancano: " + ", ".join(missing)) if missing else ""


def _skills(conn, work: int) -> tuple[bool, str]:
    missing = []
    for r in conn.execute("SELECT number, skills_required, skills_used FROM tasks "
                          "WHERE work = ? ORDER BY number", (work,)):
        lack = [s for s in json.loads(r["skills_required"])
                if s not in json.loads(r["skills_used"])]
        if lack:
            missing.append(f"task {r['number']}: {', '.join(lack)}")
    return (not missing), "; ".join(missing)


def compute_dod(conn, work: int, *, head_sha: str, allow_no_tests: bool,
                required_commands: list[str],
                external: Mapping[str, bool | None] | None = None,
                profile_items: Mapping[str, bool | None] | None = None,
                allow_unverified: bool = False, findings_cycle: int | None = None,
                specialists: list[str] | None = None,
                skip: tuple[str, ...] = ()) -> list[DodItem]:
    """`findings_cycle` limita i rilievi a un ciclo (decisione 15), `specialists` è l'elenco
    atteso in L2 (senza, la voce viene da `external`), `skip` salta le voci che si valutano solo
    dopo la revisione: valgono `None` e `dod_passes` le ignora solo se il chiamante le filtra."""
    external = external or {}
    level = get_work(conn, work)["level"]
    computed = {
        "receipt": lambda: _receipt(conn, work, head_sha, allow_no_tests, required_commands,
                                    allow_unverified),
        "tasks_approved": lambda: _tasks(conn, work),
        "findings": lambda: _findings(conn, work, findings_cycle),
        "skills": lambda: _skills(conn, work),
    }
    if specialists is not None:
        computed["specialists"] = lambda: _specialists(conn, work, specialists, findings_cycle)
    items = []
    for key in ITEMS_BY_LEVEL[level]:
        if key in skip:
            items.append(DodItem(key, LABELS[key], None, SKIPPED_DETAIL))
            continue
        if key in computed:
            ok, detail = computed[key]()
        else:
            ok = external.get(key)
            detail = "non calcolata" if ok is None else ""
        items.append(DodItem(key, LABELS[key], ok, detail))
    for key, ok in (profile_items or {}).items():
        items.append(DodItem(key, f"Voce del profilo {key.removeprefix('profile:')}", ok,
                             "non calcolata" if ok is None else ""))
    return items


def dod_passes(items: list[DodItem]) -> bool:
    return bool(items) and all(i.ok is True for i in items)
