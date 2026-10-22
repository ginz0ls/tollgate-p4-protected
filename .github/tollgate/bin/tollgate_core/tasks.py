"""Task del piano e transizioni di tasks.state (spec 6.3)."""
from __future__ import annotations

import json
import sqlite3

from . import clock, db
from .events import record_event

STATES = ("pending", "running", "review", "done", "blocked")
KINDS = ("plan", "fix")
_TRANSITIONS = {
    ("pending", "start"): "running",
    ("running", "report_done"): "review",
    ("running", "report_blocked"): "blocked",
    ("running", "needs_context"): "running",
    ("running", "budget_exceeded"): "blocked",
    ("running", "interrupted"): "pending",
    ("review", "fix"): "running",
    ("review", "approved"): "done",
    ("blocked", "unblocked"): "pending",
}
TASK_EVENTS = tuple(sorted({e for _, e in _TRANSITIONS}))
_VERDICT = {"fix": "changes", "approved": "approved"}
BASE_FIX_ROUNDS = 5       # giri di correzione senza deroghe (P3a)
MAX_FIX_ROUNDS = 8        # tetto in tutto, con `approve rounds` (decisione 13)
VERDICTS = ("approved", "changes")


class TaskTransitionError(Exception):
    pass


def get_task(conn, work: int, number: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM tasks WHERE work = ? AND number = ?",
                       (work, number)).fetchone()
    if row is None:
        raise ValueError(f"task {number} del lavoro {work} inesistente")
    return row


def next_number(conn, work: int) -> int:
    return conn.execute("SELECT coalesce(max(number), 0) + 1 FROM tasks WHERE work = ?",
                        (work,)).fetchone()[0]


def _log(conn, row, *, now, session, **extra) -> None:
    record_event(conn, "task_change",
                 {"number": row["number"], "kind": row["kind"], "state": row["state"],
                  "fix_rounds": row["fix_rounds"], "verdict": row["verdict"], **extra},
                 now=now, session=session, work=row["work"])


def add_task(conn, work: int, number: int, *, source: str, kind: str = "plan",
             skills_required: list[str] | None = None, task_text: str | None = None, now,
             session=None) -> None:
    if kind not in KINDS:
        raise ValueError(f"tipo di task sconosciuto: {kind}")
    with db.tx(conn):
        try:
            conn.execute("INSERT INTO tasks (work, number, kind, source, state, skills_required, "
                         "task_text) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                         (work, number, kind, source, json.dumps(skills_required or []),
                          task_text))
        except sqlite3.IntegrityError as e:
            raise ValueError(f"task {number} già presente nel lavoro {work}") from e
        _log(conn, get_task(conn, work, number), now=now, session=session)


def task_event(conn, work: int, number: int, event: str, *, now, session=None) -> str:
    if event not in TASK_EVENTS:
        raise ValueError(f"evento di task sconosciuto: {event}")
    with db.tx(conn):
        row = get_task(conn, work, number)
        new = _TRANSITIONS.get((row["state"], event))
        if new is None:
            raise TaskTransitionError(f"task {number}: {event} non ammesso da {row['state']}")
        fix_rounds = row["fix_rounds"] + (1 if event == "fix" else 0)
        verdict = _VERDICT.get(event, row["verdict"])
        # Un giro di correzione invalida la revisione precedente: il verdetto resta (lo storico),
        # ma `review_sha` torna vuoto finché `review-prepare` non ne prepara una nuova.
        reset = ", review_code = NULL, review_sha = NULL" if event == "fix" else ""
        conn.execute(f"UPDATE tasks SET state = ?, fix_rounds = ?, verdict = ?{reset} "
                     "WHERE work = ? AND number = ?", (new, fix_rounds, verdict, work, number))
        _log(conn, get_task(conn, work, number), now=now, session=session)
    return new


def add_extra_rounds(conn, work: int, number: int, n: int) -> int:
    """Giri di correzione concessi oltre i cinque (`approve rounds`, decisione 13). Dà il nuovo
    totale dei giri extra; `ValueError` se `n` non è positivo o i giri in tutto superano 8."""
    if n < 1:
        raise ValueError("i giri da aggiungere devono essere almeno uno")
    with db.tx(conn):
        row = get_task(conn, work, number)
        extra = row["extra_fix_rounds"] + n
        if BASE_FIX_ROUNDS + extra > MAX_FIX_ROUNDS:
            raise ValueError(f"task {number}: al massimo {MAX_FIX_ROUNDS} giri di correzione in "
                             f"tutto ({BASE_FIX_ROUNDS} più {MAX_FIX_ROUNDS - BASE_FIX_ROUNDS} "
                             "concessi)")
        conn.execute("UPDATE tasks SET extra_fix_rounds = ? WHERE work = ? AND number = ?",
                     (extra, work, number))
        return extra


def unblock_all(conn, work: int, *, now, session=None) -> list[int]:
    """Ogni task `blocked` del lavoro torna `pending` (evento `unblocked`) in una sola
    transazione: o tutti o nessuno. Dà i numeri sbloccati."""
    with db.tx(conn):
        numbers = [r["number"] for r in conn.execute(
            "SELECT number FROM tasks WHERE work = ? AND state = 'blocked' ORDER BY number",
            (work,)).fetchall()]
        for n in numbers:
            task_event(conn, work, n, "unblocked", now=now, session=session)
    return numbers


def add_skill_used(conn, work: int, number: int, skill: str) -> None:
    with db.tx(conn):
        used = json.loads(get_task(conn, work, number)["skills_used"])
        if skill not in used:
            used.append(skill)
            conn.execute("UPDATE tasks SET skills_used = ? WHERE work = ? AND number = ?",
                         (json.dumps(used), work, number))


PENDING = ("launch", "resume")


def assign(conn, work: int, number: int, *, implementer: str, agent_type: str, pending: str,
           reviewer_type: str | None = None, now, session=None) -> None:
    """Scritto da `task start` (P3): chi può partire o riprendere su questo task (6.3)."""
    if pending not in PENDING:
        raise ValueError(f"pending sconosciuto: {pending}")
    with db.tx(conn):
        get_task(conn, work, number)
        conn.execute("UPDATE tasks SET implementer = ?, agent_type = ?, "
                     "reviewer_type = coalesce(?, reviewer_type), "
                     "pending = ? WHERE work = ? AND number = ?",
                     (implementer, agent_type, reviewer_type, pending, work, number))
        _log(conn, get_task(conn, work, number), now=now, session=session)


def take_pending(conn, work: int, *, agent_type: str, resume: bool,
                 number: int | None = None) -> int | None:
    """Associa un subagente che parte (o riprende) al task in sospeso del suo tipo. Con `number`
    guarda solo quel task (la ripresa sa già di chi è). Azzera anche la prenotazione del lancio."""
    want = "resume" if resume else "launch"
    with db.tx(conn):
        row = conn.execute("SELECT number FROM tasks WHERE work = ? AND pending = ? "
                           "AND agent_type = ? AND (? IS NULL OR number = ?) "
                           "ORDER BY number LIMIT 1",
                           (work, want, agent_type, number, number)).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE tasks SET pending = NULL, reserved_at = NULL "
                     "WHERE work = ? AND number = ?", (work, row["number"]))
        return row["number"]


def reserve(conn, work: int, number: int, *, now) -> None:
    """Prenota il lancio: un secondo `Agent` sullo stesso task entro 120 s è negato (decisione 12)."""
    with db.tx(conn):
        get_task(conn, work, number)
        conn.execute("UPDATE tasks SET reserved_at = ? WHERE work = ? AND number = ?",
                     (clock.fmt(now), work, number))


def clear_reservation(conn, work: int, number: int) -> None:
    with db.tx(conn):
        conn.execute("UPDATE tasks SET reserved_at = NULL WHERE work = ? AND number = ?",
                     (work, number))


def set_skills_required(conn, work: int, number: int, skills: list[str]) -> None:
    with db.tx(conn):
        get_task(conn, work, number)
        conn.execute("UPDATE tasks SET skills_required = ? WHERE work = ? AND number = ?",
                     (json.dumps(skills), work, number))


def set_review_prep(conn, work: int, number: int, *, sha: str, code: str) -> None:
    """`review-prepare`: sha e codice della revisione; un verdetto precedente non vale più."""
    with db.tx(conn):
        get_task(conn, work, number)
        conn.execute("UPDATE tasks SET review_sha = ?, review_code = ?, verdict = NULL, "
                     "review_findings = '[]' WHERE work = ? AND number = ?",
                     (sha, code, work, number))


def set_verdict(conn, work: int, number: int, *, outcome: str, findings: list[dict], now,
                session=None, dropped: int = 0) -> None:
    """Verdetto del revisore: lo stato del task non cambia (lo muove `task done` o `--fix`)."""
    if outcome not in VERDICTS:
        raise ValueError(f"esito del verdetto sconosciuto: {outcome}")
    with db.tx(conn):
        get_task(conn, work, number)
        conn.execute("UPDATE tasks SET verdict = ?, review_findings = ? "
                     "WHERE work = ? AND number = ?",
                     (outcome, json.dumps(findings, ensure_ascii=False), work, number))
        _log(conn, get_task(conn, work, number), now=now, session=session, dropped=dropped)


def add_commit(conn, work: int, number: int, sha: str) -> None:
    with db.tx(conn):
        commits = json.loads(get_task(conn, work, number)["commits"])
        if sha not in commits:
            commits.append(sha)
            conn.execute("UPDATE tasks SET commits = ? WHERE work = ? AND number = ?",
                         (json.dumps(commits), work, number))
