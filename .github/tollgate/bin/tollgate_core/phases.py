"""Lavori, fasi (spec 12.3) e blocchi (spec 8.3)."""
from __future__ import annotations

import json
import sqlite3

from . import clock, db
from .events import record_event
from .paths import State

PHASES = ("spec_audit", "plan", "approval", "execution", "review", "pr_open", "closed", "blocked")
SEQUENCES = {
    "L0": ("execution", "review", "pr_open", "closed"),
    "L1": ("plan", "execution", "review", "pr_open", "closed"),
    "L2": ("spec_audit", "plan", "approval", "execution", "review", "pr_open", "closed"),
}
INITIAL = {"L0": "execution", "L1": "plan", "L2": "spec_audit"}
LEVELS = ("L0", "L1", "L2")
BLOCK_TYPES = ("needs_you", "test_spec_conflict", "dependency", "permission", "transient")
CLOSE_CAUSES = frozenset({"merged", "closed_unmerged", "abandoned"})
# Il passaggio in avanti di L2 ha una causa propria: la fase non avanza senza l'atto o il giro
# pulito che la giustifica (decisione 11).
_FORWARD_CONDITION = {
    ("execution", "review"): "finish_check_green",
    ("spec_audit", "plan"): "approve_spec",
    ("plan", "approval"): "audit_clean",
    ("approval", "execution"): "approve_plan",
}
_BACK = {
    ("review", "execution"): {"needs_fix", "start"},
    ("pr_open", "execution"): {"start", "sync"},
    ("plan", "spec_audit"): {"reopen_spec"},
    ("approval", "spec_audit"): {"reopen_spec"},
    ("execution", "spec_audit"): {"reopen_spec"},
    ("approval", "plan"): {"reopen_plan"},
    ("execution", "plan"): {"reopen_plan"},
}


class TransitionError(Exception):
    pass


class WorkExists(Exception):
    pass


def check_transition(level: str, frm: str, to: str, cause: str) -> None:
    if frm == "closed":
        raise TransitionError("il lavoro è chiuso")
    if to == "closed":
        if cause in CLOSE_CAUSES:
            return
        raise TransitionError(f"chiusura solo per {', '.join(sorted(CLOSE_CAUSES))}")
    if "blocked" in (frm, to):
        raise TransitionError("la fase blocked si apre e si chiude solo con i blocchi")
    if level == "L0" and (frm, to, cause) == ("execution", "plan", "l0_grew"):
        return
    seq = SEQUENCES[level]
    if frm in seq and to in seq:
        if seq.index(to) == seq.index(frm) + 1:
            needed = _FORWARD_CONDITION.get((frm, to), "advance")
            if cause == needed:
                return
            raise TransitionError(f"{frm} → {to} solo con {needed}")
        if cause in _BACK.get((frm, to), ()):
            return
    raise TransitionError(f"transizione non ammessa in {level}: {frm} → {to} ({cause})")


def get_work(conn: sqlite3.Connection, work: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM work_items WHERE id = ?", (work,)).fetchone()
    if row is None:
        raise ValueError(f"lavoro {work} inesistente")
    return row


def find_active(conn, repo_key: str, issue: int):
    return conn.execute("SELECT * FROM work_items WHERE repo_key = ? AND issue = ? "
                        "AND phase <> 'closed'", (repo_key, issue)).fetchone()


def find_latest(conn, repo_key: str, issue: int):
    return conn.execute("SELECT * FROM work_items WHERE repo_key = ? AND issue = ? "
                        "ORDER BY id DESC LIMIT 1", (repo_key, issue)).fetchone()


def create_work(conn, *, repo_key: str, issue: int, level: str, now, session=None, branch=None,
                worktree=None, work_base_sha=None, gate_mode=None, spec_path=None,
                from_approved_spec: bool = False, phase: str | None = None,
                cause: str = "start") -> int:
    """`phase` (adopt, spec 12.4) fa partire il lavoro da una fase diversa dalla iniziale: deve
    stare nella sequenza del livello e non essere `closed`; esclude `from_approved_spec`."""
    if level not in LEVELS:
        raise ValueError(f"livello sconosciuto: {level}")
    if from_approved_spec and phase is None and not spec_path:
        raise ValueError("from_approved_spec richiede spec_path")
    if phase is not None:
        if from_approved_spec:
            raise ValueError("phase e from_approved_spec si escludono")
        if phase == "closed" or phase not in SEQUENCES[level]:
            raise ValueError(f"fase iniziale non ammessa in {level}: {phase}")
    else:
        phase = "plan" if (level == "L2" and from_approved_spec) else INITIAL[level]
    ts = clock.fmt(now)
    with db.tx(conn):
        try:
            cur = conn.execute(
                "INSERT INTO work_items (repo_key, issue, level, phase, branch, worktree, "
                "work_base_sha, gate_mode, spec_path, sessions, created, updated) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (repo_key, issue, level, phase, branch, worktree, work_base_sha, gate_mode,
                 spec_path, json.dumps([session] if session else []), ts, ts))
        except sqlite3.IntegrityError as e:
            raise WorkExists(f"esiste già un lavoro attivo per {repo_key}#{issue}") from e
        work = cur.lastrowid
        record_event(conn, "phase_change", {"from": None, "to": phase, "cause": cause},
                     now=now, session=session, work=work)
    return work


def bind_session(conn, work: int, session: str, *, now) -> None:
    with db.tx(conn):
        row = get_work(conn, work)
        if row["phase"] == "closed":
            raise TransitionError("il lavoro è chiuso")
        sessions = json.loads(row["sessions"])
        if session not in sessions:
            sessions.append(session)
            conn.execute("UPDATE work_items SET sessions = ?, updated = ? WHERE id = ?",
                         (json.dumps(sessions), clock.fmt(now), work))


def set_worktree(conn, work: int, path, *, now) -> None:
    """Il percorso del worktree cambia quando la ripresa lo ricrea altrove."""
    with db.tx(conn):
        get_work(conn, work)
        conn.execute("UPDATE work_items SET worktree = ?, updated = ? WHERE id = ?",
                     (str(path), clock.fmt(now), work))


def set_spec_path(conn, work: int, path: str, *, now) -> None:
    """Registra la spec del lavoro, una volta sola: una già registrata non si cambia."""
    with db.tx(conn):
        get_work(conn, work)
        conn.execute("UPDATE work_items SET spec_path = ?, updated = ? "
                     "WHERE id = ? AND spec_path IS NULL", (path, clock.fmt(now), work))


def set_base(conn, work: int, sha: str, *, cause: str, now, session=None) -> None:
    """Riallinea la base del lavoro (sync, approve rebase, spec 6.5)."""
    with db.tx(conn):
        row = get_work(conn, work)
        conn.execute("UPDATE work_items SET work_base_sha = ?, updated = ? WHERE id = ?",
                     (sha, clock.fmt(now), work))
        record_event(conn, "base_realigned",
                     {"from": row["work_base_sha"], "to": sha, "cause": cause},
                     now=now, session=session, work=work)


def set_pr(conn, work: int, number: int | None, url: str | None, *, now) -> None:
    with db.tx(conn):
        get_work(conn, work)
        conn.execute("UPDATE work_items SET pr_number = ?, pr_url = ?, updated = ? "
                     "WHERE id = ?", (number, url, clock.fmt(now), work))


def set_finish(conn, work: int, sha: str | None, report: dict | None, *, now) -> None:
    """SHA dell'ultimo `finish check` verde e le voci calcolate (JSON)."""
    with db.tx(conn):
        get_work(conn, work)
        conn.execute("UPDATE work_items SET finish_sha = ?, finish_report = ?, updated = ? "
                     "WHERE id = ?",
                     (sha, None if report is None else json.dumps(report, ensure_ascii=False),
                      clock.fmt(now), work))


def add_extra_cycles(conn, work: int, n: int, *, now) -> int:
    """Cicli di revisione concessi oltre i quattro (decisione 13). Dà il nuovo totale."""
    with db.tx(conn):
        get_work(conn, work)
        conn.execute("UPDATE work_items SET extra_review_cycles = extra_review_cycles + ?, "
                     "updated = ? WHERE id = ?", (n, clock.fmt(now), work))
        return get_work(conn, work)["extra_review_cycles"]


def set_review_unverified(conn, work: int, *, now) -> None:
    with db.tx(conn):
        get_work(conn, work)
        conn.execute("UPDATE work_items SET review_unverified = 1, updated = ? WHERE id = ?",
                     (clock.fmt(now), work))


def _change_phase(conn, work: int, frm: str, to: str, cause: str, now, session) -> None:
    conn.execute("UPDATE work_items SET phase = ?, updated = ? WHERE id = ?",
                 (to, clock.fmt(now), work))
    record_event(conn, "phase_change", {"from": frm, "to": to, "cause": cause},
                 now=now, session=session, work=work)


def set_phase(conn, state: State, work: int, to: str, cause: str, *, now, session=None) -> None:
    if conn.in_transaction:
        raise RuntimeError("set_phase va chiamato fuori da una transazione: "
                           "la copia del DB deve vedere solo dati confermati")
    with db.tx(conn):
        row = get_work(conn, work)
        check_transition(row["level"], row["phase"], to, cause)
        _change_phase(conn, work, row["phase"], to, cause, now, session)
        if to == "closed":
            conn.execute("UPDATE work_items SET closed_reason = ?, phase_before_block = NULL "
                         "WHERE id = ?", (cause, work))
            for b in conn.execute("SELECT id FROM blocks WHERE work = ? AND closed IS NULL",
                                  (work,)).fetchall():
                conn.execute("UPDATE blocks SET closed = ?, resolution = ? WHERE id = ?",
                             (clock.fmt(now), f"lavoro chiuso: {cause}", b["id"]))
                record_event(conn, "block_closed", {"id": b["id"]},
                             now=now, session=session, work=work)
        if cause == "l0_grew":
            conn.execute("UPDATE work_items SET level = 'L1' WHERE id = ?", (work,))
            record_event(conn, "level_change", {"from": "L0", "to": "L1"},
                         now=now, session=session, work=work)
    db.backup(conn, state, f"fase-{to}")


def set_level(conn, work: int, level: str, *, now, session=None) -> None:
    if level not in LEVELS:
        raise ValueError(f"livello sconosciuto: {level}")
    with db.tx(conn):
        row = get_work(conn, work)
        if row["phase"] == "closed":
            raise TransitionError("il lavoro è chiuso")
        current = row["level"]
        if LEVELS.index(level) < LEVELS.index(current):
            raise TransitionError("il livello si abbassa solo con un atto dell'utente (tetto)")
        if level != current:
            conn.execute("UPDATE work_items SET level = ?, updated = ? WHERE id = ?",
                         (level, clock.fmt(now), work))
            record_event(conn, "level_change", {"from": current, "to": level},
                         now=now, session=session, work=work)


def set_level_cap(conn, work: int, cap: str, reason: str, cap_paths: list[str], *, now,
                  session=None) -> None:
    """Tetto al livello (spec 5, decisione 14): ammesso solo se la fase corrente (per `blocked`,
    quella prima del blocco) esiste nella sequenza di `cap`. Non tocca la fase."""
    if cap not in LEVELS:
        raise ValueError(f"livello sconosciuto: {cap}")
    with db.tx(conn):
        row = get_work(conn, work)
        phase = row["phase_before_block"] if row["phase"] == "blocked" else row["phase"]
        if row["phase"] == "closed":
            raise TransitionError("il lavoro è chiuso")
        if phase not in SEQUENCES[cap]:
            raise TransitionError(f"{cap} non ha la fase {phase}: il livello si abbassa solo "
                                  "in una fase che esiste anche nella sequenza di arrivo")
        conn.execute("UPDATE work_items SET level_cap = ?, level_cap_reason = ?, "
                     "level_cap_paths = ?, updated = ? WHERE id = ?",
                     (cap, reason, json.dumps(list(cap_paths)), clock.fmt(now), work))
        if LEVELS.index(cap) < LEVELS.index(row["level"]):
            conn.execute("UPDATE work_items SET level = ? WHERE id = ?", (cap, work))
            record_event(conn, "level_change",
                         {"from": row["level"], "to": cap, "cause": "cap"},
                         now=now, session=session, work=work)


def open_block(conn, state: State, work: int, type_: str, reason: str, *, now,
               session=None) -> int:
    if type_ not in BLOCK_TYPES:
        raise ValueError(f"tipo di blocco sconosciuto: {type_}")
    if conn.in_transaction:
        raise RuntimeError("open_block va chiamato fuori da una transazione")
    with db.tx(conn):
        row = get_work(conn, work)
        if row["phase"] == "closed":
            raise TransitionError("il lavoro è chiuso")
        cur = conn.execute("INSERT INTO blocks (work, type, reason, opened) VALUES (?, ?, ?, ?)",
                           (work, type_, reason, clock.fmt(now)))
        block = cur.lastrowid
        changed = row["phase"] != "blocked"
        if changed:
            conn.execute("UPDATE work_items SET phase_before_block = ? WHERE id = ?",
                         (row["phase"], work))
            _change_phase(conn, work, row["phase"], "blocked", "block", now, session)
        record_event(conn, "block_opened", {"id": block, "type": type_},
                     now=now, session=session, work=work)
    if changed:
        db.backup(conn, state, "fase-blocked")
    return block


def close_block(conn, state: State, block_id: int, resolution: str, *, now,
                session=None) -> str:
    if conn.in_transaction:
        raise RuntimeError("close_block va chiamato fuori da una transazione")
    with db.tx(conn):
        b = conn.execute("SELECT * FROM blocks WHERE id = ?", (block_id,)).fetchone()
        if b is None or b["closed"] is not None:
            raise TransitionError(f"blocco {block_id} inesistente o già chiuso")
        work = b["work"]
        conn.execute("UPDATE blocks SET closed = ?, resolution = ? WHERE id = ?",
                     (clock.fmt(now), resolution, block_id))
        record_event(conn, "block_closed", {"id": block_id}, now=now, session=session, work=work)
        row = get_work(conn, work)
        still_open = conn.execute("SELECT count(*) FROM blocks WHERE work = ? AND closed IS NULL",
                                  (work,)).fetchone()[0]
        changed = still_open == 0 and row["phase"] == "blocked"
        if changed:
            back = row["phase_before_block"]
            conn.execute("UPDATE work_items SET phase_before_block = NULL WHERE id = ?", (work,))
            _change_phase(conn, work, "blocked", back, "unblock", now, session)
        phase = get_work(conn, work)["phase"]
    if changed:
        db.backup(conn, state, f"fase-{phase}")
    return phase
