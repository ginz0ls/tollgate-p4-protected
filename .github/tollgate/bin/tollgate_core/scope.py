"""Scope del piano e registrazione del piano (spec 7.5, 6.2)."""
from __future__ import annotations

from . import clock, db, phases, tasks
from .events import record_event


def paths(conn, work: int) -> set[str]:
    return {r[0] for r in conn.execute("SELECT path FROM scope WHERE work = ?", (work,))}


def set_plan_path(conn, work: int, plan_path: str, *, now) -> None:
    """In L2 il piano si registra come percorso; scope e plan_sha arrivano con approve plan."""
    with db.tx(conn):
        conn.execute("UPDATE work_items SET plan_path = ?, updated = ? "
                     "WHERE id = ? AND plan_path IS NULL", (plan_path, clock.fmt(now), work))


def reset_plan(conn, work: int, *, now, session=None) -> list[int]:
    """Ritira la registrazione del piano (reopen, decisione 12): toglie lo scope `plan`, azzera
    `plan_sha` e cancella i task del lavoro, di cui dà i numeri. `plan_path` resta, così
    `post_edit` riconosce lo stesso file. Le righe storiche dei subagenti restano, ma senza il
    numero del task: il piano nuovo rinumera i task e non deve ereditare i loro report."""
    with db.tx(conn):
        row = phases.get_work(conn, work)
        if row["plan_sha"] is None:
            return []
        numbers = [r[0] for r in conn.execute(
            "SELECT number FROM tasks WHERE work = ? ORDER BY number", (work,))]
        conn.execute("DELETE FROM scope WHERE work = ? AND origin = 'plan'", (work,))
        conn.execute("UPDATE subagents SET task = NULL WHERE work = ? AND task IS NOT NULL",
                     (work,))
        conn.execute("DELETE FROM tasks WHERE work = ?", (work,))
        conn.execute("UPDATE work_items SET plan_sha = NULL, updated = ? WHERE id = ?",
                     (clock.fmt(now), work))
        record_event(conn, "plan_reset", {"plan_sha": row["plan_sha"], "tasks": numbers},
                     now=now, session=session, work=work)
        return numbers


def register_plan(conn, state, work: int, *, plan_path: str, plan_sha: str,
                  scope_paths: list[str], plan_tasks: list[tuple[int, list[str]]],
                  advance: bool, now, session=None) -> None:
    """Scope e task dal piano; una volta registrato lo scope non cresce (7.5)."""
    with db.tx(conn):
        row = phases.get_work(conn, work)
        if row["plan_sha"] is not None:
            raise ValueError("piano già registrato: per cambiarlo serve /tollgate:reopen plan")
        ts = clock.fmt(now)
        conn.execute("UPDATE work_items SET plan_path = ?, plan_sha = ?, updated = ? "
                     "WHERE id = ?", (plan_path, plan_sha, ts, work))
        for p in dict.fromkeys(scope_paths):
            conn.execute("INSERT INTO scope (work, path, origin, registered_at) "
                         "VALUES (?, ?, 'plan', ?)", (work, p, ts))
        for number, skills in plan_tasks:
            tasks.add_task(conn, work, number, source="plan", skills_required=skills, now=now,
                           session=session)
        record_event(conn, "scope_registered",
                     {"count": len(set(scope_paths)), "plan": plan_path, "plan_sha": plan_sha},
                     now=now, session=session, work=work)
    if advance:
        phases.set_phase(conn, state, work, "execution", "advance", now=now, session=session)
