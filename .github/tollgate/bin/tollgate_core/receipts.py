"""Ricevute locali (spec 8.1): le producono solo verify e finish check."""
from __future__ import annotations

from . import clock, db
from .events import record_event

STATES = ("green", "red", "empty", "uncounted", "unverified")


def add(conn, *, work: int | None, sha: str, command: str, resolved_command: str | None,
        exit_code: int | None, tests_run: int | None, tests_skipped: int | None,
        duration: float | None, log: str | None, produced_by: str, state: str, now,
        session=None) -> int:
    if state not in STATES:
        raise ValueError(f"stato di ricevuta sconosciuto: {state}")
    with db.tx(conn):
        cur = conn.execute(
            "INSERT INTO receipts (work, sha, command, resolved_command, exit, tests_run, "
            "tests_skipped, duration, log, produced_by, state, at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (work, sha, command, resolved_command, exit_code, tests_run, tests_skipped,
             duration, log, produced_by, state, clock.fmt(now)))
        record_event(conn, "receipt", {"sha": sha, "command": command, "state": state,
                                       "tests_run": tests_run},
                     now=now, session=session, work=work)
        return cur.lastrowid


def latest(conn, work: int | None, sha: str) -> list:
    return conn.execute(
        "SELECT r.* FROM receipts r WHERE r.work IS ? AND r.sha = ? AND r.id = "
        "(SELECT max(id) FROM receipts x WHERE x.work IS r.work AND x.sha = r.sha "
        "AND x.command = r.command) ORDER BY r.command", (work, sha)).fetchall()


def any_since(conn, work: int, since: str) -> bool:
    return conn.execute("SELECT 1 FROM receipts WHERE work = ? AND at >= ? LIMIT 1",
                        (work, since)).fetchone() is not None
