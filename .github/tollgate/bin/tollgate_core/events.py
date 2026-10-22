"""Registro degli eventi (spec 18.4): sola aggiunta, seq monotono, potatura oltre events_days."""
from __future__ import annotations

import json
import socket
import sqlite3
from datetime import datetime, timedelta

from . import clock, git
from .db import tx

ENVELOPE_VERSION = 1
EVENT_TYPES = frozenset({
    "session_start", "act", "phase_change", "level_change", "scope_registered", "waiver_added",
    "block_opened", "block_closed", "commit", "receipt", "subagent_start", "subagent_stop",
    "veto", "effect_requested", "effect_executed", "review_cycle", "pr_opened", "pr_updated",
    "merge_detected", "sentinel_alert", "spec_audit_round", "act_expired", "task_change",
    "finding", "off", "on", "finish_check", "base_realigned", "plan_reset", "skills_absent",
})
_COLUMNS = "seq, v, at, host, session, work, repo_key, issue, type, data"


def record_event(conn: sqlite3.Connection, type_: str, data: dict | None = None, *,
                 now: datetime, session: str | None = None, work: int | None = None,
                 host: str | None = None) -> int:
    if type_ not in EVENT_TYPES:
        raise ValueError(f"tipo di evento sconosciuto: {type_}")
    with tx(conn):
        repo_key = issue = None
        if work is not None:
            row = conn.execute("SELECT repo_key, issue FROM work_items WHERE id = ?",
                               (work,)).fetchone()
            if row is None:
                raise ValueError(f"lavoro {work} inesistente")
            repo_key, issue = row[0], row[1]
        cur = conn.execute(
            "INSERT INTO events (v, at, host, session, work, repo_key, issue, type, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ENVELOPE_VERSION, clock.fmt(now), host or socket.gethostname(), session, work,
             repo_key, issue, type_, json.dumps(data or {}, ensure_ascii=False, sort_keys=True)))
        return cur.lastrowid


def known_commits(conn: sqlite3.Connection, work: int) -> set[str]:
    return {json.loads(r[0]).get("sha") for r in conn.execute(
        "SELECT data FROM events WHERE type = 'commit' AND work = ?", (work,))}


def record_commits(conn: sqlite3.Connection, work: int, wt, base: str, *, now,
                   session: str | None = None) -> int:
    """Gli eventi `commit` dei commit di `base..HEAD` non ancora noti (rebase, integrazioni):
    PostToolUse Bash non li tratta come nuovi del lavoro. Dà quanti ne ha registrati."""
    known = known_commits(conn, work)
    new = [s for s in git.rev_list(wt, base, git.head(wt)) if s not in known]
    for sha in new:
        record_event(conn, "commit", {"sha": sha}, now=now, session=session, work=work)
    return len(new)


def _as_dict(row) -> dict:
    d = {k: row[k] for k in ("seq", "v", "at", "host", "session", "work", "repo_key", "issue",
                             "type")}
    d["data"] = json.loads(row["data"])
    return d


def export_events(conn: sqlite3.Connection, after_seq: int) -> list[dict]:
    rows = conn.execute(f"SELECT {_COLUMNS} FROM events WHERE seq > ? ORDER BY seq",
                        (after_seq,)).fetchall()
    return [_as_dict(r) for r in rows]


def to_jsonl(items: list[dict]) -> str:
    return "".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in items)


def prune_events(conn: sqlite3.Connection, now: datetime, events_days: int) -> int:
    limit = clock.fmt(now - timedelta(days=events_days))
    with tx(conn):
        return conn.execute("DELETE FROM events WHERE at < ?", (limit,)).rowcount
