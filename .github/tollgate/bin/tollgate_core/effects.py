"""Effetti esterni come intenti (spec 8.5): veto, atto, una esecuzione, avviso se ripetuto."""
from __future__ import annotations

import hashlib
import json

from . import clock, db
from .events import record_event


def effect_key(command: str, work: int | None, sha: str | None) -> str:
    raw = f"{command}\0{'' if work is None else work}\0{sha or ''}"
    return hashlib.sha256(raw.encode("utf-8", "surrogateescape")).hexdigest()


def effect_id(key: str) -> str:
    return f"e-{key[:8]}"


def get(conn, key: str):
    return conn.execute("SELECT * FROM intents WHERE idempotency_key = ?",
                        (f"effect:{key}",)).fetchone()


def executed_at(row) -> str | None:
    return json.loads(row["data"] or "{}").get("executed_at") if row else None


def request(conn, *, key: str, command: str, work: int | None, sha: str | None, now,
            session=None) -> None:
    eid = effect_id(key)
    with db.tx(conn):
        row = get(conn, key)
        if row is None:
            data = {"id": eid, "command": command, "sha": sha}
            conn.execute("INSERT INTO intents (work, action, idempotency_key, data, state, at) "
                         "VALUES (?, 'effect', ?, ?, 'requested', ?)",
                         (work, f"effect:{key}", json.dumps(data), clock.fmt(now)))
        else:
            conn.execute("UPDATE intents SET state = 'requested' WHERE id = ?", (row["id"],))
        record_event(conn, "effect_requested", {"command_hash": key, "id": eid},
                     now=now, session=session, work=work)


def mark_executed(conn, *, key: str, act_id: str, now, session=None) -> None:
    with db.tx(conn):
        row = get(conn, key)
        if row is None:
            raise ValueError(f"effetto {effect_id(key)} mai richiesto")
        data = json.loads(row["data"] or "{}")
        data["executed_at"] = clock.fmt(now)
        data["act_id"] = act_id
        conn.execute("UPDATE intents SET state = 'executed', outcome = ?, data = ? WHERE id = ?",
                     (clock.fmt(now), json.dumps(data), row["id"]))
        record_event(conn, "effect_executed", {"command_hash": key, "id": effect_id(key),
                                               "act_id": act_id},
                     now=now, session=session, work=row["work"])
