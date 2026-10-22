"""Atti dell'utente (spec 8.4): registrazione, legame, scadenza, consumo."""
from __future__ import annotations

import json
from datetime import timedelta

from . import clock, db
from .events import record_event

ACT_TYPES = frozenset({"finish", "approve", "reopen", "resolve", "sync", "adopt", "abandon",
                       "cleanup", "off", "on"})
APPROVE_OBJECTS = frozenset({"spec", "plan", "waiver", "level", "effect", "finding", "rounds",
                             "unverified-review", "unverified-tests", "rebase", "pr"})
_ONE_SHOT = frozenset({("finish", None), ("approve", "effect"), ("approve", "pr"),
                       ("approve", "rebase"), ("sync", None), ("adopt", None),
                       ("cleanup", None), ("abandon", None)})
# Un finish decade appena il lavoro riceve un commit successivo all'atto (spec 8.4):
# HEAD tornato allo SHA registrato non lo riattiva.
_FINISH_ALIVE = ("AND NOT EXISTS (SELECT 1 FROM events e WHERE e.work = acts.work "
                 "AND e.type = 'commit' AND e.at > acts.at)")


class ActError(Exception):
    pass


def is_one_shot(type_: str, object_: str | None) -> bool:
    return (type_, object_) in _ONE_SHOT


def record_act(conn, *, type_: str, object_: str | None = None, target: str | None = None,
               args: list[str] | None = None, typed_text: str, source: str = "claude-code",
               actor: str | None = None, session: str | None, work: int | None = None,
               head_sha: str | None = None, now, ttl_minutes: int) -> str:
    if type_ not in ACT_TYPES:
        raise ValueError(f"atto sconosciuto: {type_}")
    if type_ == "approve" and object_ not in APPROVE_OBJECTS:
        raise ValueError(f"oggetto di approve sconosciuto: {object_}")
    if type_ == "finish" and (work is None or not head_sha):
        raise ValueError("finish richiede il lavoro e lo SHA di HEAD")
    if type_ != "finish" and session is None:
        raise ValueError(f"l'atto {type_} richiede la sessione")
    expires = None if type_ == "finish" else clock.fmt(now + timedelta(minutes=ttl_minutes))
    with db.tx(conn):
        cur = conn.execute(
            "INSERT INTO acts (type, object, target, args, at, typed_text, source, actor, "
            "session, work, head_sha, state, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
            (type_, object_, target, json.dumps(args or []), clock.fmt(now), typed_text, source,
             actor, session, work, head_sha, expires))
        act_id = f"a-{cur.lastrowid}"
        conn.execute("UPDATE acts SET act_id = ? WHERE n = ?", (act_id, cur.lastrowid))
        record_event(conn, "act", {"act_id": act_id, "type": type_, "object": object_,
                                   "target": target, "args": args or [], "source": source,
                                   "actor": actor}, now=now, session=session, work=work)
    return act_id


def find_usable(conn, *, type_: str, object_: str | None = None, target: str | None = None,
                work: int | None, session: str | None, now, head_sha: str | None = None):
    sql = ("SELECT * FROM acts WHERE state = 'pending' AND type = ? AND object IS ? "
           "AND target IS ? AND work IS ?")
    params: list = [type_, object_, target, work]
    if type_ == "finish":
        sql += " AND head_sha = ? " + _FINISH_ALIVE
        params.append(head_sha)
    else:
        if session is None:
            raise ValueError(f"l'atto {type_} richiede la sessione")
        sql += " AND session = ? AND expires_at > ?"
        params += [session, clock.fmt(now)]
    return conn.execute(sql + " ORDER BY n DESC LIMIT 1", params).fetchone()


def consume(conn, act_id: str, *, type_: str, object_: str | None = None,
            target: str | None = None, now, work: int | None, session: str | None,
            head_sha: str | None = None) -> None:
    """Consuma l'atto se e' del tipo, oggetto e target attesi e vale per questo lavoro,
    sessione (o SHA per finish) e istante."""
    with db.tx(conn):
        row = conn.execute("SELECT * FROM acts WHERE act_id = ?", (act_id,)).fetchone()
        if row is None or row["state"] != "pending":
            raise ActError(f"atto {act_id} inesistente o non più valido")
        if (row["type"], row["object"], row["target"]) != (type_, object_, target):
            raise ActError(f"atto {act_id} non è del tipo, oggetto o target richiesto")
        if row["work"] != work:
            raise ActError(f"atto {act_id} non vale per questo lavoro")
        if row["type"] == "finish":
            valid = row["head_sha"] == head_sha and conn.execute(
                "SELECT 1 FROM acts WHERE act_id = ? " + _FINISH_ALIVE,
                (act_id,)).fetchone() is not None
        else:
            valid = row["session"] == session and row["expires_at"] > clock.fmt(now)
        if not valid:
            raise ActError(f"atto {act_id} non vale per questa sessione, HEAD o istante")
        conn.execute("UPDATE acts SET state = 'consumed', consumed_at = ? WHERE act_id = ?",
                     (clock.fmt(now), act_id))


def _expire(conn, rows, *, now, session) -> list[str]:
    ids = []
    for r in rows:
        conn.execute("UPDATE acts SET state = 'expired' WHERE act_id = ?", (r["act_id"],))
        record_event(conn, "act_expired", {"act_id": r["act_id"]}, now=now, session=session,
                     work=r["work"])
        ids.append(r["act_id"])
    return ids


def expire_stale(conn, *, now, session=None) -> list[str]:
    with db.tx(conn):
        rows = conn.execute("SELECT act_id, work FROM acts WHERE state = 'pending' "
                            "AND type <> 'finish' AND expires_at <= ? ORDER BY n",
                            (clock.fmt(now),)).fetchall()
        return _expire(conn, rows, now=now, session=session)


def invalidate_finish(conn, work: int, head_sha: str, *, now, session=None) -> list[str]:
    with db.tx(conn):
        rows = conn.execute("SELECT act_id, work FROM acts WHERE state = 'pending' "
                            "AND type = 'finish' AND work = ? AND head_sha <> ? ORDER BY n",
                            (work, head_sha)).fetchall()
        return _expire(conn, rows, now=now, session=session)


def approved_waivers(conn, work: int) -> set[str]:
    """Un `approve waiver` vale in ogni stato dell'atto (decisione 10 di P2)."""
    return {r[0] for r in conn.execute(
        "SELECT target FROM acts WHERE type = 'approve' AND object = 'waiver' "
        "AND work = ? AND target IS NOT NULL", (work,))}


def has_approval(conn, work: int, object_: str) -> bool:
    """Esiste un `approve <object_>` del lavoro, in qualunque stato (pending, consumato,
    scaduto): serve a `unverified-tests`, che vale dal DB come `waiver`."""
    return conn.execute("SELECT 1 FROM acts WHERE type = 'approve' AND object = ? AND work = ? "
                        "LIMIT 1", (object_, work)).fetchone() is not None
