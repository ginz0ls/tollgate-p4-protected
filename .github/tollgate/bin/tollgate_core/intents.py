"""Intenti di P3b (spec 12.2): azioni con effetto esterno da ripetere senza doppioni.

Un intento `pr` (apri o aggiorna la PR), `sync` (rebase) o `force_push` (push forzato
autorizzato) ha una chiave di idempotenza: ripetere la richiesta non crea una seconda riga.
Stati: `requested` -> `executed`; `authorized` -> `used` (solo `force_push`)."""
from __future__ import annotations

import json
import sqlite3

from . import clock, db

ACTIONS = ("pr", "sync", "force_push")
# Prefisso del motivo del blocco aperto da `sync` con un conflitto nel rebase: lo riconosce
# `approve rebase` (decisione 14).
SYNC_CONFLICT_REASON = "sync: conflitto nel rebase"


def request(conn, *, work: int, action: str, key: str, data: dict, now) -> int:
    """Registra l'intento; con la stessa chiave la riga esistente torna `requested` e ne
    aggiorna i dati."""
    if action not in ACTIONS:
        raise ValueError(f"azione sconosciuta: {action}")
    payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
    with db.tx(conn):
        row = conn.execute("SELECT id FROM intents WHERE idempotency_key = ?", (key,)).fetchone()
        if row is not None:
            conn.execute("UPDATE intents SET state = 'requested', data = ?, outcome = NULL "
                         "WHERE id = ?", (payload, row["id"]))
            return row["id"]
        cur = conn.execute("INSERT INTO intents (work, action, idempotency_key, data, state, at) "
                           "VALUES (?, ?, ?, ?, 'requested', ?)",
                           (work, action, key, payload, clock.fmt(now)))
        return cur.lastrowid


def complete(conn, key: str, *, outcome: str, now) -> None:
    with db.tx(conn):
        cur = conn.execute("UPDATE intents SET state = 'executed', outcome = ? "
                           "WHERE idempotency_key = ?", (outcome, key))
        if cur.rowcount == 0:
            raise ValueError(f"intento {key} inesistente")


def authorize_force(conn, work: int, *, reason: str, now, lease: str | None = None) -> str:
    """Autorizza un push forzato (da `sync` o `approve rebase`): chiave `force:<lavoro>:<n>`.
    `lease` è lo SHA remoto atteso: il push forzato lo usa come `--force-with-lease`, così un
    commit arrivato dopo non si sovrascrive."""
    with db.tx(conn):
        n = conn.execute("SELECT count(*) FROM intents WHERE work = ? AND action = 'force_push'",
                         (work,)).fetchone()[0] + 1
        key = f"force:{work}:{n}"
        conn.execute("INSERT INTO intents (work, action, idempotency_key, data, state, at) "
                     "VALUES (?, 'force_push', ?, ?, 'authorized', ?)",
                     (work, key, json.dumps({"reason": reason, "lease": lease}, ensure_ascii=False),
                      clock.fmt(now)))
        return key


def force_authorized(conn, work: int) -> bool:
    """C'è un'autorizzazione al push forzato non ancora usata (sola lettura)."""
    return conn.execute("SELECT 1 FROM intents WHERE work = ? AND action = 'force_push' "
                        "AND state = 'authorized' LIMIT 1", (work,)).fetchone() is not None


def force_lease(conn, work: int) -> str | None:
    """Lo SHA remoto atteso dell'autorizzazione che `take_force` consumerebbe (sola lettura)."""
    row = conn.execute("SELECT data FROM intents WHERE work = ? AND action = 'force_push' "
                       "AND state = 'authorized' ORDER BY id DESC LIMIT 1", (work,)).fetchone()
    return json.loads(row["data"] or "{}").get("lease") if row else None


def refresh_lease(conn, work: int, lease: str) -> bool:
    """Porta il lease dell'autorizzazione non ancora usata alla punta remota appena letta (dopo un
    `sync` il remoto può essere avanzato e integrato). Dà `False` se non ce n'è una."""
    with db.tx(conn):
        row = conn.execute("SELECT id, data FROM intents WHERE work = ? AND action = 'force_push' "
                           "AND state = 'authorized' ORDER BY id DESC LIMIT 1", (work,)).fetchone()
        if row is None:
            return False
        data = json.loads(row["data"] or "{}")
        data["lease"] = lease
        conn.execute("UPDATE intents SET data = ? WHERE id = ?",
                     (json.dumps(data, ensure_ascii=False), row["id"]))
        return True


def take_force(conn, work: int, *, now) -> str | None:
    """Consuma la più recente autorizzazione: ogni push forzato ne usa una sola."""
    with db.tx(conn):
        row = conn.execute("SELECT id, idempotency_key FROM intents WHERE work = ? "
                           "AND action = 'force_push' AND state = 'authorized' "
                           "ORDER BY id DESC LIMIT 1", (work,)).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE intents SET state = 'used' WHERE id = ?", (row["id"],))
        return row["idempotency_key"]


def pending(conn, work: int, action: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM intents WHERE work = ? AND action = ? "
                        "AND state = 'requested' ORDER BY id", (work, action)).fetchall()
