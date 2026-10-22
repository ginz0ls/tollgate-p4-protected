"""Sessioni viste dagli hook, sessione viva e lavoro legato (spec 0, 6.6, 12.4)."""
from __future__ import annotations

import json
import os
import re
from datetime import timedelta
from pathlib import Path

from . import clock, db
from .paths import State, ensure_dirs

BOUND_DIR = "bound"
CLI_DIR = "cli"
CLI_WINDOW_S = 120
_SAFE = re.compile(r"^[A-Za-z0-9_-]+$")


def touch(conn, session: str, *, now) -> None:
    with db.tx(conn):
        conn.execute("INSERT INTO session_seen (session, last_seen) VALUES (?, ?) "
                     "ON CONFLICT(session) DO UPDATE SET last_seen = excluded.last_seen",
                     (session, clock.fmt(now)))


def alive(conn, session: str, *, now, stale_minutes: int) -> bool:
    row = conn.execute("SELECT last_seen FROM session_seen WHERE session = ?",
                       (session,)).fetchone()
    return row is not None and row[0] > clock.fmt(now - timedelta(minutes=stale_minutes))


def bound_work(conn, session: str):
    """Il lavoro attivo a cui la sessione è legata (il più recente, se più d'uno)."""
    for row in conn.execute("SELECT * FROM work_items WHERE phase <> 'closed' "
                            "ORDER BY updated DESC, id DESC"):
        if session in json.loads(row["sessions"]):
            return row
    return None


def work_for_path(conn, path):
    """Il lavoro attivo il cui worktree contiene il percorso (risolto, anche se non esiste)."""
    p = Path(path).resolve()
    for row in conn.execute("SELECT * FROM work_items WHERE phase <> 'closed' "
                            "AND worktree IS NOT NULL ORDER BY id"):
        wt = Path(row["worktree"]).resolve()
        if p == wt or wt in p.parents:
            return row
    return None


def mark_bound(state: State, session: str) -> None:
    """Segnalino per il wrapper (decisione 22): la sessione è legata a un lavoro."""
    if not _SAFE.match(session):
        return
    ensure_dirs(state)
    d = state.root / BOUND_DIR
    d.mkdir(mode=0o700, exist_ok=True)
    (d / session).touch()


def prune_bound(conn, state: State, *, now, stale_minutes: int) -> int:
    """Toglie i segnalini delle sessioni non vive e non legate a un lavoro attivo (vincolo 3)."""
    d = state.root / BOUND_DIR
    if not d.is_dir():
        return 0
    keep = set()
    for row in conn.execute("SELECT sessions FROM work_items WHERE phase <> 'closed'"):
        keep |= set(json.loads(row[0]))
    removed = 0
    for f in d.iterdir():
        if f.is_file() and f.name not in keep \
                and not alive(conn, f.name, now=now, stale_minutes=stale_minutes):
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
    return removed


class CliSessionError(Exception):
    pass


def _read_signals(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def note_cli_call(state: State, session: str, cwd: str, argv: list[str], *, now) -> None:
    """Segnale per la CLI (decisione 2): `cli/<sessione>.json`, una voce per sottocomando.
    Non solleva mai: un segnale mancante lo scopre la CLI, un hook non deve fallire."""
    if not _SAFE.match(session) or not argv:
        return
    try:
        ensure_dirs(state)
        d = state.root / CLI_DIR
        d.mkdir(mode=0o700, exist_ok=True)
        target = d / f"{session}.json"
        data = _read_signals(target)
        data[argv[0]] = {"cwd": str(cwd), "argv": list(argv), "at": clock.fmt(now)}
        tmp = d / f".{session}.json.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, target)
    except OSError:
        return


def _consume_signal(path: Path, subcommand: str) -> None:
    """Toglie dal file la sola voce del sottocomando (tmp + os.replace, come `note_cli_call`).
    Un errore di scrittura non fa fallire la chiamata."""
    try:
        data = _read_signals(path)
        data.pop(subcommand, None)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return


def cli_session(state: State, cwd, subcommand: str, *, now,
                argv: list[str] | None = None) -> str:
    """La sessione che ha lanciato il sottocomando: segnale recente, stessa cartella risolta,
    stesso sottocomando (decisione 2). Con `argv` la voce vale solo se `argv` coincide e si toglie
    dal file (un secondo lancio senza hook non eredita la sessione); senza `argv` è una lettura
    che non consuma. Zero candidate o più d'una: errore."""
    here = Path(cwd).resolve()
    limit = clock.fmt(now - timedelta(seconds=CLI_WINDOW_S))
    found = []
    d = state.root / CLI_DIR
    for f in sorted(d.glob("*.json")) if d.is_dir() else []:
        entry = _read_signals(f).get(subcommand)
        if not isinstance(entry, dict) or not isinstance(entry.get("at"), str) \
                or not isinstance(entry.get("cwd"), str) or not _SAFE.match(f.stem):
            continue
        if argv is not None and entry.get("argv") != argv:
            continue
        if entry["at"] > limit and Path(entry["cwd"]).resolve() == here:
            found.append((f.stem, f))
    if not found:
        raise CliSessionError("sessione non riconosciuta: lancia il comando da Claude Code "
                              "con tollgate acceso")
    if len(found) > 1:
        raise CliSessionError("più sessioni di Claude Code hanno lanciato questo comando "
                              "da questa cartella: ripeti il comando")
    session, path = found[0]
    if argv is not None:
        _consume_signal(path, subcommand)
    return session
