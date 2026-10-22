"""tollgate waiver add, tollgate block open (spec 8.3): li usa l'agente, dal worktree."""
from __future__ import annotations

import fcntl
import os
import secrets
from contextlib import contextmanager
from pathlib import Path

from tollgate_analysis import waivers

from . import clock, db, git, phases, sessions
from .cli import UsageError
from .events import record_event
from .paths import State


def _work(conn, cwd):
    root = git.toplevel(cwd)
    work = sessions.work_for_path(conn, root or cwd)
    if work is None:
        raise UsageError("nessun lavoro attivo in questa cartella: lancialo dal worktree "
                         "del lavoro")
    return work


def _root_relative(file: str, worktree: str) -> str:
    """Un percorso relativo si intende relativo alla radice del worktree (come nelle violazioni);
    uno assoluto si converte. Il risultato, con '/' come separatore, non può uscire dal worktree."""
    root = Path(worktree).resolve()
    p = Path(file)
    p = p if p.is_absolute() else root / p
    try:
        rel = p.resolve().relative_to(root).as_posix()
    except ValueError as e:
        raise UsageError(f"il file è fuori dal worktree: {file}") from e
    if rel == ".":
        raise UsageError(f"indica un file, non la radice del worktree: {file}")
    return rel


@contextmanager
def _locked(path: Path):
    """Lucchetto esclusivo (flock) su un file accanto a quello delle deroghe: lettura,
    assegnazione dell'id e scrittura sono una sola sezione critica. Il file di lock si toglie
    a fine lavoro (non resta nel working tree); chi aspettava su un file ormai tolto riprova."""
    lock = path.with_name(path.name + ".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    while True:
        fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                same = os.stat(lock).st_ino == os.fstat(fd).st_ino
            except FileNotFoundError:
                same = False
        except BaseException:
            os.close(fd)
            raise
        if same:
            break
        os.close(fd)
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)
        os.close(fd)


def add_waiver(state: State, cwd, *, type_: str, file: str | None = None,
               pattern: str | None = None, tests=(), choice: str, why: str, cost: str,
               now=None) -> str:
    if type_ not in waivers.TYPES:
        raise UsageError(f"tipo di deroga sconosciuto: {type_} (ammessi: "
                         f"{', '.join(waivers.TYPES)})")
    if type_ == "test" and not tests:
        raise UsageError("una deroga di tipo test richiede almeno un --test ID")
    if (file is None) == (pattern is None):
        raise UsageError("indica un file oppure --pattern, non entrambi")
    now = now or clock.now()
    conn = db.open_db(state)
    try:
        work = _work(conn, cwd)
        if file is not None:
            file = _root_relative(file, work["worktree"])
        path = Path(work["worktree"]) / waivers.path_for(work["issue"])
        with _locked(path):
            if path.exists():
                try:
                    wf = waivers.parse(path.read_text(encoding="utf-8"))
                except ValueError as e:
                    raise UsageError(f"{path}: {e}") from e
            else:
                wf = waivers.WaiverFile(work["issue"], work["branch"] or "", [])
            wid = waivers.next_id(wf)
            wf.waivers.append(waivers.Waiver(wid, type_, file, pattern, list(tests), choice, why,
                                             cost, "agent"))
            tmp = path.with_name(f"{path.name}.{os.getpid()}-{secrets.token_hex(4)}.tmp")
            try:
                tmp.write_text(waivers.dumps(wf), encoding="utf-8")
                tmp.replace(path)
            finally:
                tmp.unlink(missing_ok=True)
        record_event(conn, "waiver_added", {"id": wid, "type": type_}, now=now,
                     work=work["id"])
        return wid
    finally:
        conn.close()


def open_block_cmd(state: State, cwd, *, type_: str, reason: str, now=None) -> int:
    if type_ not in phases.BLOCK_TYPES:
        raise UsageError(f"tipo di blocco sconosciuto: {type_}")
    conn = db.open_db(state)
    try:
        work = _work(conn, cwd)
        return phases.open_block(conn, state, work["id"], type_, reason, now=now or clock.now())
    finally:
        conn.close()
