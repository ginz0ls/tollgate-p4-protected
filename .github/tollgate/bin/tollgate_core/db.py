"""DB SQLite nella cartella di stato (spec 12.1, 12.2, 12.4)."""
from __future__ import annotations

import os
import re
import secrets
import shutil
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from . import clock
from .paths import State, ensure_dirs

BIN_PATH = Path(__file__).resolve().parents[1] / "tollgate"
KEEP_BACKUPS = 10
BUSY_TIMEOUT_MS = 5000


class DbError(Exception):
    pass


class DbCorrupt(DbError):
    pass


class DbTooNew(DbError):
    pass


def restore_hint() -> str:
    return f"{BIN_PATH} db restore"


# Le istruzioni non contengono ';' al loro interno: la lista è divisa a mano.
SCHEMA_V1 = [
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE work_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_key TEXT NOT NULL, issue INTEGER NOT NULL,
        level TEXT NOT NULL CHECK (level IN ('L0','L1','L2')),
        level_cap TEXT CHECK (level_cap IS NULL OR level_cap IN ('L0','L1','L2')),
        level_cap_reason TEXT,
        phase TEXT NOT NULL CHECK (phase IN
            ('spec_audit','plan','approval','execution','review','pr_open','closed','blocked')),
        phase_before_block TEXT,
        branch TEXT, worktree TEXT, work_base_sha TEXT, gate_mode TEXT,
        spec_path TEXT, plan_path TEXT, plan_sha TEXT,
        sessions TEXT NOT NULL DEFAULT '[]',
        created TEXT NOT NULL, updated TEXT NOT NULL, closed_reason TEXT)""",
    "CREATE UNIQUE INDEX work_items_active ON work_items(repo_key, issue) WHERE phase <> 'closed'",
    """CREATE TABLE scope (
        work INTEGER NOT NULL REFERENCES work_items(id), path TEXT NOT NULL,
        origin TEXT NOT NULL, registered_at TEXT NOT NULL, PRIMARY KEY (work, path))""",
    """CREATE TABLE receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, work INTEGER REFERENCES work_items(id),
        sha TEXT NOT NULL, command TEXT NOT NULL, resolved_command TEXT, exit INTEGER,
        tests_run INTEGER, tests_skipped INTEGER, duration REAL, log TEXT,
        produced_by TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('green','red','empty','uncounted','unverified')),
        at TEXT NOT NULL)""",
    """CREATE TABLE blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, work INTEGER NOT NULL REFERENCES work_items(id),
        type TEXT NOT NULL CHECK (type IN
            ('needs_you','test_spec_conflict','dependency','permission','transient')),
        reason TEXT NOT NULL, opened TEXT NOT NULL, closed TEXT, resolution TEXT)""",
    """CREATE TABLE subagents (
        id TEXT PRIMARY KEY, name TEXT, type TEXT, work INTEGER REFERENCES work_items(id),
        task INTEGER, session TEXT, agent_base_sha TEXT, fingerprint TEXT,
        started TEXT, ended TEXT, resumes INTEGER NOT NULL DEFAULT 0,
        declared_status TEXT, state TEXT, tokens INTEGER, duration REAL)""",
    """CREATE TABLE review_cycles (
        work INTEGER NOT NULL REFERENCES work_items(id), number INTEGER NOT NULL,
        sha TEXT, patch_id TEXT, outcome TEXT, findings_confirmed INTEGER,
        counted INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (work, number))""",
    """CREATE TABLE findings (
        id TEXT NOT NULL, work INTEGER NOT NULL REFERENCES work_items(id), cycle INTEGER,
        source TEXT,
        severity TEXT CHECK (severity IN ('blocker','major','moderate','minor')),
        confidence REAL, file TEXT, line INTEGER, text TEXT,
        verification TEXT CHECK (verification IS NULL OR
            verification IN ('confirmed','rejected','unverified')),
        verification_reason TEXT, user_decision TEXT, PRIMARY KEY (work, id))""",
    """CREATE TABLE spec_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, work INTEGER NOT NULL REFERENCES work_items(id),
        kind TEXT NOT NULL, number INTEGER NOT NULL, viewpoint TEXT, counts TEXT,
        outcome TEXT, report_path TEXT)""",
    """CREATE TABLE acts (
        n INTEGER PRIMARY KEY AUTOINCREMENT, act_id TEXT UNIQUE,
        type TEXT NOT NULL, object TEXT, target TEXT, args TEXT NOT NULL DEFAULT '[]',
        at TEXT NOT NULL, typed_text TEXT, source TEXT NOT NULL, actor TEXT, session TEXT,
        work INTEGER REFERENCES work_items(id), head_sha TEXT,
        state TEXT NOT NULL CHECK (state IN ('pending','consumed','expired')),
        expires_at TEXT, consumed_at TEXT)""",
    """CREATE TABLE intents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, work INTEGER REFERENCES work_items(id),
        action TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, data TEXT,
        state TEXT NOT NULL, outcome TEXT, at TEXT NOT NULL)""",
    """CREATE TABLE tasks (
        work INTEGER NOT NULL REFERENCES work_items(id), number INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('plan','fix')), source TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('pending','running','review','done','blocked')),
        fix_rounds INTEGER NOT NULL DEFAULT 0, implementer TEXT, agent_type TEXT,
        reviewer_type TEXT, skills_required TEXT NOT NULL DEFAULT '[]',
        skills_used TEXT NOT NULL DEFAULT '[]', commits TEXT NOT NULL DEFAULT '[]',
        verdict TEXT, review_code TEXT, PRIMARY KEY (work, number))""",
    """CREATE TABLE events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, v INTEGER NOT NULL, at TEXT NOT NULL,
        host TEXT NOT NULL, session TEXT, work INTEGER, repo_key TEXT, issue INTEGER,
        type TEXT NOT NULL, data TEXT NOT NULL)""",
    "CREATE INDEX events_work ON events(work, seq)",
]

# Migrazione 2 (piano P2, decisione 7): dati che servono agli hook.
SCHEMA_V2 = [
    "CREATE TABLE session_seen (session TEXT PRIMARY KEY, last_seen TEXT NOT NULL)",
    "ALTER TABLE subagents ADD COLUMN last_seen TEXT",
    "ALTER TABLE subagents ADD COLUMN vetoes INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE subagents ADD COLUMN report TEXT",
    "ALTER TABLE tasks ADD COLUMN pending TEXT "
    "CHECK (pending IS NULL OR pending IN ('launch','resume'))",
    "ALTER TABLE work_items ADD COLUMN level_cap_paths TEXT NOT NULL DEFAULT '[]'",
    "CREATE INDEX subagents_work ON subagents(work, state)",
]

# Migrazione 3 (piano P3a, decisione 9): verdetto del revisore e prenotazione del lancio.
SCHEMA_V3 = [
    "ALTER TABLE tasks ADD COLUMN review_sha TEXT",
    "ALTER TABLE tasks ADD COLUMN review_findings TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE tasks ADD COLUMN reserved_at TEXT",
]

# Migrazione 4 (piano P3b, decisione 1): PR, esito di finish check, cicli di revisione.
SCHEMA_V4 = [
    "ALTER TABLE work_items ADD COLUMN pr_number INTEGER",
    "ALTER TABLE work_items ADD COLUMN pr_url TEXT",
    "ALTER TABLE work_items ADD COLUMN finish_sha TEXT",
    "ALTER TABLE work_items ADD COLUMN finish_report TEXT",
    "ALTER TABLE work_items ADD COLUMN extra_review_cycles INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE work_items ADD COLUMN review_unverified INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE review_cycles ADD COLUMN code TEXT",
    "ALTER TABLE review_cycles ADD COLUMN stage TEXT "
    "CHECK (stage IS NULL OR stage IN ('review','verify','closed'))",
    "ALTER TABLE review_cycles ADD COLUMN reviewers TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE review_cycles ADD COLUMN reported TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE review_cycles ADD COLUMN opened TEXT",
    "ALTER TABLE findings ADD COLUMN rule TEXT",
    "ALTER TABLE findings ADD COLUMN blocking INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE tasks ADD COLUMN extra_fix_rounds INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE tasks ADD COLUMN task_text TEXT",
]

# Migrazione 5 (piano P3c, decisione 1): giri di audit con codice, documenti esaminati e stato
# (le righe esistenti sono giri chiusi), sospensioni dei tetti.
SCHEMA_V5 = [
    "ALTER TABLE spec_audit ADD COLUMN code TEXT",
    "ALTER TABLE spec_audit ADD COLUMN sha TEXT",
    "ALTER TABLE spec_audit ADD COLUMN spec_sha TEXT",
    "ALTER TABLE spec_audit ADD COLUMN stage TEXT NOT NULL DEFAULT 'closed' "
    "CHECK (stage IN ('open','closed'))",
    "ALTER TABLE spec_audit ADD COLUMN opened TEXT",
    "ALTER TABLE work_items ADD COLUMN audit_suspended TEXT NOT NULL DEFAULT '{}'",
]

MIGRATIONS: list[tuple[int, list[str]]] = [(1, SCHEMA_V1), (2, SCHEMA_V2), (3, SCHEMA_V3),
                                           (4, SCHEMA_V4), (5, SCHEMA_V5)]


def latest_version() -> int:
    return MIGRATIONS[-1][0]


@contextmanager
def tx(conn: sqlite3.Connection):
    """Transazione con il lucchetto di scrittura preso subito; si unisce a una già aperta."""
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def _version(conn: sqlite3.Connection) -> int:
    if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone():
        return 0
    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    return int(row[0]) if row else 0


def _migrate(conn: sqlite3.Connection, state: State) -> None:
    current = _version(conn)
    if current > latest_version():
        raise DbTooNew(f"il DB ha lo schema {current}, questa versione di tollgate arriva a "
                       f"{latest_version()}: aggiornare il plugin")
    # Un DB creato in questa stessa apertura non ha dati da proteggere: niente copia.
    fresh = current == 0
    for target, statements in MIGRATIONS:
        if target <= current:
            continue
        if not fresh:
            backup(conn, state, f"migrazione-{target}")
        with tx(conn):
            # Un altro processo può aver migrato mentre aspettavamo il lucchetto.
            current = _version(conn)
            if current >= target:
                continue
            for stmt in statements:
                conn.execute(stmt)
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
                         (str(target),))
        current = target


def _set_wal(conn: sqlite3.Connection) -> None:
    """Il cambio di journal_mode non passa dal busy handler: si riprova a mano."""
    deadline = time.monotonic() + BUSY_TIMEOUT_MS / 1000
    while True:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as e:
            code = (getattr(e, "sqlite_errorcode", None) or 0) & 0xFF
            if code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def open_db(state: State) -> sqlite3.Connection:
    ensure_dirs(state)
    conn = sqlite3.connect(state.db_path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        _set_wal(conn)
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        _migrate(conn, state)
    except sqlite3.DatabaseError as e:
        conn.close()
        code = getattr(e, "sqlite_errorcode", None)
        if code is None or (code & 0xFF) not in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB):
            raise DbError(f"DB di tollgate non disponibile ({state.db_path}): {e}. "
                          f"Per spegnere tollgate: touch {state.root / 'OFF'}") from e
        raise DbCorrupt(f"DB di tollgate guasto ({state.db_path}): {e}. "
                        f"Ripristino dal terminale: {restore_hint()}. "
                        f"Per spegnere tollgate: touch {state.root / 'OFF'}") from e
    except BaseException:
        conn.close()
        raise
    return conn


def backup(conn: sqlite3.Connection, state: State, reason: str) -> Path:
    """Copia coerente con la API di backup (in WAL il file da solo non lo è)."""
    ensure_dirs(state)
    tag = re.sub(r"[^a-z0-9-]+", "-", reason.lower()).strip("-") or "copia"
    stamp = clock.now().strftime("%Y%m%dT%H%M%S%fZ")
    # Il nome temporaneo è unico per processo: due copie nello stesso istante non condividono il
    # file. La pubblicazione con os.link non sovrascrive mai la copia di un altro processo.
    tmp_path = state.backup_dir / f".tmp-{os.getpid()}-{secrets.token_hex(4)}-{tag}.db"
    dst = sqlite3.connect(tmp_path)
    try:
        try:
            conn.backup(dst)
        finally:
            dst.close()
        dst_path = state.backup_dir / f"tollgate-{stamp}-{tag}.db"
        n = 0
        while True:
            try:
                os.link(tmp_path, dst_path)
                break
            except FileExistsError:
                n += 1
                dst_path = state.backup_dir / f"tollgate-{stamp}-{n}-{tag}.db"
    finally:
        tmp_path.unlink(missing_ok=True)
    for old in sorted(state.backup_dir.glob("tollgate-*.db"))[:-KEEP_BACKUPS]:
        old.unlink(missing_ok=True)
    return dst_path


def integrity_ok(path: Path) -> bool:
    try:
        if path.stat().st_size == 0:
            return False
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            conn.close()
    except (sqlite3.DatabaseError, OSError):
        return False


def restore(state: State, *, interactive: bool, confirm: Callable[[str], bool]) -> str:
    """Ripristino dal terminale, senza atto: solo con un DB che non supera integrity_check."""
    if not state.db_path.exists():
        raise DbError(f"nessun DB in {state.db_path}: niente da ripristinare")
    if integrity_ok(state.db_path):
        raise DbError("il DB è integro: niente da ripristinare")
    if not interactive:
        raise DbError("db restore va lanciato da un terminale interattivo")
    if not confirm(f"Il DB {state.db_path} è guasto. Spostarlo da parte e ripristinare "
                   f"l'ultima copia integra? [s/N] "):
        return "annullato"
    dest = state.broken_dir / clock.now().strftime("%Y%m%dT%H%M%S%fZ")
    dest.mkdir(parents=True)
    for suffix in ("", "-wal", "-shm"):
        p = state.db_path.with_name(state.db_path.name + suffix)
        if p.exists():
            shutil.move(str(p), dest / p.name)
    for candidate in sorted(state.backup_dir.glob("tollgate-*.db"), reverse=True):
        if integrity_ok(candidate):
            shutil.copy2(candidate, state.db_path)
            open_db(state).close()
            return f"ripristinata la copia {candidate.name}; il DB guasto è in {dest}"
    open_db(state).close()
    return (f"nessuna copia integra: DB vuoto; il DB guasto è in {dest}. "
            f"Per ogni lavoro con un ramo tg/* lancia /tollgate:adopt #N")
