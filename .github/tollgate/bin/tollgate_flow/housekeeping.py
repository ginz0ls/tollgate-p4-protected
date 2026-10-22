"""Pulizie che `start` fa a ogni avvio (vincolo 3 del piano principale, rilievo P1)."""
from __future__ import annotations

import shutil
import sqlite3
from datetime import timedelta
from pathlib import Path

from tollgate_core import events, sessions

TMP_BACKUP_MAX_AGE = timedelta(hours=1)
CLI_SIGNAL_MAX_AGE = timedelta(days=1)


def _remove_older(directory: Path, limit: float, pattern: str = "*") -> None:
    if not directory.is_dir():
        return
    for p in directory.glob(pattern):
        try:
            if p.stat().st_mtime < limit:
                shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
        except OSError:
            continue


def run(conn, state, cfg, *, now) -> list[str]:
    """Potatura di eventi, segnalini, copie temporanee e file vecchi. Righe di avviso.
    Ogni pulizia è indipendente: un errore in una diventa un avviso e non salta le altre."""
    warnings = []
    retention = timedelta(days=cfg.get("retention.retention_days"))
    stamp = now.timestamp()

    def step(what, fn):
        try:
            fn()
        except (sqlite3.Error, OSError, ValueError, TypeError) as e:
            warnings.append(f"pulizia non riuscita ({what}): {e}")

    step("eventi", lambda: events.prune_events(conn, now, cfg.get("retention.events_days")))
    step("segnalini delle sessioni", lambda: sessions.prune_bound(
        conn, state, now=now, stale_minutes=cfg.get("review.stale_minutes")))
    step("copie temporanee", lambda: _remove_older(
        state.backup_dir, stamp - TMP_BACKUP_MAX_AGE.total_seconds(), ".tmp-*"))
    for name in ("logs", "ctx"):
        step(name, lambda name=name: _remove_older(state.root / name,
                                                   stamp - retention.total_seconds()))
    step("segnali della CLI", lambda: _remove_older(
        state.root / sessions.CLI_DIR, stamp - CLI_SIGNAL_MAX_AGE.total_seconds()))
    return warnings
