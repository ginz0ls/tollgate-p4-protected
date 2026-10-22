"""Import in `events` delle accensioni e degli spegnimenti scritti dal wrapper (decisione 5).

Il file viene reclamato con un rename su un nome unico (`.off.log.<pid>-<hex>`); lo si cancella
solo dopo il commit. Se qualcosa fallisce, il file resta e la chiamata successiva lo riprende:
un file reclamato da un processo morto (o dallo stesso processo, in una chiamata fallita) è un
orfano; quello di un processo vivo non si tocca, perché sta ancora importando.
"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from . import clock, db
from .events import record_event
from .paths import State

LOG_NAME = "off.log"
_LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z) (off|on)(?: (\d+))?\s*$")
_CLAIMED = re.compile(r"^\.off\.log\.(\d+)(?:-[0-9a-f]+)?$")


def _pid_alive(pid: int) -> bool:
    if pid == os.getpid():
        # Questo processo non sta importando nulla: un suo file è un orfano di una chiamata fallita.
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _claim(src: Path, root: Path) -> Path | None:
    dst = root / f".{LOG_NAME}.{os.getpid()}-{secrets.token_hex(4)}"
    try:
        src.rename(dst)     # atomico: due processi non reclamano lo stesso file
    except FileNotFoundError:
        return None
    return dst


def import_log(conn, state: State) -> int:
    if conn.in_transaction:
        raise RuntimeError("import_log va chiamato fuori da una transazione: "
                           "il file deve restare finché i suoi eventi non sono confermati")
    root = state.root
    # Snapshot prima del reclamo del file vivo: il file appena reclamato non va riletto.
    candidates = sorted(p for p in root.iterdir() if _CLAIMED.match(p.name))
    files = []
    live = _claim(root / LOG_NAME, root)
    if live is not None:
        files.append(live)
    for p in candidates:
        pid = int(_CLAIMED.match(p.name).group(1))
        if not _pid_alive(pid):
            claimed = _claim(p, root)
            if claimed is not None:
                files.append(claimed)
    if not files:
        return 0

    texts = [f.read_text(encoding="utf-8", errors="replace") for f in files]
    n = 0
    with db.tx(conn):
        for text in texts:
            for line in text.splitlines():
                m = _LINE.match(line)
                if not m:
                    continue
                try:
                    when = clock.parse(m.group(1))
                except ValueError:      # data che passa la regex ma non esiste (mese 13)
                    continue
                data = {"until": int(m.group(3))} if m.group(3) else {}
                record_event(conn, m.group(2), data, now=when)
                n += 1
    # Solo dopo il commit: se la transazione fallisce i file restano per la prossima chiamata.
    for f in files:
        f.unlink(missing_ok=True)
    return n
