"""Registro delle radici attive (spec 6.6, 7.1 punto 3).

La protezione segue il bersaglio, non il `cwd`: per ogni repo attivo il runner scrive in
`<stato>/active/<hash>` i percorsi del checkout principale e dei worktree, uno per riga. Il
wrapper `hooks/run`, su `PreToolUse` con il `cwd` fuori dai repo attivi, lancia Python se il
registro non è vuoto (il bersaglio può essere relativo, con `~`, `cd` o `git -C`); registro
vuoto: esce senza costo.
`start` li scrive anche alla creazione di un worktree."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from . import git
from .paths import State

ACTIVE_DIR = "active"
REFRESH_SECONDS = 300


def _lines(paths) -> list[str]:
    """Ogni percorso, e la sua forma con le escape JSON se diversa (l'input è JSON)."""
    out = []
    for p in paths:
        for s in (str(p), json.dumps(str(p), ensure_ascii=False)[1:-1]):
            if s and s not in out:
                out.append(s)
    return out


def register(state: State, repo, *, extra=(), now: float | None = None,
             force: bool = False) -> None:
    """Registra il repo attivo `repo` (checkout e worktree, più i percorsi in `extra`).
    Non riscrive il file se è recente e contiene già la radice di `repo`, salvo `force`
    (`start` aggiunge un worktree appena creato). Mai un errore."""
    try:
        top = Path(repo).resolve()
        common = git.common_dir(top)
        dest_dir = state.root / ACTIVE_DIR
        dest = dest_dir / hashlib.sha1(str(common).encode()).hexdigest()[:16]
        now = time.time() if now is None else now
        if not force and dest.is_file() and now - dest.stat().st_mtime < REFRESH_SECONDS \
                and str(top) in dest.read_text(encoding="utf-8").splitlines():
            return
        paths = [p for p, _ in git.worktrees(top)] + [Path(e).resolve() for e in extra]
        dest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = dest_dir / f".tmp-{os.getpid()}-{secrets.token_hex(4)}"
        tmp.write_text("\n".join(_lines(paths)) + "\n", encoding="utf-8")
        os.replace(tmp, dest)
    except (OSError, ValueError, git.GitError):
        pass


def prefixes(state: State) -> list[str]:
    """Tutti i percorsi registrati (senza righe vuote: nel wrapper `grep -F` le prenderebbe
    per un pattern che combacia con tutto)."""
    out = []
    d = state.root / ACTIVE_DIR
    try:
        for f in sorted(d.iterdir()):
            if f.name.startswith(".tmp-"):
                continue
            out += [ln for ln in f.read_text(encoding="utf-8").splitlines() if ln]
    except OSError:
        pass
    return out
