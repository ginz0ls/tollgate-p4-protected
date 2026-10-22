"""Livello del lavoro (spec 5): il massimo tra diff, etichette e scelta dell'utente."""
from __future__ import annotations

from dataclasses import dataclass

from . import globs

LEVELS = ("L0", "L1", "L2")


@dataclass(frozen=True)
class FileChange:
    path: str
    added: int
    removed: int
    binary: bool = False
    status: str = "M"
    old_path: str | None = None


def max_level(*levels: str) -> str:
    return max(levels, key=LEVELS.index) if levels else "L0"


def sensitive_in(paths, sensitive_paths) -> list[str]:
    return sorted({p for p in paths if globs.match_any(sensitive_paths, p)})


def diff_level(changes, *, diff_bytes: int, sensitive_paths, l0_max_files: int,
               l0_max_lines: int, l0_max_bytes: int) -> str:
    """Livello dal diff. Contratto (decisione 18):
    - `changes`: una voce per file, inclusi i file non tracciati (untracked), che il diff
      della base non mostra;
    - `diff_bytes`: lunghezza del diff unificato dalla base più la dimensione dei file nuovi
      non tracciati, in byte.
    Un percorso sensibile dà sempre L2; sopra una soglia L0 (file, righe o byte) o un file
    binario dà L1.
    """
    changes = list(changes)
    paths = [c.path for c in changes] + [c.old_path for c in changes if c.old_path]
    if sensitive_in(paths, sensitive_paths):
        return "L2"
    lines = sum(c.added + c.removed for c in changes)
    if (len(changes) > l0_max_files or lines > l0_max_lines or diff_bytes > l0_max_bytes
            or any(c.binary for c in changes)):
        return "L1"
    return "L0"


def labels_level(labels, sensitive_labels) -> str:
    return "L2" if set(labels) & set(sensitive_labels) else "L0"


def next_level(*, current: str, computed: str, cap: str | None, cap_paths,
               sensitive_now) -> str:
    """Lo script alza soltanto; il tetto vale finché non compare un percorso sensibile nuovo."""
    if cap and set(sensitive_now) <= set(cap_paths):
        computed = min(computed, cap, key=LEVELS.index)
    return max_level(current, computed)
