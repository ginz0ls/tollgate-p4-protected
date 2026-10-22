"""File di tollgate e file protetti (spec 0, 7.4)."""
from __future__ import annotations

from pathlib import Path

from . import globs

TOLLGATE_FILES = ["/tollgate.toml", ".github/workflows/tollgate-*.yml",
                  ".github/actions/tollgate-*/**", ".github/tollgate/**"]
WAIVER_FILES = [".tollgate/waivers/**"]
REPO_PROTECTED = TOLLGATE_FILES + WAIVER_FILES + [
    "docs/superpowers/reviews/**",
    ".claude/settings.json", ".claude/settings.local.json",
    ".git/hooks/**", ".git/config",
]


def is_tollgate_file(rel: str) -> bool:
    return globs.match_any(TOLLGATE_FILES, rel)


def is_protected(rel: str | None, abs_path: Path, *, abs_roots: list[Path]) -> bool:
    """`rel` è il percorso nel repo (None fuori da un repo); `abs_roots` sono cartelle o file
    protetti per percorso assoluto: cartella di stato, plugin installati, impostazioni utente,
    `.git/hooks` e `.git/config` della cartella comune di git."""
    if rel is not None and globs.match_any(REPO_PROTECTED, rel):
        return True
    p = Path(abs_path)
    return any(p == r or r in p.parents for r in abs_roots)
