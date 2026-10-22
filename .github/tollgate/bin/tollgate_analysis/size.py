"""Dimensione di un task (spec 6.3): righe aggiunte più rimosse, esclusi lockfile e generati."""
from __future__ import annotations

import posixpath

from . import globs

GENERATED = ["**/*.min.js", "**/*.generated.*", "**/__snapshots__/**", "**/dist/**"]


def task_lines(changes, lockfiles) -> int:
    """`changes` ha `path`, `added` e `removed` (git.Change); `lockfiles` sono nomi di file."""
    return sum(c.added + c.removed for c in changes
               if posixpath.basename(c.path) not in lockfiles
               and not globs.match_any(GENERATED, c.path))
