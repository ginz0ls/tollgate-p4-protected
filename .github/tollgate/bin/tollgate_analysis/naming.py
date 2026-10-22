"""Nomi di rami e implementatori (decisione 17). Puro: nessun accesso a git né al disco."""
from __future__ import annotations

import re
import unicodedata

SLUG_MAX = 40
RENAMED_FROM_ROUND = 4


def slug(title: str) -> str:
    """Titolo → `[a-z0-9-]`, trattini compressi, al massimo 40 caratteri, mai vuoto."""
    ascii_ = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[^a-z0-9]+", "-", ascii_.lower()).strip("-")
    return s[:SLUG_MAX].strip("-") or "issue"


def branch_name(issue: int, title: str, taken: set[str]) -> str:
    base = f"tg/{issue}-{slug(title)}"
    name, n = base, 1
    while name in taken:
        n += 1
        name = f"{base}-{n}"
    return name


def implementer_name(issue: int, task: int, round_: int = 0) -> str:
    base = f"tg-{issue}-t{task}"
    return f"{base}-r{round_}" if round_ >= RENAMED_FROM_ROUND else base
