"""Blocco JSON nella PR (spec 18.1, decisione 11 di P3b): il contratto con il gate di P4.

Va in un commento HTML `<!-- tollgate {...} -->`. `render` sostituisce `<`, `>` e `&` con le
sequenze `\\uXXXX`: il JSON resta valido e il testo non contiene mai `-->` né `<!--` dentro il
commento, qualunque cosa dica un campo. `parse` legge l'ultimo blocco del testo."""
from __future__ import annotations

import json

SCHEMA_VERSION = 1
FIELDS = (
    "schema_version", "tollgate_version", "issue", "level", "level_minimum", "level_cap",
    "level_cap_reason", "gate_mode", "plan", "plan_sha", "spec", "spec_reviews_dir",
    "plan_reviews_dir", "spec_audit", "head_sha", "receipts", "waivers_file", "blocks", "acts",
    "dod", "verdict", "findings", "fix_rounds", "subagents", "effects", "components_off",
    "off_periods", "tasks_over", "skills_absent")
# Campi nuovi (decisione 21 di P4): un blocco costruito da chi non li conosce ha elenchi vuoti.
DEFAULTS = {"tasks_over": [], "skills_absent": []}
_OPEN = "<!-- tollgate "
_CLOSE = " -->"
_ESCAPES = (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"))


def build(facts: dict) -> dict:
    """I campi di 18.1 nell'ordine della spec; `KeyError` se ne manca uno (salvo quelli di
    `DEFAULTS`, che valgono elenchi vuoti)."""
    return {key: facts[key] if key in facts or key not in DEFAULTS else list(DEFAULTS[key])
            for key in FIELDS}


def render(block: dict) -> str:
    text = json.dumps(block, ensure_ascii=False, separators=(",", ":"))
    for raw, escaped in _ESCAPES:
        text = text.replace(raw, escaped)
    return f"{_OPEN}{text}{_CLOSE}"


def parse(text: str) -> dict | None:
    """L'ultimo blocco del testo, oppure `None` se manca o non è un oggetto JSON valido (un
    blocco rotto in coda non lascia ripiegare su uno precedente)."""
    start = text.rfind(_OPEN)
    if start < 0:
        return None
    body = text[start + len(_OPEN):]
    end = body.find(_CLOSE)
    if end < 0:
        return None
    try:
        data = json.loads(body[:end])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
