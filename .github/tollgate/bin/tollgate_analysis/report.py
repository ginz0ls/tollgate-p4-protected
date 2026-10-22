"""Report dell'implementatore (spec 18.5), taglio di maxTurns (6.3), token dal transcript."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

STATUSES = ("DONE", "DONE_WITH_CONCERNS", "BLOCKED", "NEEDS_CONTEXT")
REQUIRED = ("v", "task", "status", "done", "tests", "files", "concerns", "left")
CUT_PREFIX = "NOTE: this agent stopped at its"


@dataclass
class ImplReport:
    """`status` è lo stato normalizzato (maiuscolo, senza spazi). Uno stato fuori da
    STATUSES rende il report non valido (fail-closed, spec 18.5)."""
    status: str
    data: dict = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    unknown_status: bool = False

    @property
    def valid(self) -> bool:
        return not self.missing and not self.unknown_status


MAX_SCAN_CHARS = 65536
MAX_DECODES = 500


def json_candidates(text: str, key: str) -> list[dict]:
    """Oggetti JSON con la chiave `key`, dal fondo del testo verso l'inizio. Esamina solo la coda
    di MAX_SCAN_CHARS caratteri e al più MAX_DECODES aperture di `{` (decisione 23)."""
    dec = json.JSONDecoder()
    out: list[dict] = []
    lo = max(0, len(text) - MAX_SCAN_CHARS)
    pos = text.rfind("{", lo)
    decodes = 0
    while pos >= lo and decodes < MAX_DECODES:
        decodes += 1
        try:
            obj, _ = dec.raw_decode(text, pos)
            if isinstance(obj, dict) and key in obj:
                out.append(obj)
        except json.JSONDecodeError:
            pass
        pos = text.rfind("{", lo, pos)
    return out


def _last_json(text: str) -> dict | None:
    """Preferisce l'oggetto che contiene tutti i campi REQUIRED; altrimenti l'ultimo."""
    cands = json_candidates(text, "status")
    for c in cands:
        if all(k in c for k in REQUIRED):
            return c
    return cands[0] if cands else None


def parse_report(text: str | None) -> ImplReport:
    data = _last_json(text or "")
    if data is None:
        return ImplReport("DONE", {}, list(REQUIRED))
    missing = [k for k in REQUIRED if k not in data]
    raw = data.get("status")
    status = raw.strip().upper() if isinstance(raw, str) else str(raw)
    return ImplReport(status, data, missing, status not in STATUSES)


def is_turn_cut(tool_response: dict | None) -> bool:
    """Il blocco lo scrive Claude Code, separato dall'output del subagente (P0, E6)."""
    if not isinstance(tool_response, dict):
        return False
    count = tool_response.get("harnessNoteCount")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        return False
    content = tool_response.get("content")
    if not isinstance(content, list) or not content or not isinstance(content[0], dict):
        return False
    return str(content[0].get("text", "")).startswith(CUT_PREFIX)


def _count(v) -> int:
    """Solo gli interi veri contano: stringhe, liste, float (anche 1e999) e bool si saltano."""
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def transcript_tokens(path) -> int:
    """Token nuovi del subagente: input + cache_creation + output, una volta per messaggio
    (decisione 20). cache_read resta fuori perché riconta il contesto a ogni turno."""
    seen: dict[str, int] = {}
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return 0
    with fh:
        for n, line in enumerate(fh):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = row.get("message") if isinstance(row, dict) else None
            usage = msg.get("usage") if isinstance(msg, dict) else None
            if not isinstance(usage, dict):
                continue
            total = sum(_count(usage.get(k)) for k in
                        ("input_tokens", "cache_creation_input_tokens", "output_tokens"))
            seen[str(msg.get("id") or f"riga-{n}")] = total
    return sum(seen.values())
