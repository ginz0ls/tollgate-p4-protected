"""Regole sui workflow del progetto (spec 9.2, decisione 15). Puro: nessun accesso a git né al
disco. Non è un parser YAML: legge per righe e, nel dubbio, dà rosso (fail-closed)."""
from __future__ import annotations

import re

FORBIDDEN_EVENTS = ("pull_request_target", "workflow_run")
GUARDED_SCOPES = ("statuses", "checks")
SAFE_VALUES = ("read", "none")

_PATH = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
_EVENT = re.compile(r"(?<![\w-])(" + "|".join(FORBIDDEN_EVENTS) + r")(?![\w-])")
_WRITE_ALL = re.compile(r"(?<![\w-])write-all(?![\w-])")
_SCOPE = re.compile(r"(?:^|[\s{,\[-])[\"']?(" + "|".join(GUARDED_SCOPES) + r")[\"']?[ \t]*:"
                    r"(?:[ \t]+|(?=[,}\]]|$))(\"[^\"]*\"|'[^']*'|[^\s,}\]]*)")
# àncora, alias o chiave di fusione: a inizio nodo (riga, `- `, dopo `chiave: `, `[`, `{` o `,`)
_ANCHOR = re.compile(r"(?:^\s*(?:-\s+)*|:\s+|[\[{,]\s*)[&*]\S")
_MERGE = re.compile(r"^\s*(?:-\s+)?<<\s*:")
_TOP_PERMISSIONS = re.compile(r"^[\"']?permissions[\"']?[ \t]*:")
# tag YAML (`!!str`, `!tag`, `!<...>`): a inizio nodo, come àncore e alias
_TAG = re.compile(r"(?:^\s*(?:-\s+)*|:\s*|[\[{,]\s*)!")
# chiave complessa `? `
_COMPLEX_KEY = re.compile(r"^\s*(?:-\s+)*\?(?:\s|$)")
_TAB_INDENT = re.compile(r"^[ ]*\t")
_RUN_KEY = re.compile(r"^\s*(?:-\s+)*[\"']?run[\"']?\s*:\s*$")
# inizio nodo fuori da un flusso: a inizio riga, dopo soli indicatori (`- `, `? `, `--- `) o dopo
# `: ` (uno scalare semplice non contiene `: `); `a - "x` è uno scalare semplice
_LEAD = re.compile(r"[ \t]*(?:(?:-|\?|---)[ \t]+)*")
_AFTER_COLON = re.compile(r":[ \t]+$")
# intestazione di scalare a blocco: `|` o `>` (con `+`/`-` e una cifra) è l'intero valore di
# `chiave:` o di `- `
_BLOCK_HEADER = re.compile(
    r"(?P<lead>[ ]*(?:-[ \t]+)*)"
    r"(?:(?P<key>\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*'"
    r"|(?:[^\s\"'#\[\]{},&*!|>%@`?:-]|[?:-](?=\S))(?:[^:]|:(?=\S))*?)[ \t]*:[ \t]+)?"
    r"[|>](?:(?P<width>[1-9])[-+]?|[-+](?P<width2>[1-9])?)?[ \t]*")


def is_workflow_path(rel: str) -> bool:
    """`.github/workflows/<nome>.yml` o `.yaml`, direttamente nella cartella."""
    return _PATH.match(rel) is not None


def _strip_comment(line: str) -> str:
    """La riga senza il commento (`#` a inizio riga o dopo uno spazio, fuori dalle virgolette)."""
    quote, i = "", 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
        i += 1
    return line


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].strip()
    return value


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _next_value(lines: list[str], index: int) -> str:
    """Il valore di una chiave senza valore sulla sua riga: la riga seguente, se più rientrata
    e senza `:` né `- ` (un valore su più righe); altrimenti vuoto (la chiave apre una mappa)."""
    here = _indent(lines[index])
    for line in lines[index + 1:]:
        text = _strip_comment(line)
        if not text.strip():
            continue
        if _indent(text) > here and ":" not in text and not text.lstrip().startswith("-"):
            return _unquote(text)
        return ""
    return ""


def _block_header(line: str) -> tuple[int, int | None] | None:
    """Se `line` (fuori da stringhe e flussi) è l'intestazione di uno scalare a blocco: il rientro
    del nodo che lo contiene (la colonna della chiave, o dell'ultimo `-` per `- |`) e il rientro
    del contenuto, se l'indicatore lo fissa (altrimenti lo fissa la prima riga non vuota)."""
    m = _BLOCK_HEADER.fullmatch(_strip_comment(line).rstrip())
    if m is None:
        return None
    lead = m.group("lead")
    if m.group("key") is not None:
        base = len(lead)
    elif "-" in lead:
        base = lead.rfind("-")
    else:
        return None
    width = m.group("width") or m.group("width2")
    return base, base + int(width) if width else None


def _flow_node_start(before: str, closed_at: int) -> bool:
    """Una virgoletta dentro un flusso apre una stringa dopo `[`, `{`, `,`, `? `, `: `, a inizio
    riga o dopo `:` attaccato a una chiave tra virgolette (`{"a":"b"}`)."""
    head = before.rstrip()
    if not head or head[-1] in "[{," or _AFTER_COLON.search(before):
        return True
    if head[-1] == "?" and head != before:
        rest = head[:-1].rstrip()
        return not rest or rest[-1] in "[{,"
    return head[-1] == ":" and len(head) - 2 == closed_at


def _scan(lines: list[str]) -> tuple[list[str], set[int]]:
    """Legge il testo con lo stato di YAML che serve alle regole: dentro una stringa a doppie o a
    singole virgolette, profondità di flusso, dentro uno scalare a blocco (col rientro del
    contenuto). Restituisce i problemi che vede (un `\\` in una stringa a doppie virgolette fuori
    dal valore di `run:`, un flusso che non si chiude sulla riga in cui si apre, una virgoletta
    dentro un flusso fuori da inizio nodo, una stringa aperta a inizio riga che non si chiude
    sulla stessa riga) e i numeri di riga del contenuto degli scalari a blocco, che è testo."""
    found: list[str] = []
    blocks: set[int] = set()
    quote, run_value, depth = "", False, 0
    block: tuple[int, int | None] | None = None
    for number, line in enumerate(lines, 1):
        if block is not None:
            base, inner = block
            if not line.strip():
                blocks.add(number)
                continue
            if inner is None and _indent(line) > base:
                inner = _indent(line)
            if inner is not None and _indent(line) >= inner:
                block = (base, inner)
                blocks.add(number)
                continue
            block = None
        clean_start = not quote and depth == 0
        flow_here = escape = stray = lead_quote = False
        closed_at, i = -1, 0
        while i < len(line):
            c = line[i]
            if quote == '"':
                if c == "\\":
                    if not run_value and not escape:
                        found.append(f"escape (\\) in una stringa tra virgolette doppie fuori da "
                                     f"run: (riga {number}): non si controlla")
                        escape = True
                    i += 1
                elif c == '"':
                    quote, closed_at = "", i
            elif quote == "'":
                if c == "'" and line[i + 1:i + 2] == "'":
                    i += 1
                elif c == "'":
                    quote, closed_at = "", i
            elif c == "#" and (i == 0 or line[i - 1] in " \t"):
                break
            elif c in "[{" and (depth or _LEAD.fullmatch(line[:i]) or
                                _AFTER_COLON.search(line[:i])):
                flow_here = flow_here or not depth
                depth += 1
            elif c in "]}" and depth:
                depth -= 1
            elif c in "\"'" and depth:
                if _flow_node_start(line[:i], closed_at):
                    quote, run_value = c, False
                elif not stray:
                    found.append(f"virgolette dentro una collezione a flusso fuori da inizio "
                                 f"nodo (riga {number}): non si controlla")
                    stray = True
            elif c in "\"'":
                before = line[:i]
                if _LEAD.fullmatch(before):
                    quote, run_value, lead_quote = c, False, True
                elif _AFTER_COLON.search(before):
                    quote, run_value = c, _RUN_KEY.match(before) is not None
                    lead_quote = False
            i += 1
        if depth and flow_here:
            found.append(f"collezione a flusso su più righe (riga {number}): non si "
                         f"controlla")
        if quote and lead_quote and not depth:
            found.append(f"stringa tra virgolette su più righe aperta a inizio riga (riga "
                         f"{number}): non si controlla")
        if clean_start and not flow_here and not quote and not depth:
            block = _block_header(line)
    return found, blocks


def problems(text: str) -> list[str]:
    """Le regole che il workflow `text` viola, una frase ciascuna (`[]` se nessuna): niente
    `pull_request_target` né `workflow_run` (nemmeno in una stringa), una chiave `statuses` o
    `checks` a qualunque livello solo con `read` o `none`, niente `write-all`, un blocco
    `permissions` di primo livello. Fail-closed: un testo che non si legge (tabulazione di
    rientro, byte non UTF-8), un'àncora, un alias o `<<:` YAML, una collezione a flusso su più
    righe sono un problema."""
    if any(c == "�" or c == "\x00" or "\ud800" <= c <= "\udfff" for c in text):
        return ["il file non si legge: byte non UTF-8 o caratteri di controllo"]
    lines = text.lstrip("﻿").splitlines()
    for number, line in enumerate(lines, 1):
        if _TAB_INDENT.match(line):
            return [f"il file non si legge: tabulazione nel rientro (riga {number})"]
    found: list[str] = []
    scanned, blocks = _scan(lines)
    top_permissions = False
    for number, raw in enumerate(lines, 1):
        line = _strip_comment(raw)
        if _TOP_PERMISSIONS.match(line):
            top_permissions = True
        for m in _EVENT.finditer(line):
            found.append(f"usa {m.group(1)} (riga {number})")
        if _WRITE_ALL.search(line):
            found.append(f"permissions: write-all (riga {number})")
        for m in _SCOPE.finditer(line):
            value = _unquote(m.group(2))
            if not value:
                value = _next_value(lines, number - 1)
            if value and value not in SAFE_VALUES:
                found.append(f"{m.group(1)}: {value} invece di read o none (riga {number})")
        if _COMPLEX_KEY.match(line):
            found.append(f"chiave complessa YAML `?` (riga {number}): non si controlla")
        if number not in blocks and (_ANCHOR.search(line) or _MERGE.match(line)):
            found.append(f"àncora, alias o chiave di fusione YAML (riga {number}): non si "
                         f"controlla")
        if number not in blocks and _TAG.search(line):
            found.append(f"tag YAML (riga {number}): non si controlla")
    found += scanned
    if not top_permissions:
        found.append("manca il blocco permissions di primo livello")
    return found
