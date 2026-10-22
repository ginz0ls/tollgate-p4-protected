"""Lettura di codice senza commenti e stringhe (JS/TS e simili, Python)."""
from __future__ import annotations

import io
import tokenize

# Dopo queste parole chiave una `/` apre una regex (altrimenti è una divisione).
_KW_BEFORE = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void",
              "throw", "yield", "await"}
# Punteggiatura dopo la quale una `/` apre una regex. `=>` finisce con `>`.
_RE_PREV = set("(,=:[!&|?{};+-*%<>~^")


def _regex_ok(last, jsx: bool) -> bool:
    if last is None:
        return True
    kind, val = last
    if kind == "p":
        if jsx and val == "<":          # `</p>` in JSX: la `/` è un tag di chiusura
            return False
        return val in _RE_PREV
    if kind == "id":
        return val in _KW_BEFORE
    return False


def _regex_end(text: str, i: int) -> int | None:
    """Fine (esclusa) di una regex letterale che inizia in `i`; None se non è una regex."""
    n = len(text)
    j, cls = i + 1, False
    while j < n:
        c = text[j]
        if c == "\n":
            return None
        if c == "\\":
            j += 2
            continue
        if cls:
            if c == "]":
                cls = False
        elif c == "[":
            cls = True
        elif c == "/":
            break
        j += 1
    else:
        return None
    j += 1
    while j < n and (text[j].isalnum() or text[j] == "_"):   # flag
        j += 1
    return j


def _template(text: str, i: int) -> tuple[str, int, bool]:
    """Testo di un template da `i`: (segmento, posizione dopo, vero se si apre `${`)."""
    n, buf, j = len(text), [], i
    while j < n:
        c = text[j]
        if c == "\\" and j + 1 < n:
            buf.append(text[j + 1])
            j += 2
            continue
        if c == "`":
            return "".join(buf), j + 1, False
        if c == "$" and j + 1 < n and text[j + 1] == "{":
            return "".join(buf), j + 2, True
        buf.append(c)
        j += 1
    return "".join(buf), n, False


def _apostrophe(text: str, i: int, last) -> bool:
    """Apice JSX come in `don't`: lettera prima e dopo, non preceduto da una parola chiave."""
    return (0 < i < len(text) - 1 and text[i - 1].isalpha() and text[i + 1].isalpha()
            and last is not None and last[0] == "id" and last[1] not in _KW_BEFORE)


def js_tokens(text: str, jsx: bool = False):
    """Token di linguaggi con la sintassi del C: ('str', valore), ('re', regex), ('id', nome),
    ('p', carattere). I template con `${}` emettono i segmenti come 'str' e il codice interno
    come token normali. `jsx` abilita la regola dell'apice dei file .jsx/.tsx."""
    n = len(text)
    i = 0
    last = None
    braces: list[int] = []   # per ogni `${` aperto: parentesi graffe non ancora chiuse
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == "`" or (c == "}" and braces and braces[-1] == 0):
            if c == "}":
                braces.pop()
            seg, i, expr = _template(text, i + 1)
            yield ("str", seg)
            if expr:
                braces.append(0)
                last = None
            else:
                last = ("str", seg)
            continue
        tok = None
        re_end = _regex_end(text, i) if c == "/" and _regex_ok(last, jsx) else None
        if c in "'\"":
            if jsx and c == "'" and _apostrophe(text, i, last):
                tok, i = ("p", c), i + 1
            else:
                j, buf = i + 1, []
                # Come in JS, una stringa non terminata finisce a fine riga.
                while j < n and text[j] != c and text[j] != "\n":
                    if text[j] == "\\" and j + 1 < n:
                        buf.append(text[j + 1])
                        j += 2
                        continue
                    buf.append(text[j])
                    j += 1
                tok, i = ("str", "".join(buf)), j + 1
        elif re_end is not None:
            tok, i = ("re", text[i:re_end]), re_end
        elif c.isalnum() or c in "_$":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            tok, i = ("id", text[i:j]), j
        else:
            if c == "{" and braces:
                braces[-1] += 1
            elif c == "}" and braces and braces[-1] > 0:
                braces[-1] -= 1
            if not c.isspace():
                tok = ("p", c)
            i += 1
        if tok is not None:
            last = tok
            yield tok


def js_code(text: str, jsx: bool = False) -> str:
    return " ".join("S" if k in ("str", "re") else v for k, v in js_tokens(text, jsx))


def py_code(text: str) -> str | None:
    """Codice Python senza commenti né stringhe; None se il file non si legge.
    Le f-string (3.12+ le tokenizza) non contribuiscono, come su 3.11."""
    out = []
    fdepth = 0
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            name = tokenize.tok_name[tok.type]
            if name == "ERRORTOKEN" and not tok.string.isspace():
                return None   # Python 3.11 non solleva su una stringa non chiusa
            if name == "FSTRING_START":
                fdepth += 1
                continue
            if name == "FSTRING_END":
                fdepth -= 1
                continue
            if fdepth or "STRING" in name or name in ("COMMENT", "NL", "NEWLINE", "INDENT",
                                                      "DEDENT", "ENDMARKER"):
                continue
            out.append(tok.string)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    return " ".join(out)
