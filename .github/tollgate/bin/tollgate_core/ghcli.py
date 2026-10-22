"""`gh` senza stato (spec 3.1), per il flusso e per il gate. Nei test `TOLLGATE_GH` indica il
finto `tests/fakegh.py`.

Nessun testo non fidato entra mai in un argomento: si passano solo numeri, SHA e prefissi
costruiti da numeri."""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass

from . import paths

GH_ENV = "TOLLGATE_GH"
GH_TIMEOUT_S = 60
REQUIRED_CONTEXTS = ("tollgate/guard", "tollgate/verdict")
SENTINEL_TITLE = "tollgate: merge non verificato"
# Il bot di GitHub Actions: `user.login` dell'API REST (con `user.type == "Bot"`) e
# `author.login` di `gh pr view --json comments` (GraphQL, senza `[bot]`), osservati in V1.
BOT_LOGINS = ("github-actions[bot]", "github-actions")
# Per gli stati di commit (REST) il solo login legittimo è questo (V6): `github-actions` senza
# `[bot]` è un nome utente qualunque.
STATUS_BOT = "github-actions[bot]"

_STATUS_LINE = re.compile(r"HTTP/\S+\s+(\d{3})\b")
_HEADERS_END = re.compile(r"\r?\n\r?\n")


class GhError(Exception):
    pass


@dataclass(frozen=True)
class ApiResult:
    """`status` è il codice HTTP (solo con `include=True`), `data` il corpo JSON decodificato
    (con `paginate`, la lista dei valori), `stderr` l'errore di `gh`."""
    status: int | None
    data: object
    stderr: str


def gh_cmd(state: paths.State) -> list[str]:
    override = paths.test_env(state, GH_ENV)
    return [override] if override else ["gh"]


def run(state, repo, args) -> subprocess.CompletedProcess:
    env = {**os.environ, "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"}
    try:
        return subprocess.run([*gh_cmd(state), *args], cwd=str(repo), capture_output=True,
                              text=True, timeout=GH_TIMEOUT_S, env=env,
                              stdin=subprocess.DEVNULL)
    except FileNotFoundError as e:
        raise GhError("gh non è installato") from e
    except subprocess.TimeoutExpired as e:
        raise GhError(f"gh {' '.join(args[:2])}: timeout dopo {GH_TIMEOUT_S} s") from e


def _failed(args, r) -> GhError:
    return GhError(f"gh {' '.join(args[:2])}: {r.stderr.strip() or 'uscita ' + str(r.returncode)}")


def run_json(state, repo, args):
    r = run(state, repo, args)
    if r.returncode != 0:
        raise _failed(args, r)
    try:
        return json.loads(r.stdout)
    except ValueError as e:
        raise GhError(f"gh {' '.join(args[:2])}: risposta non JSON") from e


def decode_json_values(text: str) -> list[dict]:
    """I valori JSON dell'uscita in sequenza (G5: niente `--slurp`), uno per riga o su più righe,
    separati da spazi. Un testo non JSON o un valore che non è un oggetto è un errore."""
    decoder, values, i = json.JSONDecoder(), [], 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return values
        try:
            value, i = decoder.raw_decode(text, i)
        except ValueError as e:
            raise GhError("risposta non JSON") from e
        if not isinstance(value, dict):
            raise GhError("risposta inattesa: un valore JSON che non è un oggetto")
        values.append(value)


def run_json_lines(state, repo, args) -> list[dict]:
    """Per `--paginate --jq`: un oggetto JSON per elemento. Uscita non zero → `GhError`."""
    r = run(state, repo, args)
    if r.returncode != 0:
        raise _failed(args, r)
    try:
        return decode_json_values(r.stdout)
    except GhError as e:
        raise GhError(f"gh {' '.join(args[:2])}: {e}") from e


def _split_include(stdout: str) -> tuple[int, str] | None:
    """`(codice, corpo)` dell'uscita di `gh api --include`: riga di stato, intestazioni, riga
    vuota, corpo (V2). `None` se la prima riga non è una riga di stato."""
    first, _, rest = stdout.partition("\n")
    m = _STATUS_LINE.match(first)
    if m is None:
        return None
    end = _HEADERS_END.search(rest)
    # senza riga vuota dopo le intestazioni non c'è corpo (intestazioni terminate da `\r\n`)
    body = rest[end.end():] if end else ""
    return int(m.group(1)), body


def api(state, cwd, path: str, *, method: str = "GET", fields: dict[str, str] | None = None,
        file_fields: dict[str, object] | None = None, input_file=None, include: bool = False,
        paginate: bool = False, jq: str | None = None) -> ApiResult:
    """`gh api`. Con `include=True` il codice HTTP si legge dalla riga di stato e un 403 o 404 è un
    risultato (`status`, `data` col corpo JSON se c'è), non un errore; senza, l'uscita non zero è
    un `GhError`. `file_fields` passa il contenuto di un file come campo (`-F chiave=@file`): il
    testo non fidato non entra mai negli argomenti. `paginate` vuole `jq` (G5: gli array delle
    pagine non si concatenano) e `data` è la lista dei valori che il filtro stampa, uno per riga."""
    if paginate and jq is None:
        raise ValueError("api --paginate richiede jq")
    if paginate and include:
        raise ValueError("api --paginate non si combina con --include")
    args = ["api"]
    if method != "GET":
        args += ["--method", method]
    if include:
        args.append("--include")
    if paginate:
        args.append("--paginate")
    if jq is not None:
        args += ["--jq", jq]
    for key, value in (fields or {}).items():
        args += ["-f", f"{key}={value}"]
    for key, value in (file_fields or {}).items():
        args += ["-F", f"{key}=@{value}"]
    if input_file is not None:
        args += ["--input", str(input_file)]
    args.append(path)
    r = run(state, cwd, args)
    status, text = None, r.stdout
    if include:
        split = _split_include(r.stdout)
        if split is None:
            raise _failed(args, r) if r.returncode != 0 else GhError(
                f"gh {' '.join(args[:2])}: risposta senza riga di stato")
        status, text = split
    elif r.returncode != 0:
        raise _failed(args, r)
    if paginate:
        try:
            return ApiResult(status, decode_json_values(text), r.stderr)
        except GhError as e:
            raise GhError(f"gh {' '.join(args[:2])}: {e}") from e
    try:
        data = json.loads(text) if text.strip() else None
    except ValueError as e:
        if r.returncode == 0:
            raise GhError(f"gh {' '.join(args[:2])}: risposta non JSON") from e
        data = None
    return ApiResult(status, data, r.stderr)
