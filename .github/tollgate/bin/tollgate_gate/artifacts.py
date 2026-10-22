"""Artefatti di `gate run` letti da `gate evaluate` (spec 9.1, decisione 13): sono dati non fidati,
prodotti da codice della PR. `validate` li controlla prima di leggerne il contenuto."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath

from tollgate_analysis.junit import parse_junit

from .model import CommandResult
from .run import RESULTS_VERSION, STATES

MAX_FILE = 50 * 2**20
MAX_TOTAL = 200 * 2**20


def _report_problem(report) -> str | None:
    if not isinstance(report, str):
        return f"report {report!r} non è un percorso"
    if any(ord(c) < 32 or ord(c) == 127 for c in report):
        return f"report {report!r}: caratteri di controllo"
    path = PurePosixPath(report)
    if path.is_absolute() or ".." in path.parts:
        return f"report {report!r}: percorso assoluto o con '..'"
    if len(path.parts) < 2 or path.parts[0] != "junit":
        return f"report {report!r}: fuori da junit/"
    return None


def _load_results(root: Path, max_file: int = MAX_FILE) -> tuple[dict | None, list[str]]:
    path = root / "results.json"
    try:
        if path.stat().st_size > max_file:
            return None, ["results.json troppo grande"]
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None, ["results.json assente o illeggibile"]
    if not isinstance(data, dict) or data.get("v") != RESULTS_VERSION:
        return None, ["results.json: versione o forma inattesa"]
    if not isinstance(data.get("applicable"), bool) or not isinstance(data.get("commands"), list):
        return None, ["results.json: campi applicable o commands non validi"]
    return data, []


def validate(root: Path, *, max_file: int = MAX_FILE, max_total: int = MAX_TOTAL) -> list[str]:
    """I problemi degli artefatti sotto `root`, vuoto se vanno bene: collegamenti simbolici e file
    non regolari, file o totale oltre i limiti, XML con DOCTYPE o entità, `results.json` assente
    o con percorsi `report` fuori da `junit/`."""
    return _check(Path(root), max_file, max_total)[0]


def _check(root: Path, max_file: int, max_total: int) -> tuple[list[str], dict | None]:
    """I problemi di `validate` e il contenuto di `results.json`, letto una volta sola."""
    try:
        return _check_tree(root, max_file, max_total)
    except Exception as e:  # confine fail-closed su dati non fidati: nessuna eccezione sfugge
        return [f"{type(e).__name__}: {e}"], None


def _check_tree(root: Path, max_file: int, max_total: int) -> tuple[list[str], dict | None]:
    problems: list[str] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        for name in [*dirnames, *filenames]:
            p = base / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                problems.append(f"{rel}: collegamento simbolico")
            elif p.is_file():
                try:
                    size = p.stat().st_size
                except OSError as e:
                    problems.append(f"{rel}: {e.strerror or e}")
                    continue
                total += size
                if size > max_file:
                    problems.append(f"{rel}: oltre {max_file} byte")
            elif not p.is_dir():
                problems.append(f"{rel}: non è un file regolare")
        # i collegamenti a cartelle non si seguono
        dirnames[:] = [d for d in dirnames if not (base / d).is_symlink()]
    if total > max_total:
        problems.append(f"totale degli artefatti oltre {max_total} byte")
    data, found = _load_results(root, max_file)
    problems += found
    if data is not None:
        for cmd in data["commands"]:
            report = cmd.get("report") if isinstance(cmd, dict) else None
            if report is not None and (bad := _report_problem(report)):
                problems.append(f"results.json: {bad}")
    junit_dir = root / "junit"
    if junit_dir.is_dir() and not junit_dir.is_symlink():
        for p in sorted(junit_dir.rglob("*.xml")):
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > max_file:
                    continue    # già segnalato sopra
                parse_junit(p.read_bytes())
            except (OSError, ValueError, RecursionError) as e:     # JunitError è un ValueError
                problems.append(f"{p.relative_to(root).as_posix()}: {e}")
    return problems, data


def _int_or_none(value) -> bool:
    return value is None or (isinstance(value, int) and not isinstance(value, bool))


def read_results(root: Path, *, meta: dict | None = None
                 ) -> tuple[list[CommandResult] | None, bool, list[str]]:
    """(risultati, `applicable`, problemi). Con problemi i risultati sono `None`; con
    `applicable` falso sono una lista vuota. Se `meta` è un dizionario, vi si scrivono `sha` e
    `config_sha` di `results.json` (valori non controllati: li confronta chi chiama), dalla
    stessa lettura."""
    try:
        return _read_results(Path(root), meta)
    except Exception as e:  # confine fail-closed su dati non fidati: nessuna eccezione sfugge
        return None, False, [f"{type(e).__name__}: {e}"]


def _read_results(root: Path, meta: dict | None
                  ) -> tuple[list[CommandResult] | None, bool, list[str]]:
    problems, data = _check(root, MAX_FILE, MAX_TOTAL)
    if problems or data is None:
        return None, False, problems or ["results.json assente o illeggibile"]
    if meta is not None:
        meta.update(sha=data.get("sha"), config_sha=data.get("config_sha"))
    if not data["applicable"]:
        return [], False, []
    results: list[CommandResult] = []
    for cmd in data["commands"]:
        if not isinstance(cmd, dict) or not isinstance(cmd.get("name"), str) \
                or cmd.get("state") not in STATES or not _int_or_none(cmd.get("exit")) \
                or not _int_or_none(cmd.get("tests_run")):
            problems.append(f"results.json: voce non valida {cmd!r}"[:200])
            continue
        junit = None
        if cmd.get("report") is not None:
            try:
                junit = parse_junit((root / cmd["report"]).read_bytes())
            except (OSError, ValueError, RecursionError) as e:
                problems.append(f"results.json: report di {cmd['name']}: {e}")
                continue
        results.append(CommandResult(cmd["name"], cmd["state"], cmd.get("exit"),
                                     cmd.get("tests_run"), junit))
    if problems:
        return None, False, problems
    return results, True, []
