"""Esecuzione dei comandi del gate (spec 8.1), senza stato: nessun DB. La usano `verify` (in
locale) e `tollgate_gate` (su GitHub)."""
from __future__ import annotations

import contextlib
import os
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from tollgate_analysis import profiles as prof
from tollgate_analysis.junit import Junit, JunitError, parse_junit

from .config import Config, ConfigError

TIMEOUT_EXIT = 124


@dataclass(frozen=True)
class CommandSpec:
    name: str
    command: str
    report: str


def _report_for(report, name: str) -> str:
    if isinstance(report, dict):
        return report.get(name, "")
    return report or ""


def report_path(spec: str) -> str | None:
    """Percorso del report relativo al worktree. Assoluto o con `..` è rifiutato, prima di ogni unlink."""
    rel = spec.split(":", 1)[1] if spec.startswith("junit:") else spec
    if not rel:
        return None
    path = PurePosixPath(rel)
    if path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"report {rel!r} non valido: deve essere un percorso relativo al "
                          f"worktree, senza '..'")
    return rel


def gate_commands(cfg: Config, files) -> list[CommandSpec]:
    cmds = cfg.get("commands")
    out = [CommandSpec(n, cmds.get(n, ""), _report_for(cmds["report"], n))
           for n in cmds["gate"]]
    profs = cfg.profiles
    for name in prof.active_profiles(files, profs, cfg.get("profiles.active")):
        p = profs[name]
        for n in p["gate"]:
            out.append(CommandSpec(f"profile:{name}:{n}", p["commands"].get(n, ""),
                                   _report_for(p["report"], n)))
    return out


def dod_commands(cfg: Config, files) -> list[CommandSpec]:
    """I `dod` dei profili attivi che non sono già nel gate, con nome `profile:<p>:<c>`."""
    profs = cfg.profiles
    out = []
    for name in prof.active_profiles(files, profs, cfg.get("profiles.active")):
        p = profs[name]
        for n in p["dod"]:
            if n not in p["gate"]:
                out.append(CommandSpec(f"profile:{name}:{n}", p["commands"].get(n, ""),
                                       _report_for(p["report"], n)))
    return out


def receipt_state(*, exit_code: int, report_configured: bool, junit: Junit | None,
                  allow_no_tests: bool) -> str:
    if report_configured and junit is None:
        return "red"     # report configurato e assente: resta rosso (8.1, decisione 11)
    if junit is None:
        return "red" if exit_code != 0 else "uncounted"
    if exit_code != 0 or junit.failed:
        return "red"
    if junit.total - junit.skipped == 0:
        return "empty"
    return "green"


def clean_env(env_allow, environ) -> dict:
    # le variabili di test TOLLGATE_* non arrivano mai al comando, nemmeno se in env_allow
    return {k: environ[k] for k in env_allow
            if k in environ and not k.startswith("TOLLGATE_")}


def counts_green(state: str, exit_code: int, allow_no_tests: bool) -> bool:
    return state == "green" or (allow_no_tests and (
        state == "empty" or (state == "uncounted" and exit_code == 0)))


def run_one(spec: CommandSpec, *, root: Path, files: list[str], env: dict, timeout_s: int,
            allow_no_tests: bool, log_dir: Path, tag: str
            ) -> tuple[str, int, Junit | None, float, str, Path]:
    resolved = spec.command.replace("{files}", " ".join(shlex.quote(f) for f in files))
    report_rel = report_path(spec.report)
    report = root / report_rel if report_rel else None
    if report is not None:
        report.unlink(missing_ok=True)
    log = log_dir / f"{tag}-{spec.name.replace(':', '_')}.log"
    t0 = time.monotonic()
    timed_out = False
    with open(log, "wb") as fh:
        # sessione propria: al timeout si uccide l'intero gruppo, figli in background compresi
        proc = subprocess.Popen(["/bin/sh", "-c", resolved], cwd=root, env=env,
                                stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            proc.communicate(timeout=timeout_s)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            exit_code = TIMEOUT_EXIT
            timed_out = True
        finally:
            # anche a fine normale: nessun figlio in background sopravvive al comando
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
    duration = time.monotonic() - t0
    if timed_out:
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(f"\n[tollgate] timeout dopo {timeout_s} s\n")
    junit = None
    if report is not None and report.is_file():
        try:
            junit = parse_junit(report.read_bytes())
        except JunitError as e:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(f"\n[tollgate] report non valido: {e}\n")
    state = receipt_state(exit_code=exit_code, report_configured=report is not None,
                          junit=junit, allow_no_tests=allow_no_tests)
    return resolved, exit_code, junit, duration, state, log


def executed_ids(junit: Junit) -> set[str]:
    """Gli identificativi eseguiti e non saltati, compresi i falliti."""
    return (set(junit.ids_run) | set(junit.ids_failed)) - set(junit.ids_skipped)


def ids_commands(cfg: Config) -> list[CommandSpec]:
    """I comandi `gate` globali più il `gate` di ogni profilo dichiarato, qualunque sia il diff:
    gli identificativi della base di un albero non dipendono da chi li ha calcolati."""
    cmds = cfg.get("commands")
    out = [CommandSpec(n, cmds.get(n, ""), _report_for(cmds["report"], n)) for n in cmds["gate"]]
    for name, p in cfg.profiles.items():
        for n in p["gate"]:
            out.append(CommandSpec(f"profile:{name}:{n}", p["commands"].get(n, ""),
                                   _report_for(p["report"], n)))
    return out
