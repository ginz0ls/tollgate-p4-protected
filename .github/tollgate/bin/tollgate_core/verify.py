"""tollgate verify (spec 8.1): comandi del gate su HEAD, ambiente ripulito, ricevute."""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field

from tollgate_analysis.junit import Junit

from . import clock, db, git, receipts, sessions
from .config import ConfigError, load_config, output_excludes
from .paths import State, ensure_dirs
# I nomi del modulo `runner` restano importabili da qui (gli alias privati sono i vecchi nomi).
from .runner import (TIMEOUT_EXIT, CommandSpec, _report_for, clean_env, counts_green,  # noqa: F401
                     dod_commands, executed_ids, gate_commands, receipt_state)
from .runner import report_path as _report_path, run_one as _run_one


@dataclass
class GateRun:
    """Esito di `run_gate`. `sha is None`: gate non eseguito (worktree sporco, configurazione
    non valida, nessun comando); `lines` porta il motivo."""
    ok: bool
    lines: list[str]
    sha: str | None = None
    states: dict[str, str] = field(default_factory=dict)
    junits: dict[str, Junit | None] = field(default_factory=dict)


def run_verify(state: State, cwd, *, related: bool = False, now=None,
               environ=None) -> tuple[int, list[str]]:
    """Esegue i comandi e registra le ricevute. Errori di git o del DB diventano uscita 1."""
    run = _guarded(state, cwd, related=related, produced_by="verify", extra=(), now=now,
                   environ=environ, strict=False)
    return (0 if run.ok else 1), run.lines


def run_gate(state: State, cwd, *, produced_by: str, extra: list[CommandSpec] = (), now=None,
             environ=None) -> GateRun:
    """Come `run_verify` senza `--related`: gate più `extra`, ricevute con `produced_by` dato,
    JUnit di ogni comando restituiti (per i must-have di `finish check`)."""
    return _guarded(state, cwd, related=False, produced_by=produced_by, extra=extra, now=now,
                    environ=environ, strict=True)


def _guarded(state, cwd, *, related, produced_by, extra, now, environ, strict) -> GateRun:
    environ = os.environ if environ is None else environ
    label = f"tollgate {produced_by}"
    try:
        return _gate(state, cwd, related=related, produced_by=produced_by, extra=list(extra),
                     now=now, environ=environ, label=label, strict=strict)
    except git.GitError as e:
        return GateRun(False, [f"{label}: {e}"])
    except sqlite3.Error as e:
        return GateRun(False, [f"{label}: errore del database: {e}"])


def _gate(state, cwd, *, related: bool, produced_by: str, extra: list[CommandSpec], now,
          environ, label: str, strict: bool) -> GateRun:
    root = git.toplevel(cwd)
    if root is None:
        return GateRun(False, [f"{label}: non sei in un repo git"])
    conn = db.open_db(state)
    try:
        work = sessions.work_for_path(conn, root)
        wid = work["id"] if work is not None else None
        # C13: senza work_base_sha si usa il riferimento di base del repo, mai None
        base = (work["work_base_sha"] if work is not None else None) or git.default_ref(root)
        if base is None:
            return GateRun(False, [f"{label}: nessun riferimento remoto da cui leggere tollgate.toml"])
        try:
            cfg = load_config(state, root, base, env=environ)
        except ConfigError as e:
            return GateRun(False, [f"{label}: {e}"])
        exclude = output_excludes(cfg)
        if not git.is_clean(root, exclude):
            return GateRun(False, [f"{label}: worktree non pulito: committa prima di verificare"])
        sha = git.head(root)
        if sha is None:
            return GateRun(False, [f"{label}: nessun commit da verificare"])
        files = [c.path for c in git.changes(root, base, head=sha) if c.status != "D"]
        allow = cfg.get("project.allow_no_tests")
        cmds = cfg.get("commands")
        # decisione 12: --related esegue test_related sui file cambiati; se non trova test
        # ripiega sul gate completo (8.1)
        use_related = related and bool(files) and bool(cmds["test_related"])
        related_spec = CommandSpec("related", cmds["test_related"], cmds["report_related"])
        gate = gate_commands(cfg, files) + extra
        # i percorsi dei report si validano prima di eseguire o cancellare alcunché
        try:
            for spec in ([related_spec] if use_related else []) + gate:
                _report_path(spec.report)
        except ConfigError as e:
            return GateRun(False, [f"{label}: {e}"])
        if strict and not gate:
            return GateRun(False, [f"{label}: nessun comando del gate da eseguire"])
        env = clean_env(cfg.get("commands.env_allow"), environ)
        timeout_s = cfg.get("commands.timeout_s")
        now = now or clock.now()
        ensure_dirs(state)
        log_dir = state.root / "logs"
        log_dir.mkdir(mode=0o700, exist_ok=True)
        tag = (f"{work['issue'] if work is not None else 'repo'}-{sha[:7]}-"
               f"{now.strftime('%Y%m%dT%H%M%S')}")

        states: dict[str, str] = {}
        junits: dict[str, Junit | None] = {}

        def execute(spec: CommandSpec) -> tuple[str, bool, str]:
            if not spec.command:
                states[spec.name], junits[spec.name] = "unverified", None
                receipts.add(conn, work=wid, sha=sha, command=spec.name, resolved_command=None,
                             exit_code=None, tests_run=None, tests_skipped=None, duration=None,
                             log=None, produced_by=produced_by, state="unverified", now=now)
                return "unverified", False, (f"{spec.name}: unverified (comando non configurato: "
                                             f"serve /tollgate:approve unverified-tests)")
            resolved, exit_code, junit, duration, st, log = _run_one(
                spec, root=root, files=files, env=env, timeout_s=timeout_s,
                allow_no_tests=allow, log_dir=log_dir, tag=tag)
            states[spec.name], junits[spec.name] = st, junit
            receipts.add(conn, work=wid, sha=sha, command=spec.name, resolved_command=resolved,
                         exit_code=exit_code,
                         tests_run=(junit.total - junit.skipped) if junit else None,
                         tests_skipped=junit.skipped if junit else None, duration=duration,
                         log=str(log), produced_by=produced_by, state=st, now=now)
            good = counts_green(st, exit_code, allow)
            run = f", {junit.total - junit.skipped} test" if junit else ""
            line = f"{spec.name}: {st} (uscita {exit_code}{run}; log {log})"
            if st == "uncounted" and not good:
                line += ("; uncounted: il comando è uscito 0 senza report, quindi non conta i test;"
                         " con allow_no_tests = false il verdetto è rosso")
            return st, good, line

        lines: list[str] = []
        if use_related:
            st, good, line = execute(related_spec)
            lines.append(line)
            if st != "empty":
                return GateRun(good, lines, sha, states, junits)
            lines.append("nessun test correlato: si esegue il gate completo")
        all_ok = True
        for spec in gate:
            st, good, line = execute(spec)
            all_ok = all_ok and good
            lines.append(line)
        return GateRun(all_ok, lines, sha, states, junits)
    finally:
        conn.close()
