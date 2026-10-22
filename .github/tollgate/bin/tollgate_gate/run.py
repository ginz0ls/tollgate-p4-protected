"""`gate run` (spec 9.1): esegue sulla testa i comandi del gate letti dalla punta del predefinito e
scrive gli artefatti (`results.json`, `junit/`, `logs/`). Nessun DB, nessuno stato locale."""
from __future__ import annotations

import json
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path

from tollgate_analysis import profiles as prof
from tollgate_core import git, runner
from tollgate_core.config import Config, load_config_at

LOG_MAX = 1024 * 1024
# `results.json` (decisione 13): stati e versione che `artifacts.read_results` accetta.
STATES = ("green", "red", "empty", "uncounted", "unverified")
RESULTS_VERSION = 1


def truncate_log(path: Path, limit: int = LOG_MAX) -> None:
    """Tiene la coda del log (la fine di un comando fallito è la parte utile)."""
    size = path.stat().st_size
    if size <= limit:
        return
    with open(path, "rb") as fh:
        fh.seek(size - limit)
        tail = fh.read()
    path.write_bytes(f"[tollgate] log troncato: ultimi {limit} byte\n".encode() + tail)


def setup_commands(cfg: Config, names) -> list[runner.CommandSpec]:
    """I `setup` globale e dei profili `names` (D5), nell'ordine, senza quelli vuoti."""
    out = [runner.CommandSpec("setup", cfg.get("commands.setup"), "")]
    for name in names:
        out.append(runner.CommandSpec(f"profile:{name}:setup", cfg.profiles[name]["setup"], ""))
    return [s for s in out if s.command]


def run_commands(repo: Path, cfg: Config, setups: list[runner.CommandSpec],
                 gate: list[runner.CommandSpec], *, files: list[str], environ: Mapping[str, str],
                 out: Path, tag: str) -> list[dict]:
    """Esegue prima i `setup`, poi i comandi del gate; copia i JUnit in `out/junit` e tronca i
    log in `out/logs`. Ogni voce ha `name`, `state`, `exit`, `tests_run`, `tests_skipped`,
    `report` e `_junit` (il `Junit` letto, per chi vuole gli identificativi); un comando che non
    gira ha `exit` nullo e, se salta per un `setup` fallito, un `reason`."""
    env = runner.clean_env(cfg.get("commands.env_allow"), environ)
    timeout_s = cfg.get("commands.timeout_s")
    allow = cfg.get("project.allow_no_tests")
    for spec in [*setups, *gate]:       # prima di eseguire o cancellare alcunché
        runner.report_path(spec.report)
    log_dir, junit_dir = out / "logs", out / "junit"
    log_dir.mkdir(parents=True, exist_ok=True)
    junit_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []
    failed_setup = None
    for spec in setups:
        _, code, _junit, _dur, state, log = runner.run_one(
            spec, root=repo, files=files, env=env, timeout_s=timeout_s, allow_no_tests=allow,
            log_dir=log_dir, tag=tag)
        truncate_log(log)
        entries.append(_entry(spec.name, state, code, None, None))
        if state == "red" and failed_setup is None:
            failed_setup = spec.name
    for i, spec in enumerate(gate):
        if failed_setup is not None:
            entries.append(_entry(spec.name, "red", None, None, None,
                                  reason=f"non eseguito: {failed_setup} è fallito"))
        elif not spec.command:
            entries.append(_entry(spec.name, "unverified", None, None, None))
        else:
            _, code, junit, _dur, state, log = runner.run_one(
                spec, root=repo, files=files, env=env, timeout_s=timeout_s,
                allow_no_tests=allow, log_dir=log_dir, tag=tag)
            truncate_log(log)
            report = None
            if junit is not None:
                report_rel = runner.report_path(spec.report)
                shutil.copyfile(repo / report_rel, junit_dir / f"{i}.xml")
                report = f"junit/../{i}.xml"
            entry = _entry(spec.name, state, code,
                           junit.total - junit.skipped if junit else None,
                           junit.skipped if junit else None, report=report)
            entry["_junit"] = junit
            entries.append(entry)
    return entries


def _entry(name, state, exit_code, tests_run, tests_skipped, *, report=None, reason=None) -> dict:
    entry = {"name": name, "state": state, "exit": exit_code, "tests_run": tests_run,
             "tests_skipped": tests_skipped, "report": report}
    if reason:
        entry["reason"] = reason
    return entry


def run(repo: Path, *, config_sha: str, base_sha: str, out: Path, environ: Mapping[str, str],
        applicable: bool) -> int:
    """Scrive `out/results.json`. 0 se il file è scritto (lo stato lo decide `verdict`), 1 se non
    si può scrivere. Con `applicable` falso non esegue nulla."""
    head = git.head(repo) or ""
    results: dict = {"v": RESULTS_VERSION, "applicable": applicable, "sha": head,
                     "config_sha": config_sha, "commands": []}
    try:
        out.mkdir(parents=True, exist_ok=True)
        if applicable:
            cfg = load_config_at(repo, config_sha)
            files = []
            for c in git.changes(repo, base_sha, head=head):
                if c.status != "D":
                    files.append(c.path)
            names = prof.active_profiles(files, cfg.profiles, cfg.get("profiles.active"))
            entries = run_commands(
                repo, cfg, setup_commands(cfg, names), runner.gate_commands(cfg, files),
                files=files, environ=environ, out=out, tag=head[:7] or "head")
            results["commands"] = [{k: v for k, v in e.items() if not k.startswith("_")}
                                   for e in entries]
        (out / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"gate run: {e.strerror or e} ({e.filename or out})\n")
        return 1
    return 0
