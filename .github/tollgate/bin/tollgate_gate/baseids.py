"""Identificativi di test della base (spec 9.5, decisione 12): `gate base-ids` esegue la suite
della base e scrive `ids.json`; `load` lo rilegge, solo se è dello stesso albero. `gate
base-publish` pubblica `tollgate/base` da quel file senza eseguire codice del progetto."""
from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from tollgate_core import git, paths, runner
from tollgate_core.config import load_config_at

from . import github
from . import run as gate_run

IDS_VERSION = 1
MAX_IDS_FILE = 50 * 2**20


def compute(repo: Path, *, config_sha: str, sha: str, out: Path, environ: Mapping[str, str],
            cfg_repo: Path | None = None) -> dict:
    """Esegue in `repo` (il checkout di `sha`) i comandi di `runner.ids_commands`, con la
    configurazione di `config_sha` letta in `cfg_repo` (di norma `repo`), e scrive
    `out/ids.json`. Un `setup` fallito lascia i comandi `red` e senza identificativi."""
    cfg = load_config_at(cfg_repo or repo, config_sha)
    tree = git.run(repo, "rev-parse", f"{sha}^{{tree}}").strip()
    specs = runner.ids_commands(cfg)
    setups = gate_run.setup_commands(cfg, list(cfg.profiles))
    entries = gate_run.run_commands(repo, cfg, setups, specs, files=[], environ=environ,
                                    out=out, tag=f"base-{sha[:7]}")
    ids, commands = {}, {}
    for spec, entry in zip(specs, entries[len(setups):]):
        junit = entry.get("_junit")
        ids[spec.name] = sorted(runner.executed_ids(junit)) if junit is not None else []
        commands[spec.name] = entry["state"]
    result = {"v": IDS_VERSION, "tree": tree, "sha": sha, "ids": ids, "commands": commands}
    out.mkdir(parents=True, exist_ok=True)
    (out / "ids.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def load(path: Path, *, tree: str) -> dict[str, set[str]] | None:
    """Gli identificativi per comando, `None` se il file è illeggibile, malformato o di un altro
    albero."""
    try:
        return _load(path, tree)
    except Exception:   # confine fail-closed su dati non fidati: illeggibile = assente
        return None


def _load(path: Path, tree: str) -> dict[str, set[str]] | None:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("v") != IDS_VERSION or data.get("tree") != tree:
        return None
    ids = data.get("ids")
    if not isinstance(ids, dict):
        return None
    out: dict[str, set[str]] = {}
    for name, values in ids.items():
        if (not isinstance(name, str) or not isinstance(values, list)
                or not all(isinstance(v, str) for v in values)):
            return None
        out[name] = set(values)
    return out


def publish(repo: Path, *, config_sha: str, sha: str, result: dict,
            environ: Mapping[str, str]) -> None:
    """In `detect` pubblica `tollgate/base` sul commit `sha` (spec 9.1): `failure` se qualche
    comando della suite della base è `red`, e allora commenta anche l'issue di sentinel (la crea
    se manca). In `protected` non scrive nulla: il segnale è il job."""
    _publish(repo, load_config_at(repo, config_sha), sha=sha, result=result, environ=environ)


def _publish(repo: Path, cfg, *, sha: str, result: dict, environ: Mapping[str, str]) -> None:
    if cfg.get("gate.mode") != "detect":
        return
    state, slug = paths.resolve_state(environ), github.repo_slug(environ)
    red = sorted(name for name, st in result["commands"].items() if st == "red")
    open_ = sorted(name for name, st in result["commands"].items() if st == "unverified")
    extra = f"; non verificati: {', '.join(open_)}" if open_ else ""
    if not red:
        github.set_status(state, repo, slug, sha, context="tollgate/base", status="success",
                          description=f"suite della base verde{extra}")
        return
    github.set_status(state, repo, slug, sha, context="tollgate/base", status="failure",
                      description=f"suite della base rossa: {len(red)} comandi{extra}")
    with tempfile.TemporaryDirectory(prefix="tollgate-base-") as tmp:
        body = Path(tmp) / "body.md"
        body.write_text(
            "## tollgate: merge non verificato\n\nLa suite della base è rossa sul commit "
            f"`{sha}`. Comandi rossi: {', '.join(f'`{n}`' for n in red)}.\n\n"
            "Chiudi l'issue su GitHub dopo averla letta.\n", encoding="utf-8")
        github.report_sentinel(state, repo, slug, body_file=body)


def read_result(path: Path, *, tree: str, names: set[str]) -> dict | None:
    """Il risultato di `ids.json` per `publish`, `None` se il file è assente, un collegamento
    simbolico, troppo grande, malformato, di un altro albero, o ha comandi che la configurazione
    non conosce o stati fuori da `run.STATES`. Il file viene da un job che esegue codice del
    progetto: nulla del suo testo entra in uno stato o in un commento se non è tra i `names`."""
    try:
        p = Path(path)
        if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_IDS_FILE:
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("v") != IDS_VERSION or data.get("tree") != tree:
            return None
        commands = data.get("commands")
        if not isinstance(commands, dict) or not set(commands) <= names:
            return None
        if not all(isinstance(v, str) and v in gate_run.STATES for v in commands.values()):
            return None
        return {"commands": dict(commands)}
    except Exception:   # confine fail-closed su dati non fidati: illeggibile = assente
        return None


def publish_from(repo: Path, *, config_sha: str, sha: str, ids_dir: Path,
                 environ: Mapping[str, str], publish: bool) -> int:
    """Pubblica da `ids_dir/ids.json` (l'artefatto di `ids`, dati non fidati) come `publish`.
    Il file deve essere dell'albero di `sha` (su un cache hit il suo `sha` è un altro commit con
    lo stesso albero). Se non è valido: in `detect` stato `error` con il motivo, e codice 1 in
    ogni modalità, così il job è rosso. Senza `publish` legge e basta."""
    cfg = load_config_at(repo, config_sha)
    tree = git.run(repo, "rev-parse", f"{sha}^{{tree}}").strip()
    names = {spec.name for spec in runner.ids_commands(cfg)}
    result = read_result(Path(ids_dir) / "ids.json", tree=tree, names=names)
    if result is None:
        sys.stderr.write("base-publish: identificativi della base assenti o non validi\n")
        if publish and cfg.get("gate.mode") == "detect":
            github.set_status(paths.resolve_state(environ), repo, github.repo_slug(environ), sha,
                              context="tollgate/base", status="error",
                              description="identificativi della base assenti o non validi")
        return 1
    if publish:
        _publish(repo, cfg, sha=sha, result=result, environ=environ)
    return 0
