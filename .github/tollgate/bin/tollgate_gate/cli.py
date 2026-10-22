"""`tollgate gate <sottocomando>` (spec 3.1, decisione 1): gira su GitHub senza DB né cartella di
stato. `bin/tollgate` lo smista prima di importare `tollgate_core.cli`."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from tollgate_core import git
from tollgate_core.config import ConfigError
from tollgate_core.ghcli import GhError
from tollgate_core.git import GitError

from . import baseids, guard, sentinel, verdict
from . import run as gate_run

ACTIONS_ENV = "GITHUB_ACTIONS"


class GateUsageError(ValueError):
    pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gate", description="Il gate di tollgate su GitHub",
                                allow_abbrev=False)
    sub = p.add_subparsers(dest="gate_cmd", required=True)
    r = sub.add_parser("run", allow_abbrev=False,
                      help="esegue i comandi del gate sulla testa e scrive gli artefatti")
    r.add_argument("--event", required=True, metavar="FILE", help="evento della PR (JSON)")
    r.add_argument("--out", required=True, metavar="DIR", help="cartella degli artefatti")
    b = sub.add_parser("base-ids", allow_abbrev=False,
                      help="esegue la suite della base e scrive ids.json")
    b.add_argument("--sha", required=True, metavar="SHA", help="commit della base")
    b.add_argument("--out", required=True, metavar="DIR")
    b.add_argument("--root", metavar="DIR",
                   help="checkout da cui calcolare l'albero (predefinito: la cartella corrente)")
    b.add_argument("--event", metavar="FILE", help="evento da cui leggere il ramo predefinito")
    q = sub.add_parser("base-publish", allow_abbrev=False,
                       help="pubblica tollgate/base dai dati di base-ids, senza eseguire codice")
    q.add_argument("--ids", required=True, metavar="DIR", help="cartella con ids.json")
    q.add_argument("--event", required=True, metavar="FILE", help="evento push (JSON)")
    q.add_argument("--publish", action="store_true", help="solo dentro GitHub Actions")
    g = sub.add_parser("guard", allow_abbrev=False,
                       help="controlla i file di tollgate e i workflow del progetto di una PR")
    g.add_argument("--event", required=True, metavar="FILE", help="evento della PR (JSON)")
    g.add_argument("--publish", action="store_true", help="solo dentro GitHub Actions")
    e = sub.add_parser("evaluate", allow_abbrev=False,
                       help="il verdetto: legge gli artefatti di run e pubblica gli stati")
    e.add_argument("--event", required=True, metavar="FILE", help="evento workflow_run (JSON)")
    e.add_argument("--artifacts", required=True, metavar="DIR", help="artefatti di tollgate-run")
    e.add_argument("--base-ids-cache", metavar="FILE", help="ids.json ripristinato dalla cache")
    e.add_argument("--base-ids-artifact", metavar="DIR", help="artefatto tollgate-base-ids")
    e.add_argument("--publish", action="store_true", help="solo dentro GitHub Actions")
    n = sub.add_parser("sentinel", allow_abbrev=False,
                       help="dopo un push sul predefinito: ogni commit viene da una PR verificata?")
    n.add_argument("--event", required=True, metavar="FILE", help="evento push (JSON)")
    n.add_argument("--publish", action="store_true", help="solo dentro GitHub Actions")
    return p


def _require_actions(args) -> None:
    if args.publish and os.environ.get(ACTIONS_ENV) != "true":
        raise GateUsageError(f"--publish si usa solo dentro GitHub Actions ({ACTIONS_ENV}=true)")


def _read_event(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except UnicodeDecodeError as e:
        raise GateUsageError(f"{path}: codifica non UTF-8") from e
    if not isinstance(data, dict):
        raise GateUsageError(f"{path}: l'evento non è un oggetto JSON")
    return data


def _field(data: dict, *keys: str) -> str:
    node = data
    for k in keys:
        node = node.get(k) if isinstance(node, dict) else None
    if not isinstance(node, str) or not node:
        raise GateUsageError(f"evento senza {'.'.join(keys)}")
    return node


def _default_tip(repo: Path, default: str) -> str:
    tip = git.resolve_ref(repo, f"origin/{default}")
    if tip is None:
        raise GitError(f"origin/{default} non trovato: serve un checkout con il ramo predefinito")
    return tip


def cmd_run(args) -> int:
    repo = Path.cwd()
    event = _read_event(args.event)
    base_ref = _field(event, "pull_request", "base", "ref")
    default = _field(event, "repository", "default_branch")
    tip = _default_tip(repo, default)
    applicable = base_ref == default
    base_sha = git.run(repo, "merge-base", tip, "HEAD").strip() if applicable else ""
    return gate_run.run(repo, config_sha=tip, base_sha=base_sha, out=Path(args.out),
                        environ=os.environ, applicable=applicable)


def cmd_base_ids(args) -> int:
    cwd = Path.cwd()
    root = Path(args.root) if args.root else cwd
    default = (_field(_read_event(args.event), "repository", "default_branch") if args.event
               else git.default_branch(cwd))
    if not default:
        raise GitError("ramo predefinito non determinabile: passa --event")
    tip = _default_tip(cwd, default)
    sha = git.resolve_ref(root, args.sha)
    if sha is None:
        raise GitError(f"commit {args.sha!r} non trovato in {root}")
    result = baseids.compute(root, config_sha=tip, sha=sha, out=Path(args.out),
                             environ=os.environ, cfg_repo=cwd)
    print(f"base-ids: albero {result['tree']}, {len(result['ids'])} comandi")
    return 0


def cmd_base_publish(args) -> int:
    _require_actions(args)
    cwd = Path.cwd()
    event = _read_event(args.event)
    tip = _default_tip(cwd, _field(event, "repository", "default_branch"))
    return baseids.publish_from(cwd, config_sha=tip, sha=_field(event, "after"),
                                ids_dir=Path(args.ids), environ=os.environ, publish=args.publish)


def cmd_guard(args) -> int:
    _require_actions(args)
    return guard.run(Path(args.event), publish=args.publish, environ=os.environ)


def cmd_evaluate(args) -> int:
    _require_actions(args)
    return verdict.main(
        Path(args.event), artifacts=Path(args.artifacts),
        base_ids_cache=Path(args.base_ids_cache) if args.base_ids_cache else None,
        base_ids_artifact=Path(args.base_ids_artifact) if args.base_ids_artifact else None,
        publish=args.publish, environ=os.environ)


def cmd_sentinel(args) -> int:
    _require_actions(args)
    return sentinel.run(Path(args.event), publish=args.publish, environ=os.environ)


HANDLERS = {"run": cmd_run, "base-ids": cmd_base_ids, "base-publish": cmd_base_publish,
            "guard": cmd_guard, "evaluate": cmd_evaluate, "sentinel": cmd_sentinel}


def main(args: list[str]) -> int:
    ns = build_parser().parse_args(args)
    try:
        return HANDLERS[ns.gate_cmd](ns)
    except (GhError, GitError, ConfigError, OSError, ValueError) as e:
        sys.stderr.write(f"gate {ns.gate_cmd}: {e}\n")
        return 1
