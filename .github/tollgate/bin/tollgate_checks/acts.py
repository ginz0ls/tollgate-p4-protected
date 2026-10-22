"""UserPromptExpansion (spec 8.4): l'atto da command_name (forma lunga) e command_args."""
from __future__ import annotations

import shlex
from pathlib import Path

from tollgate_core import acts, git
from tollgate_core.paths import program_command
from tollgate_hooks.model import inject, record

CHECK = {"api": 1, "events": ["prompt_expansion"], "component": None, "order": 10}
_TARGET_ARG = {"waiver", "effect", "finding", "level", "rounds", "spec"}


def _refuse(why: str):
    return [inject(f"tollgate: atto non registrato: {why}")]


def decide(event, ctx):
    name = str(event.raw.get("command_name") or "")
    if not name.startswith("tollgate:"):
        return []
    if "expansion_type" in event.raw and event.raw["expansion_type"] != "slash_command":
        return []
    type_ = name.split(":", 1)[1]
    if type_ in ("off", "on"):
        return []
    # Decisione 3: il percorso del programma arriva con ogni /tollgate:*, atto o no.
    program = f"tollgate: programma {program_command(ctx.plugin_bin)}"
    if type_ not in acts.ACT_TYPES:
        return [inject(program)]
    out = _act(event, ctx, type_)
    return out[:-1] + [inject(f"{out[-1].text}\n{program}")]


def _act(event, ctx, type_):
    raw_args = str(event.raw.get("command_args") or "")
    try:
        args = shlex.split(raw_args)
    except ValueError:
        args = raw_args.split()
    work = ctx.work if ctx.bound else None
    work_id = work["id"] if work is not None else None
    head = git.head(Path(work["worktree"])) if work is not None and work["worktree"] else None
    obj = target = None
    if type_ == "finish":
        if work is None or not head:
            return _refuse("/tollgate:finish vale solo in una sessione legata a un lavoro: "
                           "riprendi il lavoro con /tollgate:start #<N> (lega questa sessione) "
                           "oppure apri Claude Code nel worktree del lavoro, poi digita di "
                           "nuovo /tollgate:finish")
    elif type_ == "approve":
        if not args or args[0] not in acts.APPROVE_OBJECTS:
            return _refuse(f"oggetto di approve sconosciuto: {args[0] if args else '(vuoto)'}")
        obj = args[0]
        if obj in _TARGET_ARG:
            if len(args) < 2:
                return _refuse(f"approve {obj} richiede un argomento")
            target = args[1]
        elif obj == "pr":
            if not head:
                return _refuse("approve pr vale solo in una sessione legata a un lavoro")
            target = head
    elif type_ == "reopen":
        if not args or args[0] not in ("spec", "plan"):
            return _refuse("reopen vuole spec o plan e un motivo")
        obj = args[0]
    elif type_ == "resolve":
        if not args:
            return _refuse("resolve vuole l'identificativo del blocco")
        target = args[0]
    elif type_ in ("adopt", "abandon"):
        if not args or not args[0].lstrip("#").isdigit():
            return _refuse(f"{type_} vuole il numero dell'issue (#N)")
        target = args[0].lstrip("#")
    if type_ in ("adopt", "cleanup", "abandon"):
        work_id = None
    typed = str(event.raw.get("prompt") or f"/{name} {raw_args}".strip())
    label = " ".join(x for x in (type_, obj, target) if x)
    return [record("expire_acts"),
            record("act", type=type_, object=obj, target=target, args=args, typed_text=typed,
                   work=work_id, head_sha=head if type_ == "finish" else None),
            inject(f"tollgate: atto ricevuto ({label})")]
