"""PreToolUse Bash: chiamate al programma `tollgate` (decisioni 2 e 22).

La CLI gira dentro Bash e non riceve il session_id: per `start` e `act`, i soli sottocomandi
che leggono la sessione (e quelli di chiusura di P3b), il controllo lascia un segnale (operazione `cli_call`). Un subagente
non può lanciare i comandi del coordinatore. `gate … --publish` scrive su GitHub con
il token del processo: dentro Actions e nient'altro, quindi lo si nega a chiunque (D4)."""
from __future__ import annotations

import os
import re

from tollgate_analysis import bash
from tollgate_hooks.model import deny, record

CHECK = {"api": 1, "events": ["pre_bash"], "component": None, "order": 5}
_SIGNALLED = ("start", "act", "finish", "sync", "adopt", "cleanup", "abandon")
_COORDINATOR_ONLY = ("start", "task", "act", "finish", "review", "sync", "adopt", "cleanup",
                     "abandon", "audit")


def _undecidable(token: str) -> bool:
    """Un percorso che la shell espande a runtime (`$p`, `$(…)`, backtick): non si sa quale
    programma sia."""
    return "$" in token or "`" in token or token == bash.SUBST_TOKEN


def _program_args(c: bash.Cmd, plugin_bin: str) -> tuple[list[str], bool] | None:
    """Gli argomenti dopo il programma (`tollgate x` o `python3 [opzioni] <bin/tollgate> x`) e se il
    programma è certo (False: lo script o il comando è un'espansione, trattato come possibile
    programma). None se non è il programma."""
    a = c.argv
    if not a:
        return None
    k = bash.script_index(a)
    if k is not None and (bash.uses_tollgate_bin(c, plugin_bin)
                          or os.path.basename(a[k]) == "tollgate"):
        return a[k + 1:], True
    if bash.uses_tollgate_bin(c, plugin_bin) or os.path.basename(a[0]) == "tollgate":
        return a[1:], True
    if k is not None and _undecidable(a[k]):
        return a[k + 1:], False
    if _undecidable(a[0]):
        return a[1:], False
    return None


def _subcommand(args: list[str]) -> str | None:
    return next((x for x in args if not x.startswith("-")), None)


def _coordinator_only(sub: str | None, args: list[str]) -> bool:
    return sub in _COORDINATOR_ONLY or (sub == "status" and "--checkpoint" in args)


def _is_publish(token: str) -> bool:
    """`--publish` o un suo prefisso di almeno `--pu`, con o senza `=valore`."""
    name = token.split("=", 1)[0]
    return len(name) >= 4 and "--publish".startswith(name)


def _publishes(sub: str | None, args: list[str]) -> bool:
    return sub == "gate" and any(_is_publish(x) for x in args)


def _deny_publish():
    return deny("il sottocomando gate con --publish pubblica su GitHub e si lancia solo dentro "
                "GitHub Actions: in locale gli stati non contano e non si scrivono.",
                rule="gate_publish")


def _deny_subagent(sub: str | None, certain: bool):
    text = (f"tollgate {sub} è un comando del coordinatore: un subagente non lo lancia. "
            "Riporta al coordinatore (BLOCKED o NEEDS_CONTEXT).")
    if not certain:
        text += (" Il programma qui è una variabile o un'espansione e non si può riconoscere: se "
                 "non stai lanciando tollgate, scrivi il percorso dello script in modo letterale, "
                 "senza variabile né $(…).")
    return deny(text, rule="coordinator_only")


def decide(event, ctx):
    raw = str(event.tool_input.get("command") or "")
    try:
        cmds = bash.parse(raw, str(event.cwd))
    except bash.BashParseError:
        # Fail-closed per un subagente: non si capisce il comando, ma se nomina il programma con
        # un sottocomando del coordinatore non passa.
        words = set(re.findall(r"[\w-]+", raw))
        if "tollgate" in raw and "gate" in words and any(_is_publish(w) for w in words):
            return [_deny_publish()]
        if event.agent_id and "tollgate" in raw and (words & {*_COORDINATOR_ONLY, "--checkpoint"}):
            return [deny("comando non analizzabile che nomina tollgate con un sottocomando del "
                         "coordinatore: un subagente non lo lancia. Riporta al coordinatore "
                         "(BLOCKED o NEEDS_CONTEXT). Se non stai lanciando tollgate, scrivi il "
                         "comando in modo letterale, senza variabili né $(…)",
                         rule="coordinator_only")]
        return []
    out = []
    for c in cmds:
        found = _program_args(c, str(ctx.plugin_bin))
        if found is None:
            continue
        args, certain = found
        sub = _subcommand(args)
        if _publishes(sub, args):
            return [_deny_publish()]
        if event.agent_id:
            if _coordinator_only(sub, args):
                return [_deny_subagent(sub, certain)]
            continue
        if certain and sub in _SIGNALLED:
            out.append(record("cli_call", cwd=bash.effective_dir(c), argv=args[args.index(sub):]))
    return out
