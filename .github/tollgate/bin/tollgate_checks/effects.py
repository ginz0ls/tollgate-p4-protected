"""Effetti esterni (spec 8.5): veto con identificativo, una esecuzione per atto.

`PreToolUse` controlla che ogni effetto della riga abbia un atto valido e non consuma nulla:
se la riga viene negata da un altro controllo l'atto resta intatto. Il consumo (l'effetto
risulta eseguito) avviene in `PostToolUse Bash`, che scatta solo se il comando è partito. Gli
strumenti MCP non hanno un `PostToolUse` nell'adattatore: per loro l'atto si consuma al
`PreToolUse`."""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path

from tollgate_analysis import bash
from tollgate_core import acts, effects, git
from tollgate_hooks.model import deny, inject, record

from ._common import governing_work

CHECK = {"api": 1, "events": ["pre_bash", "post_bash", "pre_mcp"], "component": None,
         "order": 30}


@dataclass(frozen=True)
class Intent:
    key: str
    eid: str
    work: int | None
    sha: str | None
    command: str
    reason: str
    row: object
    prev: str | None
    act: object


def _intent(ctx, event, command: str, reason: str, repo: Path | None, where: Path) -> Intent:
    work = governing_work(ctx, where)
    work_id = work["id"] if work is not None else None
    sha = git.head(repo) if repo else None
    key = effects.effect_key(command, work_id, sha)
    eid = effects.effect_id(key)
    row = effects.get(ctx.db, key)
    act = acts.find_usable(ctx.db, type_="approve", object_="effect", target=eid, work=work_id,
                           session=event.session, now=ctx.now)
    return Intent(key, eid, work_id, sha, command, reason, row, effects.executed_at(row), act)


def _request(i: Intent):
    return record("effect_request", key=i.key, command=i.command, work=i.work, sha=i.sha)


def _execute(i: Intent):
    """Richiesta (se manca la riga) e consumo dell'atto."""
    return ([] if i.row is not None else [_request(i)]) + [
        record("effect_execute", key=i.key, act_id=i.act["act_id"], work=i.work)]


def _veto_text(i: Intent) -> str:
    why = i.reason if i.reason.startswith("effetto esterno") else f"effetto esterno ({i.reason})"
    msg = (f"{why}: {i.command[:200]}. Per eseguirlo una volta l'utente digita "
           f"/tollgate:approve effect {i.eid}")
    if i.prev:
        msg += f". Attenzione: già eseguito alle {i.prev} su questo SHA"
    return msg


def _gate(intents: list[Intent], *, consume: bool):
    """Un solo veto per tutta la riga: basta un effetto senza atto. Lo stesso effetto
    ripetuto nella riga ha bisogno di un atto per ogni esecuzione."""
    seen, denied, requests, allowed = set(), None, [], []
    for i in intents:
        repeated = i.key in seen
        seen.add(i.key)
        if i.act is None or repeated:
            if denied is None:
                denied = _veto_text(i) if i.act is None else (
                    "la riga ripete lo stesso effetto: un atto vale una esecuzione, lancia i "
                    "comandi separatamente")
            requests += [] if i.row is not None else [_request(i)]
            continue
        warn = f" (attenzione: già eseguito alle {i.prev} su questo SHA)" if i.prev else ""
        allowed += _execute(i) if consume else ([] if i.row is not None else [_request(i)])
        allowed.append(inject(f"tollgate: effetto {i.eid} permesso una volta dall'atto "
                              f"{i.act['act_id']}{warn}"))
    if denied is not None:
        return [deny(denied, rule="effects")] + requests
    return allowed


def _script_reason(ctx, c: bash.Cmd) -> str | None:
    """Script dentro un repo che non è tracciato nella base (8.5, anche se ignorato da git)."""
    sp = bash.script_path(c)
    if not sp:
        return None
    p = Path(sp)
    repo = git.toplevel(p)
    if repo is None:
        return None
    work = governing_work(ctx, p)
    ref = work["work_base_sha"] if work is not None and work["work_base_sha"] \
        else git.default_ref(repo)
    rel = ctx.rel(p, repo)
    if ref and rel and not git.exists_at(repo, ref, rel):
        return "script nel repo non tracciato nella base"
    return None


def _bash_intents(event, ctx) -> list[Intent]:
    raw = str(event.tool_input.get("command") or "")
    try:
        cmds = bash.parse(raw, str(event.cwd))
    except bash.BashParseError:
        label = bash.text_effect(raw)
        if not label:
            return []
        repo = git.toplevel(event.cwd) if event.cwd.exists() else None
        return [_intent(ctx, event, " ".join(raw.split()), label, repo, event.cwd)]
    ee = ctx.cfg("external_effects")
    cfg = bash.EffectsCfg(ee["commands"], ee["project_scripts"], ee["allow"])
    out = []
    for c in cmds:
        if bash.uses_tollgate_bin(c, str(ctx.plugin_bin)):
            continue
        edir = Path(bash.effective_dir(c))
        reason = bash.effect_reason(c, cfg) or _script_reason(ctx, c)
        if reason:
            repo = git.toplevel(edir) if edir.exists() else None
            out.append(_intent(ctx, event, bash.normalized(c), reason, repo, edir))
    return out


def decide(event, ctx):
    if event.kind == "pre_mcp":
        name = event.tool_name or ""
        if any(fnmatch.fnmatchcase(name, pat) for pat in ctx.cfg("external_effects.mcp_allow")):
            return []
        command = f"{name} {json.dumps(event.tool_input, sort_keys=True, ensure_ascii=False)}"
        return _gate([_intent(ctx, event, command, "strumento MCP non in mcp_allow", ctx.repo,
                              event.cwd)], consume=True)
    intents = _bash_intents(event, ctx)
    if event.kind == "pre_bash":
        return _gate(intents, consume=False)
    out, seen = [], set()
    for i in intents:
        if i.act is not None and i.key not in seen:
            seen.add(i.key)
            out += _execute(i)
    return out
