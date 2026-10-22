"""PreToolUse SendMessage (spec 7.2, 6.3): le riprese seguono le regole dello scrittore."""
from __future__ import annotations

from tollgate_core import subagents
from tollgate_core.paths import program_command
from tollgate_hooks.model import deny

from ._common import governing_work
from .agents import live_writers

CHECK = {"api": 1, "events": ["pre_send_message"], "component": None, "order": 20}


def decide(event, ctx):
    work = governing_work(ctx, event.cwd)
    if work is None:
        return []
    to = str(event.tool_input.get("to") or event.tool_input.get("recipient") or "")
    target = subagents.by_name(ctx.db, to, work=work["id"]) or (
        subagents.get(ctx.db, to) if to else None)
    from_main = event.agent_id is None
    in_exec = work["phase"] == "execution" and work["level"] in ("L1", "L2")
    if target is None:
        if from_main and in_exec:
            return [deny(f"destinatario «{to}» mai registrato: in execution vale come un "
                         f"implementatore senza task start (6.3)", rule="writer")]
        return []
    if not target["type"] or ctx.readonly(target["type"]):
        return []
    if not in_exec:
        return []
    if not from_main:
        return [deny("un subagente non riprende un subagente che scrive", rule="writer")]
    task = None
    if target["task"] is not None:
        task = ctx.db.execute("SELECT * FROM tasks WHERE work = ? AND number = ?",
                              (work["id"], target["task"])).fetchone()
    ok = task is not None and (
        (task["pending"] == "resume" and task["agent_type"] == target["type"])
        or (task["state"] == "running" and target["declared_status"] == "NEEDS_CONTEXT"))
    if not ok:
        return [deny(f"ripresa di {to} negata: serve {program_command(ctx.plugin_bin)} task start "
                     f"{target['task']} --fix, "
                     f"oppure una risposta a NEEDS_CONTEXT (6.3)", rule="writer")]
    out = []
    if ctx.component("single_writer"):
        live, out = live_writers(ctx, work["id"], exclude=(target["id"],))
        if live:
            return out + [deny(f"scrittore unico: {live[0]['id']} è ancora in corso",
                               rule="single_writer")]
    return out
