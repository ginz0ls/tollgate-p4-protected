"""SubagentStart (spec 7.2): base, impronta e tipo; associazione al task; promemoria."""
from __future__ import annotations

from pathlib import Path

from tollgate_core import git, subagents
from tollgate_core.paths import program_command
from tollgate_hooks.model import inject, record

from ._common import governing_work

CHECK = {"api": 1, "events": ["subagent_start"], "component": None, "order": 20}


def decide(event, ctx):
    if not event.agent_type or not event.agent_id:
        return []
    work = governing_work(ctx, event.cwd)
    row = subagents.get(ctx.db, event.agent_id)
    resume = row is not None and row["started"] is not None
    wt = Path(work["worktree"]) if work is not None and work["worktree"] else None
    base = git.head(wt) if wt is not None and wt.is_dir() else None
    fp = git.fingerprint(wt, ctx.cfg("review.output_dirs")) if base else None
    implementer = not ctx.readonly(event.agent_type)
    out = [record("subagent_start", agent_id=event.agent_id, type=event.agent_type,
                  work=work["id"] if work is not None else None,
                  task=row["task"] if row is not None else None, base_sha=base, fingerprint=fp,
                  take_pending=implementer and work is not None, resume=resume,
                  refresh_fingerprint=resume and not implementer)]
    if implementer and work is not None:
        out.append(inject(
            f"tollgate: sei un subagente che scrive nel lavoro #{work['issue']}. Lavora solo sui "
            f"file dello scope del task, con TDD. Prima di DONE: committa, poi lancia "
            f"{program_command(ctx.plugin_bin)} verify e controlla che la ricevuta sia green. "
            f"Chiudi con il "
            f"report JSON di 18.5 (v, task, status, done, tests, files, must_have, concerns, "
            f"left, size_reason). Se un test contraddice la specifica: "
            f"{program_command(ctx.plugin_bin)} block open test_spec_conflict --reason \"…\" e BLOCKED."))
    return out
