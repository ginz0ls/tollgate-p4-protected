"""SessionStart (spec 7.2): legame, subagenti di sessioni morte, stato e checkpoint."""
from __future__ import annotations

from pathlib import Path

from tollgate_core import sessions, subagents
from tollgate_hooks.model import inject, record

from ._common import orphan_next, orphan_tg, status_lines

CHECK = {"api": 1, "events": ["session_start"], "component": None, "order": 10}
MAX_LINES, MAX_CHARS = 10, 1500


def decide(event, ctx):
    out = [record("expire_acts")]
    for row in subagents.running(ctx.db):
        if row["session"] and row["session"] != event.session and not sessions.alive(
                ctx.db, row["session"], now=ctx.now, stale_minutes=ctx.stale_minutes):
            out.append(record("subagent_interrupt", agent_id=row["id"]))
    work = ctx.work
    if work is not None and not ctx.bound:
        out.append(record("bind", work=work["id"]))
    if work is None:
        n = orphan_tg(ctx, ctx.repo)
        if n is not None:
            why, command = orphan_next(ctx, ctx.repo, n)
            hint = " (DB perso?)" if command.startswith("/tollgate:adopt") else ""
            out.append(inject(f"tollgate: ramo tg/{n}-* {why}{hint}. Le scritture sono negate "
                              f"finché l'utente non lancia {command}."))
        return out
    cp_lines = []
    if work["worktree"]:
        cp = Path(work["worktree"]) / f"docs/superpowers/reviews/{work['issue']}/checkpoint.md"
        try:
            cp_lines = cp.read_text(encoding="utf-8").strip().splitlines()
        except OSError:
            pass
    out.append(inject(compose(status_lines(ctx, work), cp_lines)))
    return out


def compose(status: list[str], cp_lines: list[str]) -> str:
    """Stato e checkpoint entro il budget di SessionStart (6.3: ≤ 10 righe, ≤ 1.500 caratteri).
    Il checkpoint tiene le ultime righe, dove sta il prossimo passo: si scartano le prime."""
    room = MAX_LINES - len(status) - 1
    body = cp_lines[-room:] if room > 0 and cp_lines else []
    out = status + (["checkpoint:"] + body if body else [])
    while len("\n".join(out)) > MAX_CHARS and len(out) > len(status) + 1:
        out.pop(len(status) + 1)
    return "\n".join(out)
