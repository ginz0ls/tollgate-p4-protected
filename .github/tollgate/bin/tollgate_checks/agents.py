"""PreToolUse Agent (spec 7.2, 6.3): contesto, subagenti fermi, scrittore unico, implementatore."""
from __future__ import annotations

import json

from tollgate_core import clock, subagents
from tollgate_core.paths import program_command
from tollgate_hooks.model import deny, inject, record

from ._common import governing_work

CHECK = {"api": 1, "events": ["pre_agent"], "component": None, "order": 20}
RESERVATION_S = 120


def context_pct(ctx, session: str):
    """Percentuale di contesto scritta dalla statusline (decisione 13); None se non c'è."""
    try:
        data = json.loads((ctx.state.root / "ctx" / f"{session}.json").read_text())
        v = data.get("used_pct")
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    except (OSError, ValueError, AttributeError):
        return None


def live_writers(ctx, work_id, exclude=()):
    """(scrittori vivi, record di interruzione dei fermi oltre stale_minutes)."""
    rows = [r for r in subagents.running(ctx.db, work=work_id) if r["id"] not in exclude]
    stale = [r for r in rows if subagents.is_stale(r, now=ctx.now,
                                                    stale_minutes=ctx.stale_minutes)]
    live = [r for r in rows if r not in stale
            and not ctx.readonly(r["type"])]
    return live, [record("subagent_interrupt", agent_id=r["id"]) for r in stale]


def decide(event, ctx):
    work = governing_work(ctx, event.cwd)
    if work is None:
        return []
    out = []
    if ctx.component("context_guard"):
        pct = context_pct(ctx, event.session)
        if pct is not None and pct >= ctx.cfg("context.stop_pct"):
            prog = program_command(ctx.plugin_bin)
            return [deny(f"contesto al {pct:.0f}%: nessun nuovo subagente. Scrivi il checkpoint "
                         f"({prog} status --checkpoint) e fai /clear (6.3)", rule="context")]
        if pct is not None and pct >= ctx.cfg("context.warn_pct"):
            out.append(inject(f"tollgate: contesto al {pct:.0f}%; a "
                              f"{ctx.cfg('context.stop_pct')}% servirà checkpoint e /clear."))
    ti = event.tool_input
    atype = str(ti.get("subagent_type") or "general-purpose")
    if ctx.readonly(atype):
        return out
    live, interrupts = live_writers(ctx, work["id"])
    out += interrupts
    if ctx.component("single_writer") and live:
        w = live[0]
        return out + [deny(f"scrittore unico: {w['type']} ({w['id']}) è ancora in corso nel "
                           f"lavoro #{work['issue']}. Se la sua sessione è caduta: "
                           f"/tollgate:resolve writer", rule="single_writer")]
    if work["phase"] != "execution" or work["level"] not in ("L1", "L2"):
        return out
    pending = ctx.db.execute("SELECT * FROM tasks WHERE work = ? AND pending = 'launch' "
                             "ORDER BY number", (work["id"],)).fetchall()
    cand = [t for t in pending if t["agent_type"] == atype]
    if not cand:
        hint = (f"; il task {pending[0]['number']} aspetta {pending[0]['agent_type']}"
                if pending else "")
        return out + [deny(f"in execution l'unico subagente che scrive è l'implementatore scelto "
                           f"da {program_command(ctx.plugin_bin)} task start: {atype} non ha "
                           f"un task start in sospeso"
                           f"{hint}. Usa /tollgate:execute (6.3)", rule="writer")]
    t = cand[0]
    if ti.get("name") != t["implementer"]:
        return out + [deny(f"l'implementatore va lanciato con name «{t['implementer']}» "
                           f"(scritto nel brief): serve per riprenderlo con SendMessage",
                           rule="writer")]
    if ti.get("run_in_background"):
        return out + [deny("l'implementatore si lancia in primo piano: i task sono in sequenza",
                           rule="writer")]
    # Decisione 12: due `Agent` nello stesso messaggio vedono lo stesso task in sospeso.
    if t["reserved_at"] and \
            (ctx.now - clock.parse(t["reserved_at"])).total_seconds() < RESERVATION_S:
        return out + [deny(f"lancio già in corso per il task {t['number']}", rule="writer")]
    return out + [record("task_reserve", work=work["id"], number=t["number"])]
