"""PostToolUse Agent (spec 7.2): nome → agent_id, report in primo piano, taglio di maxTurns.

In background `PostToolUse Agent` è `async_launched` e non porta il taglio: lo riconosce
`prompt_submit`."""
from __future__ import annotations

from tollgate_analysis import report
from tollgate_hooks.model import record

from ._common import budget_cut_records, governing_work

CHECK = {"api": 1, "events": ["post_agent"], "component": None, "order": 20}


def decide(event, ctx):
    tr = event.tool_response or {}
    aid = tr.get("agentId")
    if not aid:
        return []
    work = governing_work(ctx, event.cwd)
    out = []
    if event.tool_input.get("name"):
        out.append(record("subagent_name", agent_id=aid, name=str(event.tool_input["name"]),
                          work=work["id"] if work is not None else None))
    hb = tr.get("handbackReport")
    if isinstance(hb, dict) and isinstance(hb.get("text"), str):
        out.append(record("subagent_report", agent_id=aid, text=hb["text"]))
    if report.is_turn_cut(tr):
        out += budget_cut_records(ctx, aid, tr.get("totalTokens"))
    return out
