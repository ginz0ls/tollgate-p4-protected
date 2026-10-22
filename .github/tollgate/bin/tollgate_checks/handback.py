"""PostToolUse SubagentHandback (spec 7.2): in auto mode è l'unica fonte del report."""
from __future__ import annotations

from tollgate_hooks.model import record

CHECK = {"api": 1, "events": ["subagent_handback"], "component": None, "order": 10}


def decide(event, ctx):
    msg = event.tool_input.get("message")
    if not event.agent_id or not isinstance(msg, str):
        return []
    return [record("subagent_report", agent_id=event.agent_id, text=msg)]
