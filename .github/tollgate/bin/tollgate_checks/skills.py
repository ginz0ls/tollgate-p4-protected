"""PostToolUse Skill (spec 7.2, 6.3): la skill usata dall'implementatore va al suo task."""
from __future__ import annotations

from tollgate_core import subagents
from tollgate_hooks.model import record

CHECK = {"api": 1, "events": ["post_skill"], "component": None, "order": 20}


def decide(event, ctx):
    if not event.agent_id:
        return []
    row = subagents.get(ctx.db, event.agent_id)
    skill = event.tool_input.get("skill") or event.tool_input.get("command")
    if row is None or row["task"] is None or row["work"] is None or not skill:
        return []
    return [record("skill_used", work=row["work"], number=row["task"], skill=str(skill))]
