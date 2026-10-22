"""UserPromptSubmit (spec 6.3, 7.2): taglio di maxTurns in background e alla ripresa.

Non c'è SubagentStop: il taglio arriva come `<task-notification>` nel prompt (P2 E7, E8).
Il componente `task_budget` si controlla in `budget_cut_records`: la riga si chiude sempre."""
from __future__ import annotations

import re

from ._common import budget_cut_records

CHECK = {"api": 1, "events": ["prompt_submit"], "component": None, "order": 20}

_BLOCK = re.compile(r"<task-notification>(.*?)</task-notification>", re.S)
_TASK_ID = re.compile(r"<task-id>\s*([^<\s]+)\s*</task-id>")
_SUMMARY = re.compile(r"<summary>(.*?)</summary>", re.S)
_TOKENS = re.compile(r"<subagent_tokens>\s*(\d+)\s*</subagent_tokens>")
_CUT = re.compile(r"stopped at its \d+-turn limit")


def decide(event, ctx):
    prompt = event.raw.get("prompt")
    if not isinstance(prompt, str) or not prompt.lstrip().startswith("<task-notification>"):
        return []
    out = []
    for block in _BLOCK.findall(prompt):
        agent, summary = _TASK_ID.search(block), _SUMMARY.search(block)
        if agent is None or summary is None or not _CUT.search(summary.group(1)):
            continue
        tokens = _TOKENS.search(block)
        out += budget_cut_records(ctx, agent.group(1),
                                  int(tokens.group(1)) if tokens else None)
    return out
