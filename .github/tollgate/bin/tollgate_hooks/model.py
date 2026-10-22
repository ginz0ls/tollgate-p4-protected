"""Eventi d'ingresso e decisioni (spec 3.2, revisione 21)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

INPUT_EVENTS = ("session_start", "prompt_expansion", "pre_edit", "post_edit", "pre_bash",
                "post_bash", "pre_agent", "post_agent", "pre_send_message", "pre_mcp",
                "subagent_start", "subagent_stop", "subagent_handback", "post_skill",
                "prompt_submit")
CONTROL_EVENTS = frozenset({"pre_edit", "pre_bash", "pre_agent", "pre_send_message", "pre_mcp"})


@dataclass(frozen=True)
class Event:
    kind: str
    hook_event: str
    session: str
    cwd: Path
    agent_id: str | None
    agent_type: str | None
    tool_name: str | None
    tool_input: dict
    tool_response: dict | None
    raw: dict


@dataclass(frozen=True)
class Decision:
    kind: str                      # allow | deny | inject | record
    text: str = ""
    rule: str = ""
    op: str = ""
    data: dict = field(default_factory=dict)


def allow() -> Decision:
    return Decision("allow")


def deny(reason: str, rule: str = "") -> Decision:
    return Decision("deny", text=reason, rule=rule)


def inject(text: str) -> Decision:
    return Decision("inject", text=text)


def record(op: str, **data) -> Decision:
    return Decision("record", op=op, data=data)
