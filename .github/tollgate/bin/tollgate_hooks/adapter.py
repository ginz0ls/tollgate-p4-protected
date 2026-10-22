"""Adattatore per Claude Code (spec 3.2): input degli hook → Event; esito → risposta."""
from __future__ import annotations

import json
from pathlib import Path

from .model import Event

EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
_PRE = {"Bash": "pre_bash", "Agent": "pre_agent", "SendMessage": "pre_send_message"}
_POST = {"Bash": "post_bash", "Agent": "post_agent", "Skill": "post_skill",
         "SubagentHandback": "subagent_handback"}
_PLAIN = {"SessionStart": "session_start", "UserPromptExpansion": "prompt_expansion",
          "UserPromptSubmit": "prompt_submit", "SubagentStart": "subagent_start",
          "SubagentStop": "subagent_stop"}
# Come arriva un'iniezione al modello, per evento (decisione 3; esito di D2 nel Task 1).
# "context": hookSpecificOutput.additionalContext; "system": systemMessage; "stderr": solo stderr;
# "log": nessuna iniezione (il runner scrive il testo nel log degli hook).
INJECT_MODE = {"SessionStart": "context", "UserPromptExpansion": "context",
               "UserPromptSubmit": "context", "PreToolUse": "context",
               "PostToolUse": "context", "PostToolUseFailure": "context",
               "SubagentStart": "context", "SubagentStop": "log"}
# Eventi d'ingresso la cui iniezione non arriva al modello (SubagentHandback è un PostToolUse).
NO_INJECT_KINDS = frozenset({"subagent_stop", "subagent_handback"})


def _kind(hook_event: str, tool: str | None) -> str | None:
    if hook_event in _PLAIN:
        return _PLAIN[hook_event]
    if hook_event == "PreToolUse":
        if tool in EDIT_TOOLS:
            return "pre_edit"
        if tool and tool.startswith("mcp__"):
            return "pre_mcp"
        return _PRE.get(tool)
    if hook_event == "PostToolUse":
        if tool in EDIT_TOOLS:
            return "post_edit"
        return _POST.get(tool)
    if hook_event == "PostToolUseFailure":
        # Il comando o la modifica sono partiti anche se sono finiti male: stessi effetti di
        # PostToolUse (consumo dell'atto, commit visti, livello), solo per Bash e per le modifiche.
        if tool in EDIT_TOOLS:
            return "post_edit"
        return "post_bash" if tool == "Bash" else None
    return None


def to_event(hook_event: str, raw: dict) -> Event | None:
    if not isinstance(raw, dict):
        raise ValueError("input dell'hook non è un oggetto JSON")
    tool = raw.get("tool_name") if isinstance(raw.get("tool_name"), str) else None
    kind = _kind(hook_event, tool)
    if kind is None:
        return None
    ti = raw.get("tool_input")
    tr = raw.get("tool_response")
    return Event(kind=kind, hook_event=hook_event, session=str(raw.get("session_id") or ""),
                 cwd=Path(str(raw.get("cwd") or ".")), agent_id=raw.get("agent_id") or None,
                 agent_type=raw.get("agent_type") if raw.get("agent_type") is not None else None,
                 tool_name=tool, tool_input=ti if isinstance(ti, dict) else {},
                 tool_response=tr if isinstance(tr, dict) else None, raw=raw)


def edit_path(event: Event) -> str | None:
    p = event.tool_input.get("file_path") or event.tool_input.get("notebook_path")
    return p if isinstance(p, str) and p else None


def render(hook_event: str, deny_text: str | None, inject_text: str | None):
    """Solo l'uscita 2 blocca (7.1). Mai permissionDecision allow (decisione 3)."""
    if deny_text:
        return 2, "", f"tollgate: {deny_text}\n"
    if inject_text:
        mode = INJECT_MODE.get(hook_event, "context")
        if mode == "context":
            out = {"hookSpecificOutput": {"hookEventName": hook_event,
                                          "additionalContext": inject_text}}
            return 0, json.dumps(out, ensure_ascii=False), ""
        if mode == "system":
            return 0, json.dumps({"systemMessage": inject_text}, ensure_ascii=False), ""
        if mode == "stderr":
            return 0, "", inject_text + "\n"
    return 0, "", ""
