"""SubagentStop (spec 8.6, 7.3, decisioni 10 e 11): verdetto del revisore del task.

Possiede l'intera chiusura del revisore in attesa: sola lettura, verdetto e riga del subagente.
`subagent_stop` lo salta (`_common.awaiting_review`), perché i `record` si applicano anche dopo
un veto e la riga si chiuderebbe `done` con un verdetto non valido."""
from __future__ import annotations

import json
from pathlib import Path

from tollgate_analysis import profiles as prof, report, verdicts
from tollgate_core import git, subagents
from tollgate_hooks.model import deny, record

from . import _common

CHECK = {"api": 1, "events": ["subagent_stop"], "component": None, "order": 15}
MAX_VETOES = 2


def _task_files(work, task) -> list[str]:
    """File del diff del task (come `review-prepare`: dal genitore del primo commit alla
    revisione); vuoto se non si possono leggere, e allora ogni `R-…` blocca (fail-closed)."""
    wt = Path(work["worktree"]) if work["worktree"] else None
    commits = json.loads(task["commits"])
    if wt is None or not wt.is_dir() or not commits:
        return []
    try:
        base = git.range_base(wt, commits[0])
        changes = git.changes(wt, base, head=task["review_sha"])
    except git.GitError:
        return []
    return [p for c in changes for p in (c.path, c.old_path) if p]


def decide(event, ctx):
    if not event.agent_type or not event.agent_id:
        return []
    row = subagents.get(ctx.db, event.agent_id)
    if row is None or row["started"] is None or row["state"] != "running":
        return []
    found = _common.awaiting_review(ctx, row)
    if found is None:
        return []
    work, task = found
    if ctx.component("readonly_check") and work["worktree"] \
            and _common.fingerprint_changed(ctx, row, Path(work["worktree"])):
        return _common.tampered_records(row, work)
    aid = row["id"]
    tokens = report.transcript_tokens(event.raw.get("agent_transcript_path") or "")
    msg = event.raw.get("last_assistant_message") or row["report"]
    profs = ctx.config.profiles
    active = prof.active_profiles(_task_files(work, task), profs, ctx.cfg("profiles.active"))
    v = verdicts.parse_task_verdict(msg, task=task["number"], sha=task["review_sha"],
                                    code=task["review_code"],
                                    standard=ctx.component("reviewer_standard"),
                                    blocking_rules=prof.blocking_rules(active, profs),
                                    known_rules=prof.known_rules(active, profs))
    if v.valid:
        return [record("task_verdict", work=work["id"], number=task["number"],
                       outcome=v.outcome, findings=v.findings, dropped=v.dropped),
                record("subagent_finish", agent_id=aid, state="done", declared_status=v.outcome,
                       tokens=tokens)]
    why = "; ".join(v.problems)
    if row["vetoes"] >= MAX_VETOES:
        return [record("subagent_finish", agent_id=aid, state="done", tokens=tokens),
                record("block", work=work["id"], type="needs_you",
                       reason=f"verdetto del revisore non valido sul task {task['number']} "
                              f"dopo {MAX_VETOES} veti: {why}"[:500])]
    return [record("subagent_veto", agent_id=aid),
            deny(f"verdetto non valido: {why}. Chiudi con un solo blocco JSON di 18.5, con sha e "
                 f"code del brief di revisione (veto {row['vetoes'] + 1} di {MAX_VETOES})",
                 rule="task_verdict")]
