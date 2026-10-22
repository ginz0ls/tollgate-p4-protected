"""PostToolUse Bash (spec 7.2): commit nuovi, ramo cambiato; il controllo a valle di 7.4.

Il consumo degli atti degli effetti esterni è in `effects` (evento `post_bash`)."""
from __future__ import annotations

import json
from pathlib import Path

from tollgate_core import git, subagents
from tollgate_hooks.model import deny, record

from ._common import commit_violations, explain, governing_work, level_records

CHECK = {"api": 1, "events": ["post_bash"], "component": None, "order": 20}


def _block(work, reason: str) -> list:
    """Un blocco needs_you; se il lavoro è già in blocco non se ne apre un altro."""
    if work["phase"] == "blocked":
        return []
    return [record("block", work=work["id"], type="needs_you", reason=reason[:1000])]


def decide(event, ctx):
    work = governing_work(ctx, event.cwd)
    if work is None or not work["worktree"] or not Path(work["worktree"]).is_dir():
        return []
    wt = Path(work["worktree"]).resolve()
    out = []
    br = git.branch(wt)
    if work["branch"] and br != work["branch"]:
        out += _block(work, f"il ramo del worktree è {br or '(staccato)'}, atteso "
                            f"{work['branch']}: rimettilo o decidi come procedere")
    head, base = git.head(wt), work["work_base_sha"]
    if not head or not base:
        return out
    known = {json.loads(r[0]).get("sha") for r in ctx.db.execute(
        "SELECT data FROM events WHERE type = 'commit' AND work = ?", (work["id"],))}
    try:
        new = [s for s in git.rev_list(wt, base, head) if s not in known]
    except git.GitError:
        return out
    if not new:
        # HEAD si è mosso senza commit nuovi (reset, checkout): un finish su un altro SHA
        # non vale più (vincolo 3)
        if ctx.db.execute("SELECT 1 FROM acts WHERE state = 'pending' AND type = 'finish' "
                          "AND work = ? AND head_sha <> ?", (work["id"], head)).fetchone():
            out.append(record("invalidate_finish", work=work["id"], head=head))
        return out
    task = None
    if event.agent_id:
        row = subagents.get(ctx.db, event.agent_id)
        task = row["task"] if row is not None else None
    problems = []
    for sha in new:
        out.append(record("commit", work=work["id"], sha=sha, head=head))
        if task is not None:
            out.append(record("task_commit", work=work["id"], number=task, sha=sha))
        parent = git.range_base(wt, sha)
        left = commit_violations(ctx, work, wt, parent, sha, git.commit_changes(wt, sha))
        if left:
            problems.append(f"commit {sha[:10]}:\n" + explain(left, ctx))
    out = level_records(ctx, work) + out
    if problems:
        text = "\n".join(problems)
        out += _block(work, "commit con violazioni senza deroga: " + text)
        out.append(deny("commit registrati con violazioni senza deroga; aperto un blocco "
                        "needs_you:\n" + text, rule="post_bash"))
    return out
