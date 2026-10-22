"""git commit in un lavoro attivo (spec 7.4): test-guard, scope e livello su working tree e indice."""
from __future__ import annotations

from pathlib import Path

from tollgate_analysis import bash
from tollgate_core import git
from tollgate_hooks.model import deny

from ._common import (_inside, commit_violations, explain, governing_work, level_records,
                      output_excludes)

CHECK = {"api": 1, "events": ["pre_bash"], "component": None, "order": 25}


def decide(event, ctx):
    try:
        cmds = bash.parse(str(event.tool_input.get("command") or ""), str(event.cwd))
    except bash.BashParseError:
        return []
    for c in cmds:
        if not bash.is_commit(c):
            continue
        edir = Path(bash.effective_dir(c)).resolve()
        work = governing_work(ctx, edir)
        if work is None or not work["worktree"]:
            continue
        wt = Path(work["worktree"]).resolve()
        if not _inside(edir, wt):
            continue
        head = git.head(wt)
        if head is None:
            continue
        out = level_records(ctx, work)
        if any(d.kind == "record" and d.op == "phase" for d in out):
            return out + [deny("il diff ha superato le soglie di L0: il lavoro torna in fase "
                               "plan e serve un piano prima del commit", rule="level")]
        changes = git.changes(wt, head, exclude=output_excludes(ctx))
        left = commit_violations(ctx, work, wt, head, None, changes)
        if left:
            return out + [deny("commit negato, violazioni senza deroga:\n"
                               + explain(left, ctx), rule="commit")]
        return out
    return []
