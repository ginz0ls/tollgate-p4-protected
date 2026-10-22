"""PostToolUse Edit/Write (spec 7.2): livello e plan-check (7.5)."""
from __future__ import annotations

from pathlib import Path

from tollgate_analysis import plan as planmod, profiles as prof
from tollgate_core import git
from tollgate_hooks.model import deny, inject, record

from ._common import edit_target, governing_work, level_records

CHECK = {"api": 1, "events": ["post_edit"], "component": None, "order": 20}


def _plan(ctx, work, wt: Path, rel: str):
    if not (rel.startswith("docs/superpowers/plans/") and rel.endswith(".md")):
        return []
    if work["phase"] != "plan" or not ctx.component("plan_check") or work["plan_sha"]:
        return []
    if work["plan_path"] not in (None, rel) or git.exists_at(wt, work["work_base_sha"], rel):
        return []
    try:
        text = (wt / rel).read_text(encoding="utf-8")
    except OSError:
        return []
    r = planmod.check_plan(text, required_sections=ctx.cfg("plan.required_sections"),
                           max_scope_files=ctx.cfg("plan.max_scope_files"),
                           must_have_tests=ctx.component("must_have_tests"),
                           level=work["level"], profiles=ctx.config.profiles,
                           active_always=ctx.cfg("profiles.active"))
    if not r.ok:
        return [deny("piano incompleto, non registrato:\n- " + "\n- ".join(r.problems),
                     rule="plan_check")]
    out = [inject("tollgate: " + w) for w in r.warnings]
    if work["level"] == "L1":
        plan_tasks = [(t.number, prof.task_skills(t.files, ctx.config.profiles)[:3])
                      for t in r.tasks]
        out += [record("plan", work=work["id"], plan_path=rel, plan_sha=git.blob_sha(wt, rel),
                       scope=r.scope, tasks=plan_tasks, advance=True),
                inject(f"tollgate: piano registrato, scope di {len(r.scope)} file; fase "
                       f"execution. Prossimo passo: /tollgate:execute.")]
    else:
        out += [record("plan_path", work=work["id"], plan_path=rel),
                inject("tollgate: piano valido. Prossimo passo in L2: /tollgate:spec-audit "
                       "(lancia l'avversario del piano), poi /tollgate:approve plan.")]
    return out


def decide(event, ctx):
    p = edit_target(event)
    if p is None:
        return []
    work = governing_work(ctx, p)
    if work is None or not work["worktree"]:
        return []
    wt = Path(work["worktree"]).resolve()
    rel = ctx.rel(p, wt)
    if rel is None:
        return []
    plan = _plan(ctx, work, wt, rel)  # prima: un errore del livello non deve fermare il piano
    try:
        level = level_records(ctx, work)
    except Exception as e:  # noqa: BLE001 - il ricalcolo è informativo, il piano no
        level = [inject(f"tollgate: ricalcolo del livello non riuscito ({e}); riprova alla "
                        f"prossima modifica.")]
    return level + plan
