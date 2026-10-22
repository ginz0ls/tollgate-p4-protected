"""Aiuti condivisi dai controlli (non è un controllo: il registro salta i nomi con _)."""
from __future__ import annotations

import json
import os
from pathlib import Path

from tollgate_analysis import level as lv, prref, profiles as prof
from tollgate_analysis.protected import is_protected
from tollgate_core import audits, config, git, reviews, subagents, violations
from tollgate_core.paths import program_command, repo_key
from tollgate_hooks.adapter import edit_path
from tollgate_hooks.model import inject, record


def _inside(p, root) -> bool:
    """`p` è `root` o sta sotto `root` (percorsi già assoluti e risolti)."""
    p, root = Path(p), Path(root)
    return p == root or root in p.parents


def edit_lexical(event) -> Path | None:
    """Il percorso di Edit o Write come scritto, normalizzato ma senza risolvere i collegamenti."""
    raw = edit_path(event)
    if not raw:
        return None
    return Path(os.path.normpath(os.path.join(event.cwd, raw)))


def edit_target(event) -> Path | None:
    """Percorso assoluto e risolto (collegamenti compresi) che Edit o Write toccherebbe.
    Si decide sul percorso vero: un collegamento nel worktree non aggira scope né protezioni;
    i file protetti si valutano anche sul percorso non risolto (`is_protected_path`)."""
    p = edit_lexical(event)
    return p.resolve() if p is not None else None


def path_forms(p) -> list[Path]:
    """Le forme in cui un percorso può raggiungere un file: quella lessicale, quella risolta e
    le intermedie (i primi i componenti risolti, il resto come scritto). Una protezione per
    nome (`.claude/settings.json`) vale su una qualunque di esse: collegamenti a file, a
    cartelle o a monte della radice del repo non la aggirano."""
    lex = Path(os.path.normpath(p))
    parts = lex.parts
    forms = [lex]
    for i in range(1, len(parts) + 1):
        f = Path(*parts[:i]).resolve().joinpath(*parts[i:])
        if f not in forms:
            forms.append(f)
    return forms


def _repo_roots_along(forms) -> list[Path]:
    """Cartelle con un `.git` lungo il percorso (senza lanciare git): radici candidate."""
    out = []
    for f in forms:
        for a in f.parents:
            if (a / ".git").exists() and a not in out:
                out.append(a)
    return out


def output_excludes(ctx) -> list[str]:
    """Cartelle di output (report, copertura, `.tollgate-run/`): fuori da livello e scope."""
    return config.output_excludes(ctx.config)


def fingerprint_changed(ctx, row, wt: Path) -> bool:
    """Stesse esclusioni di subagent_start, che ha preso l'impronta di partenza."""
    return bool(row["fingerprint"]) and \
        git.fingerprint(wt, ctx.cfg("review.output_dirs")) != row["fingerprint"]


def tampered_records(row, work) -> list:
    """7.3: il subagente di sola lettura ha cambiato file, il suo verdetto non vale."""
    return [record("subagent_finish", agent_id=row["id"], state="tampered"),
            record("block", work=work["id"], type="needs_you",
                   reason=f"il subagente di sola lettura {row['type']} ha cambiato "
                          f"file: il suo verdetto non vale (7.3)")]


def awaiting_review(ctx, row):
    """`(lavoro, task)` se il subagente è il revisore di un task in `review` con una revisione
    preparata per il codice corrente (`review-prepare` ha scritto sha e codice); altrimenti None.
    Dopo un `--fix` sha e codice sono vuoti: un revisore che chiude non è «in attesa»."""
    if row["work"] is not None:
        work = ctx.db.execute("SELECT * FROM work_items WHERE id = ?", (row["work"],)).fetchone()
    else:
        work = governing_work(ctx, ctx.event.cwd)
    if work is None:
        return None
    task = ctx.db.execute(
        "SELECT * FROM tasks WHERE work = ? AND state = 'review' AND reviewer_type = ? "
        "AND review_code IS NOT NULL AND review_sha IS NOT NULL "
        "AND (? IS NULL OR number = ?) ORDER BY number LIMIT 1",
        (work["id"], row["type"], row["task"], row["task"])).fetchone()
    return None if task is None else (work, task)


def awaiting_final(ctx, row):
    """`(lavoro, ciclo, ruolo)` se il subagente è un revisore finale che deve ancora riportare
    nell'ultimo ciclo in stadio `review` (`reviewer`), o il verificatore di un ciclo in stadio
    `verify` (`verifier`); altrimenti None. Accetta righe `running` e `interrupted`: un revisore
    fermo per sola lettura può essere segnato interrotto prima di riportare (decisione 7)."""
    if row["state"] not in ("running", "interrupted"):
        return None
    if row["work"] is not None:
        work = ctx.db.execute("SELECT * FROM work_items WHERE id = ?", (row["work"],)).fetchone()
    else:
        work = governing_work(ctx, ctx.event.cwd)
    if work is None:
        return None
    cycle = ctx.db.execute("SELECT * FROM review_cycles WHERE work = ? ORDER BY number DESC "
                           "LIMIT 1", (work["id"],)).fetchone()
    if cycle is None:
        return None
    if cycle["stage"] == "review" and row["type"] in json.loads(cycle["reviewers"]) \
            and row["type"] not in json.loads(cycle["reported"]):
        return work, cycle, "reviewer"
    if cycle["stage"] == "verify" and row["type"] == reviews.VERIFIER:
        return work, cycle, "verifier"
    return None


def awaiting_audit(ctx, row):
    """Il giro di audit aperto del lavoro del subagente, se è l'agente di quel giro: tipo
    giusto (`audits.AGENTS`), riga `running` o `interrupted` e `started` non nullo e non
    precedente a `opened` (decisione 4: l'agente di un giro superato non appartiene al nuovo).
    Altrimenti None."""
    if row["state"] not in ("running", "interrupted") or row["started"] is None:
        return None
    if row["work"] is not None:
        work = ctx.db.execute("SELECT * FROM work_items WHERE id = ?", (row["work"],)).fetchone()
    else:
        work = governing_work(ctx, ctx.event.cwd)
    if work is None:
        return None
    rnd = ctx.db.execute("SELECT * FROM spec_audit WHERE work = ? AND stage = 'open' "
                         "ORDER BY id LIMIT 1", (work["id"],)).fetchone()
    if rnd is None or rnd["opened"] is None or row["type"] != audits.AGENTS[rnd["kind"]] \
            or row["started"] < rnd["opened"]:
        return None
    return rnd


def repo_key_of(repo) -> str | None:
    url = git.origin_url(repo) if repo else None
    return repo_key(url) if url else None


def orphan_tg(ctx, repo) -> int | None:
    """Ramo tg/<N>-* senza lavoro attivo per (repo, N): DB perso, serve adopt (12.4)."""
    if repo is None:
        return None
    issue = prref.issue_from_branch(git.branch(repo) or "")
    if issue is None:
        return None
    key = repo_key_of(repo)
    if key is None:
        return None
    row = ctx.db.execute("SELECT 1 FROM work_items WHERE repo_key = ? AND issue = ? "
                         "AND phase <> 'closed'", (key, issue)).fetchone()
    return None if row else issue


def closed_tg(ctx, repo) -> int | None:
    """Ramo tg/<N>-* che è il `branch` di un lavoro `closed` del repo e di nessun lavoro attivo:
    non serve `adopt`, i resti si tolgono con `/tollgate:cleanup` (12.4)."""
    if repo is None:
        return None
    branch = git.branch(repo) or ""
    issue = prref.issue_from_branch(branch)
    key = repo_key_of(repo)
    if issue is None or key is None:
        return None
    phases_ = [r[0] for r in ctx.db.execute(
        "SELECT phase FROM work_items WHERE repo_key = ? AND branch = ?", (key, branch))]
    if phases_ and all(p == "closed" for p in phases_):
        return issue
    return None


def orphan_next(ctx, repo, n: int) -> tuple[str, str]:
    """`(motivo, comando)` per un ramo tg/<N>-* senza lavoro attivo: `cleanup` se è il ramo di un
    lavoro chiuso, altrimenti `adopt` (DB perso)."""
    if closed_tg(ctx, repo) == n:
        return "di un lavoro chiuso", "/tollgate:cleanup"
    return "senza lavoro nel DB", f"/tollgate:adopt #{n}"


def governing_work(ctx, path):
    """Le regole complete valgono nella sessione legata e per ogni percorso nel worktree (6.6)."""
    if ctx.bound and ctx.work is not None:
        return ctx.work
    return ctx.work_for_path(path) if path is not None else None


def in_main_checkout(p: Path, wt: Path) -> bool:
    """`p` sta nel checkout principale, ma non in un altro worktree dentro di esso.
    Solleva GitError se i worktree non si possono elencare."""
    trees = [t for t, _ in git.worktrees(wt)]
    return _inside(p, trees[0]) and not any(_inside(p, t) for t in trees[1:])


def is_protected_path(ctx, p: Path, repo, work) -> bool:
    """Protetto se lo dice una qualunque radice pertinente: il repo più vicino (può essere
    annidato), il worktree del lavoro e il repo del contesto. Così un `git init` in una
    cartella protetta non sposta la radice e non aggira la regola. `p` si valuta in tutte le
    sue forme (`path_forms`): va passato il percorso lessicale, non solo quello risolto."""
    forms = path_forms(p)
    roots = []
    for r in (repo, Path(work["worktree"]) if work is not None and work["worktree"] else None,
              ctx.repo, *_repo_roots_along(forms)):
        r = Path(r).resolve() if r is not None else None
        if r is not None and r not in roots:
            roots.append(r)
    if not roots:
        roots = [None]
    for f in forms:
        for r in roots:
            rel = f.relative_to(r).as_posix() if r is not None and _inside(f, r) else None
            if is_protected(rel, f, abs_roots=ctx.protected_roots(r)):
                return True
    return False


is_docs_md = violations.is_docs_md
locked_docs = violations.locked_docs


def waiver_hint(v, ctx) -> str:
    target = f"--test {' --test '.join(v.ids)} " if v.ids else ""
    return (f"{program_command(ctx.plugin_bin)} waiver add {v.waiver_type} {v.path} {target}"
            f"--choice … --why … --cost …")


def explain(violations, ctx) -> str:
    lines = [f"- {v.path}: {v.detail} (deroga: {waiver_hint(v, ctx)})" for v in violations]
    return "\n".join(lines)


def status_lines(ctx, work) -> list[str]:
    lines = [f"tollgate: lavoro #{work['issue']} ({work['level']}), fase {work['phase']}"
             + (f" (prima: {work['phase_before_block']})" if work["phase"] == "blocked" else "")]
    for b in ctx.db.execute("SELECT id, type, reason FROM blocks WHERE work = ? AND closed "
                            "IS NULL ORDER BY id LIMIT 3", (work["id"],)):
        lines.append(f"blocco {b['id']} ({b['type']}): {b['reason'][:120]}")
    counts = {r[0]: r[1] for r in ctx.db.execute(
        "SELECT state, count(*) FROM tasks WHERE work = ? GROUP BY state", (work["id"],))}
    if counts:
        lines.append("task: " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())))
    return lines


def scope_exempt(ctx, work, rel: str, scope: set[str]) -> bool:
    return violations.scope_exempt(ctx.config, work, rel, scope)


def level_records(ctx, work) -> list:
    """Ricalcolo del livello sul diff dalla base, working tree e file nuovi compresi
    (decisione 18), senza le cartelle di output. Il livello sale e non scende mai."""
    wt = Path(work["worktree"]) if work["worktree"] else None
    base = work["work_base_sha"]
    if not base or wt is None or not wt.is_dir():
        return []
    skip = output_excludes(ctx)
    changes = git.changes(wt, base, exclude=skip)
    cfg = ctx.cfg("levels")
    paths = [c.path for c in changes] + [c.old_path for c in changes if c.old_path]
    computed = lv.diff_level(changes, diff_bytes=git.diff_size(wt, base, exclude=skip),
                             sensitive_paths=cfg["sensitive_paths"],
                             l0_max_files=cfg["l0_max_files"], l0_max_lines=cfg["l0_max_lines"],
                             l0_max_bytes=cfg["l0_max_bytes"])
    profs = ctx.config.profiles
    computed = lv.max_level(computed, prof.min_level(
        prof.active_profiles(paths, profs, ctx.cfg("profiles.active")), profs))
    new = lv.next_level(current=work["level"], computed=computed, cap=work["level_cap"],
                        cap_paths=json.loads(work["level_cap_paths"] or "[]"),
                        sensitive_now=lv.sensitive_in(paths, cfg["sensitive_paths"]))
    if new == work["level"]:
        return []
    if work["level"] == "L0" and work["phase"] == "execution":
        out = [record("phase", work=work["id"], to="plan", cause="l0_grew")]
        if new == "L2":
            out.append(record("level", work=work["id"], level="L2"))
        out.append(inject(f"tollgate: il diff supera le soglie di L0: il lavoro sale a {new} e "
                          f"torna in fase plan. Serve un piano (writing-plans)."))
        return out
    return [record("level", work=work["id"], level=new),
            inject(f"tollgate: il lavoro sale a {new} (percorsi sensibili o soglie).")]


_is_registered_plan = violations.is_registered_plan


def commit_violations(ctx, work, wt: Path, base_ref: str, head_ref: str | None,
                      changes) -> list:
    """Violazioni di test-guard e scope su `changes`: la regola è in `core.violations`."""
    return violations.diff_violations(ctx.config, ctx.db, work, wt, base_ref, head_ref, changes,
                                      components=ctx.config.data["components"])


def budget_cut_records(ctx, agent_id: str, tokens=None) -> list:
    """Taglio di maxTurns (6.3). La riga si chiude sempre come `cut` (altrimenti resterebbe un
    falso scrittore vivo); task in budget superato e blocco `needs_you` solo con `task_budget`.
    Vale per il primo piano (PostToolUse Agent) e per background e riprese (UserPromptSubmit)."""
    row = subagents.get(ctx.db, agent_id)
    if row is None or row["state"] != "running":
        return []
    count = tokens if isinstance(tokens, int) and not isinstance(tokens, bool) else None
    out = [record("subagent_finish", agent_id=agent_id, state="cut", tokens=count)]
    if not ctx.component("task_budget"):
        return out
    work, number = row["work"], row["task"]
    if work is not None and number is not None:
        t = ctx.db.execute("SELECT state FROM tasks WHERE work = ? AND number = ?",
                           (work, number)).fetchone()
        if t is not None and t["state"] == "running":
            out += [record("task", work=work, number=number, event="budget_exceeded"),
                    record("block", work=work, type="needs_you",
                           reason=f"budget superato: maxTurns esaurito sul task {number}. "
                                  f"Proposta: dividere il task")]
    out.append(inject("tollgate: il subagente ha esaurito maxTurns. Il task è bloccato con "
                      "needs_you: non riprenderlo con SendMessage."))
    return out
