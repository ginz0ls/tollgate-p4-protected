"""`tollgate task start <k> [--fix]` (spec 6.3): brief dell'implementatore e assegnazione.

Il coordinatore lancia l'implementatore con il nome e il tipo che questo comando ha scritto in
`tasks`; `SubagentStart` associa poi il subagente al task (`tasks.take_pending`)."""
from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path

from tollgate_analysis import (brief as briefs, naming, plan as planmod, profiles as prof,
                               report, size)
from tollgate_core import (clock, config, db, events, git, phases, reviews, scope as scopes,
                           sessions, tasks)
from tollgate_core.paths import program_command

from . import prereq

MAX_FIX_ROUNDS = tasks.BASE_FIX_ROUNDS
MODEL_HINT = "inherit"


class TaskError(Exception):
    pass


def _plan_text(wt: Path, work) -> str:
    """Decisione 20: il piano a `plan_sha`. Il blob può non essere negli oggetti di git (lo SHA
    viene da `hash-object` senza scrivere): allora vale il file del worktree, ma solo se ha
    lo stesso SHA."""
    sha, rel = work["plan_sha"], work["plan_path"]
    if not sha or not rel:
        raise TaskError("piano non registrato: manca il piano del lavoro")
    text = git.blob_text(wt, sha)
    if text is None:
        try:
            same = git.blob_sha(wt, rel) == sha
        except git.GitError:
            same = False
        text = git.worktree_text(wt, rel) if same else None
    if text is None:
        raise TaskError(f"piano diverso dalla versione registrata ({rel}): il piano è bloccato "
                        "dopo la registrazione")
    return text


def _check_state(row, number: int, fix: bool) -> None:
    if not fix:
        if row["state"] != "pending":
            raise TaskError(f"task {number} è {row['state']}, non pending: `task start` parte "
                            "solo da pending (per una correzione usa --fix)")
        return
    if row["state"] != "review":
        raise TaskError(f"task {number} è {row['state']}, non in review: --fix serve dopo un "
                        "verdetto del revisore")
    if row["verdict"] != "changes":
        hint = f"; il task è approvato: lancia `task done {number}`" \
            if row["verdict"] == "approved" else ""
        raise TaskError(f"task {number}: serve un verdetto «changes» del revisore "
                        f"(verdetto attuale: {row['verdict'] or 'nessuno'}){hint}")
    if row["review_sha"] is None:
        raise TaskError(f"task {number}: il verdetto è di una revisione già superata, serve "
                        "un nuovo verdetto del revisore")


def _fix_files(conn, work, row) -> list[str]:
    """File dei rilievi di un task di correzione `cycle:<n>` (per l'instradamento); quelli di un
    task `gate:<sha>` non si conoscono. Sono i rilievi confermati e bloccanti del ciclo di gravità
    dichiarata blocker o major (quelli da cui nasce il task), qualunque sia la decisione
    successiva dell'utente (`approve finding`): l'instradamento resta quello dell'origine
    (decisione 25)."""
    kind, _, ref = (row["source"] or "").partition(":")
    if kind != "cycle" or not ref.isdigit():
        return []
    rows = conn.execute("SELECT file FROM findings WHERE work = ? AND cycle = ? "
                        "AND verification = 'confirmed' AND blocking = 1 "
                        f"AND severity IN ({','.join('?' * len(reviews.BLOCKING_SEVERITIES))}) "
                        "ORDER BY rowid",
                        (work["id"], int(ref), *reviews.BLOCKING_SEVERITIES)).fetchall()
    return list(dict.fromkeys(r["file"] for r in rows if r["file"]))


def _related_tests(task, must_haves: list[planmod.MustHave]) -> list[str]:
    out = list(task.test_files)
    out += [t for m in must_haves for t in m.tests if t != "manuale"]
    return list(dict.fromkeys(out))


def task_start(state, cwd: Path, number: int, *, fix: bool, claude_dir: Path,
               now=None) -> tuple[Path, str]:
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        raise TaskError(str(e)) from e
    try:
        return _task_start(state, conn, Path(cwd), number, fix=fix, claude_dir=Path(claude_dir),
                           now=now)
    except (sqlite3.Error, tasks.TaskTransitionError, phases.TransitionError,
            git.GitError) as e:
        raise TaskError(str(e)) from e
    finally:
        conn.close()


def _task_start(state, conn, cwd: Path, number: int, *, fix: bool, claude_dir: Path,
                now) -> tuple[Path, str]:
    work = sessions.work_for_path(conn, cwd)
    if work is None:
        raise TaskError("nessun lavoro attivo per questa cartella: lancia il comando dal "
                        "worktree del lavoro")
    if work["level"] == "L0":
        raise TaskError("in L0 lavora la sessione principale: non ci sono task da assegnare")
    if work["phase"] != "execution":
        raise TaskError(f"la fase è {work['phase']}: `task start` si usa in execution")
    try:
        row = tasks.get_task(conn, work["id"], number)
    except ValueError as e:
        raise TaskError(f"task {number} inesistente nel lavoro #{work['issue']}") from e
    _check_state(row, number, fix)
    if fix and row["fix_rounds"] >= MAX_FIX_ROUNDS + row["extra_fix_rounds"]:
        reason = f"giri di correzione esauriti sul task {number}"
        phases.open_block(conn, state, work["id"], "needs_you", reason, now=now)
        raise TaskError(f"{reason}: serve una decisione dell'utente (aperto un blocco needs_you)")

    wt = Path(work["worktree"])
    main = git.main_worktree(wt)
    base = work["work_base_sha"] or git.default_ref(main)
    try:
        cfg = config.load_config(state, main, base)
    except config.ConfigError as e:
        raise TaskError(f"configurazione non valida: {e}") from e
    if row["kind"] == "fix":
        # decisione 16: il testo sta in `tasks.task_text`; il piano non c'entra
        text = row["task_text"]
        if not text:
            raise TaskError(f"task {number}: manca il testo del task di correzione")
        files, scope_files = _fix_files(conn, work, row), sorted(scopes.paths(conn, work["id"]))
        must_haves, related = [], []
    else:
        plan_text = _plan_text(wt, work)
        check = planmod.check_plan(
            plan_text, required_sections=cfg.get("plan.required_sections"),
            max_scope_files=cfg.get("plan.max_scope_files"),
            must_have_tests=bool(cfg.data["components"].get("must_have_tests", True)),
            level=work["level"], profiles=cfg.profiles, active_always=cfg.get("profiles.active"))
        text = planmod.task_text(plan_text, number)
        task = next((t for t in check.tasks if t.number == number), None)
        if text is None or task is None:
            raise TaskError(f"task {number} non è nel piano {work['plan_path']}")
        refs = task.must_haves
        must_haves = [m for m in check.must_haves if refs is None or m.id in refs]
        files, scope_files, related = task.files, task.files, _related_tests(task, must_haves)

    routing = prof.task_routing(files, cfg.profiles)
    absent = [s for s in routing.skills
              if not prereq.skill_installed(s, claude_dir=claude_dir, worktree=wt)]
    present = [s for s in routing.skills if s not in absent]

    round_ = row["fix_rounds"] + 1 if fix else 0
    renamed = fix and round_ >= naming.RENAMED_FROM_ROUND
    if fix and not renamed:
        name, pending = row["implementer"] or naming.implementer_name(work["issue"], number), \
            "resume"
    else:
        name, pending = naming.implementer_name(work["issue"], number, round_), "launch"
    # decisione 21: il modello di `[review] models`; dal giro 4 il nuovo implementatore è inherit
    hint = MODEL_HINT if renamed else cfg.get("review.models").get(routing.implementer)

    impl_brief = briefs.ImplBrief(
        issue=work["issue"], task=number, name=name, agent_type=routing.implementer,
        model_hint=hint, task_text=text, scope=scope_files,
        related_tests=related, must_haves=must_haves, skills=present,
        absent_skills=absent, verify_cmd=f"{program_command(db.BIN_PATH)} verify",
        fix_findings=json.loads(row["review_findings"]) if fix else [], fix_round=round_)
    file_name = f"task-{number}-fix-{round_}.md" if fix else f"task-{number}.md"
    path = wt / ".tollgate-run" / str(work["issue"]) / file_name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(briefs.implementer_brief(impl_brief), encoding="utf-8")
    except OSError as e:
        raise TaskError(f"scrittura del brief {path} non riuscita: {e}") from e

    # Un'unica transazione: se `assign` fallisce il task resta com'era (pending, o review).
    with db.tx(conn):
        tasks.set_skills_required(conn, work["id"], number, present)
        if absent:
            events.record_event(conn, "skills_absent", {"task": number, "skills": absent},
                                now=now, work=work["id"])
        tasks.task_event(conn, work["id"], number, "fix" if fix else "start", now=now)
        tasks.assign(conn, work["id"], number, implementer=name, agent_type=routing.implementer,
                     pending=pending, reviewer_type=routing.reviewer, now=now)
    summary = (f"task {number}: {routing.implementer} name={name}"
               + (f" model: {hint}" if hint else "") + f" {pending}"
               + f" revisore: {routing.reviewer}")
    return path, summary


def _open(state):
    try:
        return db.open_db(state)
    except db.DbError as e:
        raise TaskError(str(e)) from e


def _work_and_task(conn, cwd: Path, number: int):
    work = sessions.work_for_path(conn, cwd)
    if work is None:
        raise TaskError("nessun lavoro attivo per questa cartella: lancia il comando dal "
                        "worktree del lavoro")
    if work["phase"] != "execution":
        raise TaskError(f"la fase è {work['phase']}: la revisione dei task si fa in execution")
    try:
        return work, tasks.get_task(conn, work["id"], number)
    except ValueError as e:
        raise TaskError(f"task {number} inesistente nel lavoro #{work['issue']}") from e


def _range(wt: Path, row) -> tuple[str, str]:
    """Dal genitore del primo commit del task alla punta del ramo: un commit fuori da
    `tasks.commits` (del coordinatore) entra nella revisione. Senza commit (C11): diff vuoto."""
    head = git.head(wt)
    if head is None:
        raise TaskError("il worktree non ha commit")
    commits = json.loads(row["commits"])
    if not commits:
        return head, head
    return git.range_base(wt, commits[0]), head


def _ensure_clean(state, work, wt: Path, hint: str) -> None:
    """Le modifiche non committate non sono coperte da nessuna revisione. Restano fuori le
    cartelle di output e `.tollgate-run/`."""
    main = git.main_worktree(wt)
    try:
        cfg = config.load_config(state, main, work["work_base_sha"] or git.default_ref(main))
    except config.ConfigError as e:
        raise TaskError(f"configurazione non valida: {e}") from e
    if not git.is_clean(wt, config.output_excludes(cfg)):
        raise TaskError(hint)


def _concerns(conn, work, row) -> str:
    """Dubbi dell'ultimo implementatore del task, solo se il report dice DONE_WITH_CONCERNS."""
    last = conn.execute("SELECT report FROM subagents WHERE work = ? AND task = ? AND type = ? "
                        "ORDER BY coalesce(started, last_seen) DESC LIMIT 1",
                        (work["id"], row["number"], row["agent_type"])).fetchone()
    rep = report.parse_report(last["report"] if last else None)
    concerns = rep.data.get("concerns")
    if rep.status != "DONE_WITH_CONCERNS" or not isinstance(concerns, str):
        return ""
    return concerns.strip()


def _diff_text(wt: Path, base: str, head: str) -> str:
    flags = ("--no-color", "--no-ext-diff", "--no-textconv")
    if base == head:
        log = ""
    elif base == git.EMPTY_TREE:
        log = git.run(wt, "log", "--oneline", head)
    else:
        log = git.run(wt, "log", "--oneline", f"{base}..{head}")
    return (f"## git log --oneline\n{log}\n## git diff --stat\n"
            f"{git.run(wt, 'diff', *flags, '--stat', base, head)}\n"
            f"## git diff -U10\n{git.run(wt, 'diff', *flags, '-U10', base, head)}")


def review_prepare(state, cwd: Path, number: int, *, now=None) -> Path:
    """Spec 6.3, 8.6: diff e brief del revisore, con lo SHA e un codice casuale che il verdetto
    deve riportare. Un verdetto precedente non vale più (`set_review_prep`)."""
    conn = _open(state)
    try:
        return _review_prepare(state, conn, Path(cwd), number)
    except (sqlite3.Error, git.GitError) as e:
        raise TaskError(str(e)) from e
    finally:
        conn.close()


def reviewer_type(state, cwd: Path, number: int) -> str:
    """Tipo di revisore scelto da `task start` (decisione 15): serve a lanciare quello giusto."""
    conn = _open(state)
    try:
        _, row = _work_and_task(conn, Path(cwd), number)
        return row["reviewer_type"] or prof.DEFAULT_REVIEWER
    except sqlite3.Error as e:
        raise TaskError(str(e)) from e
    finally:
        conn.close()


def _review_prepare(state, conn, cwd: Path, number: int) -> Path:
    work, row = _work_and_task(conn, cwd, number)
    if row["state"] != "review":
        raise TaskError(f"task {number} è {row['state']}, non in review: la revisione si "
                        "prepara dopo il report DONE dell'implementatore")
    wt = Path(work["worktree"])
    main = git.main_worktree(wt)
    try:
        cfg = config.load_config(state, main, work["work_base_sha"] or git.default_ref(main))
    except config.ConfigError as e:
        raise TaskError(f"configurazione non valida: {e}") from e
    _ensure_clean(state, work, wt, "modifiche non committate nel worktree: committa o scarta le "
                                   "modifiche prima della revisione")
    base, head = _range(wt, row)
    changes = git.changes(wt, base, head=head)
    if row["kind"] == "fix":
        files = _fix_files(conn, work, row)
    else:
        plan_text = _plan_text(wt, work)
        check = planmod.check_plan(
            plan_text, required_sections=cfg.get("plan.required_sections"),
            max_scope_files=cfg.get("plan.max_scope_files"),
            must_have_tests=bool(cfg.data["components"].get("must_have_tests", True)),
            level=work["level"], profiles=cfg.profiles, active_always=cfg.get("profiles.active"))
        task = next((t for t in check.tasks if t.number == number), None)
        files = task.files if task else []
    routing = prof.task_routing(files, cfg.profiles)

    run_dir = wt / ".tollgate-run" / str(work["issue"])
    k = len(list(run_dir.glob("review-*.diff"))) + 1 if run_dir.is_dir() else 1
    brief_name = f"task-{number}-fix-{row['fix_rounds']}.md" if row["fix_rounds"] \
        else f"task-{number}.md"
    code = secrets.token_hex(4)
    diff_path, brief_path = run_dir / f"review-{k}.diff", run_dir / f"review-{k}.md"
    text = briefs.review_brief(briefs.ReviewBrief(
        issue=work["issue"], task=number, sha=head, code=code, base=base, head=head,
        brief_path=str(run_dir / brief_name), diff_path=str(diff_path),
        lines=size.task_lines(changes, set(cfg.get("scope.lockfiles"))),
        lines_warn=cfg.get("tasks.task_lines_warn"), lines_max=cfg.get("tasks.task_lines_max"),
        concerns=_concerns(conn, work, row), reviewer_skills=routing.reviewer_skills,
        standard=bool(cfg.data["components"].get("reviewer_standard", True)),
        no_changes=not json.loads(row["commits"])))
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        diff_path.write_text(_diff_text(wt, base, head), encoding="utf-8", errors="replace")
        brief_path.write_text(text, encoding="utf-8")
    except OSError as e:
        raise TaskError(f"scrittura del brief di revisione non riuscita: {e}") from e
    tasks.set_review_prep(conn, work["id"], number, sha=head, code=code)
    return brief_path


def task_done(state, cwd: Path, number: int, *, now=None) -> str:
    """Chiude il task: serve un verdetto `approved` sull'ultimo commit del task (criterio 4)."""
    now = now or clock.now()
    conn = _open(state)
    try:
        work, row = _work_and_task(conn, Path(cwd), number)
        if row["state"] != "review" or row["verdict"] != "approved":
            hint = f"; il verdetto è «changes»: lancia `task start {number} --fix`" \
                if row["state"] == "review" and row["verdict"] == "changes" else ""
            raise TaskError(f"task {number}: serve un verdetto «approved» del revisore "
                            f"(stato {row['state']}, verdetto {row['verdict'] or 'nessuno'})"
                            f"{hint}")
        wt = Path(work["worktree"])
        _ensure_clean(state, work, wt, f"task {number}: modifiche non committate nel worktree, "
                                       "il verdetto non le copre: serve una nuova revisione")
        if row["review_sha"] is None or row["review_sha"] != git.head(wt):
            raise TaskError(f"task {number}: serve una nuova revisione, il verdetto non copre "
                            "la punta del ramo")
        tasks.task_event(conn, work["id"], number, "approved", now=now)
        return f"task {number}: done"
    except (sqlite3.Error, tasks.TaskTransitionError, git.GitError) as e:
        raise TaskError(str(e)) from e
    finally:
        conn.close()
