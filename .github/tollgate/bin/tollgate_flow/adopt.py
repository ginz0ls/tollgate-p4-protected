"""`tollgate adopt N` (spec 12.4, decisione 18 di P3b): ricostruisce un lavoro dal ramo `tg/<N>-*`.

Serve dopo un DB perso o da un'altra macchina. Il ramo è quello locale oppure quello di `origin`
(in quel caso si crea il ramo locale); un worktree che già lo ospita si riusa, mai con `--force`.
Livello, fase, piano, scope, task e tetto si deducono dalle prove nel ramo e nella PR; vale la
regola «senza prova la fase torna a quella che precede l'atto mancante». Gli intenti, le deroghe
approvate e i cicli di revisione non si ricostruiscono: i task si rivedono una volta, le deroghe
tornano `pending`. Il testo dell'issue finisce solo in `.tollgate-run/<N>/issue.md`."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from tollgate_analysis import (approvals, level as lv, plan as planmod, prblock, profiles as prof,
                               waivers)
from tollgate_core import (acts, active, clock, config, db, git, phases, scope, sessions)
from tollgate_core.paths import State, repo_key

from . import gh, gitw, l2tree, start as flow_start

OK, REFUSED, INCOMPLETE = 0, 1, 4
FAILED = object()
PLANS_DIR = "docs/superpowers/plans/"
CAP_REASON_MAX = 500
ERRORS = (sqlite3.Error, phases.TransitionError, config.ConfigError, gh.GhError, git.GitError,
          gitw.GitWriteError, OSError, db.DbError)


@dataclass
class AdoptResult:
    code: int
    lines: list[str]
    worktree: Path | None = None
    work: int | None = None


@dataclass
class _Evidence:
    """Ciò che il ramo e la PR dimostrano."""
    level: str
    phase: str
    plan: tuple[str, planmod.PlanCheck] | None
    spec_header: dict | None
    plan_header: dict | None
    pr: dict | None
    cap: tuple[str, str] | None
    notes: list[str] = field(default_factory=list)


def _refuse(*reasons: str, warnings=()) -> AdoptResult:
    return AdoptResult(REFUSED, [*[f"avviso: {w}" for w in warnings],
                                 *[f"rifiuto: {r}" for r in reasons]])


def adopt(state: State, cwd: Path, issue: int, *, now=None,
          argv: list[str] | None = None) -> AdoptResult:
    now = now or clock.now()
    top = git.toplevel(cwd)
    if top is None:
        return _refuse("la cartella corrente non è in un repo git")
    main = git.main_worktree(top)
    url = git.origin_url(main)
    if not url:
        return _refuse("il repo non ha il remote origin")
    gitw.fetch(main)        # senza rete si riparte dai riferimenti locali; il ramo remoto no
    ref = git.default_ref(main)
    if not ref:
        return _refuse("origin non ha un ramo predefinito con almeno un commit")
    if not git.exists_at(main, ref, "tollgate.toml"):
        return _refuse(f"repo non attivo: manca tollgate.toml su {ref} (lancia /tollgate:init)")
    try:
        cfg = config.load_config(state, main, ref)
    except config.ConfigError as e:
        return _refuse(f"configurazione non valida: {e}")
    try:
        session = sessions.cli_session(state, cwd, "adopt", now=now, argv=argv)
    except sessions.CliSessionError as e:
        return _refuse(str(e))
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        return _refuse(str(e))
    try:
        return _adopt(state, conn, main, ref, cfg, repo_key(url), issue, session, now)
    except ERRORS as e:
        return _refuse(str(e))
    finally:
        conn.close()


def _candidates(main: Path, issue: int) -> list[tuple[str, str]]:
    """(ramo, dove) per i rami `tg/<N>-*`, locali e su origin."""
    prefix = f"tg/{issue}-"
    local = {b for b in git.local_branches(main) if b.startswith(prefix)}
    remote = set(gitw.remote_branches(main, prefix + "*"))
    return [(b, "locale" if b in local else "solo su origin") for b in sorted(local | remote)]


def _cap_from_block(body: str, issue: int, warnings: list[str]) -> tuple[str, str] | None:
    block = prblock.parse(body)
    if block is None or block.get("level_cap") is None:
        return None
    cap, reason = block.get("level_cap"), block.get("level_cap_reason")
    if cap not in phases.LEVELS or block.get("issue") != issue:
        warnings.append("blocco tollgate della PR con tetto di livello non valido o di un'altra "
                        "issue: ignorato (serve un nuovo approve level)")
        return None
    text = reason if isinstance(reason, str) and reason.strip() else "ripristinato dalla PR"
    return cap, text[:CAP_REASON_MAX]


def _read_pr(state, main: Path, branch: str, issue: int, warnings: list[str]):
    """La PR del ramo: `(pr, tetto)`. Unita: `None` come PR e rifiuto a chi chiama (`merged`).
    Chiusa senza merge: ignorata con un avviso (C25). Un errore di `gh` è un `GhError`: senza
    sapere se la PR è stata unita non si adotta."""
    pr = gh.pr_for_branch(state, main, branch)
    if pr is None:
        return None, None, False
    if pr.get("state") == "MERGED" or pr.get("mergedAt"):
        return pr, None, True
    if pr.get("state") == "CLOSED":
        warnings.append(f"PR #{pr.get('number')} chiusa senza merge: ignorata, finish open-pr "
                        "ne aprirà una nuova")
        return None, None, False
    return pr, _cap_from_block(gh.pr_body(state, main, pr["number"]), issue, warnings), False


def find_plan(main: Path, cfg, sha: str, changes, level: str):
    """Il primo file nuovo sotto `docs/superpowers/plans/` che passa plan-check."""
    for path in sorted(c.path for c in changes if c.status == "A" and c.path.startswith(PLANS_DIR)
                       and c.path.endswith(".md")):
        text = git.text_at(main, sha, path)
        if text is None:
            continue
        check = planmod.check_plan(
            text, required_sections=cfg.get("plan.required_sections"),
            max_scope_files=cfg.get("plan.max_scope_files"),
            must_have_tests=bool(cfg.data["components"].get("must_have_tests", True)),
            level=level, profiles=cfg.profiles, active_always=cfg.get("profiles.active"))
        if check.ok:
            return path, check
    return None


def _blob(main: Path, sha: str, path: str) -> str | None:
    try:
        return git.run(main, "rev-parse", f"{sha}:{path}").strip()
    except git.GitError:
        return None


def _approval(main: Path, sha: str, path: str, kind: str, *, doc: str | None = None) -> dict | None:
    """L'intestazione di un file di approvazione, solo se è ancora valida: `path` esiste nel ramo
    (e, con `doc`, è proprio quel documento) e il suo blob è `sha`. Altrimenti non è una prova."""
    header = approvals.parse_approval(git.text_at(main, sha, path) or "")
    if header is None or header.get("kind") != kind:
        return None
    target = _safe_rel(header.get("path"))
    if target is None or (doc is not None and target != doc):
        return None
    return header if approvals.is_current(header, _blob(main, sha, target)) else None


def _safe_rel(value) -> str | None:
    """Un percorso relativo al repo senza `..`: il `path` di un'approvazione è un dato del ramo."""
    if not isinstance(value, str) or not value:
        return None
    p = PurePosixPath(value)
    return value if not p.is_absolute() and ".." not in p.parts else None


def _level(state, main: Path, cfg, issue: int, base: str, sha: str, changes, warnings) -> str:
    """Diff dalla base, profili attivi, etichette e autore dell'issue (come `openpr.facts` e
    `start`)."""
    levels_cfg = cfg.get("levels")
    paths = [c.path for c in changes] + [c.old_path for c in changes if c.old_path]
    computed = lv.diff_level(
        changes, diff_bytes=git.diff_size(main, base, head=sha,
                                          exclude=config.output_excludes(cfg)),
        sensitive_paths=levels_cfg["sensitive_paths"], l0_max_files=levels_cfg["l0_max_files"],
        l0_max_lines=levels_cfg["l0_max_lines"], l0_max_bytes=levels_cfg["l0_max_bytes"])
    profs = cfg.profiles
    computed = lv.max_level(computed, prof.min_level(
        prof.active_profiles(paths, profs, cfg.get("profiles.active")), profs))
    iss = gh.issue(state, main, issue)      # illeggibile: GhError, adopt rifiuta come per la PR
    computed = lv.max_level(computed, lv.labels_level(iss.labels, levels_cfg["sensitive_labels"]))
    if iss.author_association not in flow_start.TRUSTED_AUTHORS:
        warnings.append("autore dell'issue esterno al repo: il lavoro va in L2")
        computed = lv.max_level(computed, "L2")
    return computed


def _phase(level: str, pr: dict | None, plan, spec_header, plan_header, plan_adversary: bool
           ) -> str:
    """La fase dalle prove (12.4): quella che precede l'atto mancante. In L2 con la spec approvata,
    il piano e senza `plan-approval.md` serve `plan` se l'avversario del piano è acceso (i suoi
    giri sono persi con il DB e `approve plan` li richiede), `approval` se è spento."""
    if pr is not None:
        return "pr_open"
    if level == "L0":
        return "execution"
    if level == "L1":
        return "execution" if plan else "plan"
    if not spec_header:
        return "spec_audit"
    if not plan:
        return "plan"
    if plan_header:
        return "execution"
    return "plan" if plan_adversary else "approval"


def _approved_elsewhere(main: Path, sha: str, spec_sha: str) -> dict | None:
    """Fetta successiva (decisione 16): l'approvazione di una spec, in qualunque cartella
    `reviews/<M>/`, con `sha == spec_sha` e la spec ancora con quel blob nell'albero. Vince il
    numero di issue più basso (la prima fetta)."""
    for path, _ in sorted(l2tree.spec_approvals(main, sha).items(),
                          key=lambda kv: int(kv[0].split("/")[-2])):
        header = _approval(main, sha, path, "spec-approval")
        if header is not None and header["sha"] == spec_sha:
            return header
    return None


def _l2_proofs(main: Path, sha: str, issue: int, plan) -> tuple[dict | None, dict | None]:
    """Le approvazioni di L2 valide nell'albero di `sha` (la punta del ramo): `(spec, piano)`.
    Senza `spec-approval.md` proprio, un `plan-approval.md` corrente il cui `spec_sha` è lo `sha`
    di un'approvazione trovata per una spec ancora con quel blob prova la spec approvata."""
    spec_rel, plan_rel = approvals.approval_paths(issue)
    spec_header = _approval(main, sha, spec_rel, "spec-approval")
    plan_header = None
    if plan is not None:
        plan_header = _approval(main, sha, plan_rel, "plan-approval", doc=plan[0])
        if spec_header is None and plan_header is not None and plan_header.get("spec_sha"):
            spec_header = _approved_elsewhere(main, sha, plan_header["spec_sha"])
    if spec_header is None:
        return None, None
    spec_sha = plan_header.get("spec_sha") if plan_header else None
    if spec_sha is not None and spec_sha != spec_header["sha"]:
        plan_header = None
    return spec_header, plan_header


def _gather(state, main: Path, cfg, issue: int, branch: str, sha: str, base: str,
            warnings: list[str]) -> _Evidence | AdoptResult:
    pr, cap, merged = _read_pr(state, main, branch, issue, warnings)
    if merged:
        return _refuse(f"la PR #{pr.get('number')} del ramo {branch} è stata unita: il lavoro è "
                       "concluso (i resti si tolgono con /tollgate:cleanup)", warnings=warnings)
    changes = git.changes(main, base, head=sha, exclude=config.output_excludes(cfg))
    level = _level(state, main, cfg, issue, base, sha, changes, warnings)
    plan = find_plan(main, cfg, sha, changes, level) if level != "L0" else None
    spec_header = plan_header = None
    if level == "L2":
        spec_header, plan_header = _l2_proofs(main, sha, issue, plan)
    adversary = bool(cfg.get("components").get("plan_adversary", True))
    phase = _phase(level, pr, plan, spec_header, plan_header, adversary)
    if level == "L2" and pr is not None and cap is None and not (spec_header and plan_header):
        warnings.append("L2 con la PR aperta ma senza spec-approval.md o plan-approval.md nel "
                        "ramo: la fase viene dalla PR")
    return _Evidence(level, phase, plan, spec_header, plan_header, pr, cap)


def _worktree(main: Path, branch: str, sha: str, local: bool, lines: list[str]):
    """Il worktree del ramo: quello che già lo ospita, oppure uno nuovo. Dà `(percorso, creato,
    ramo_creato)` o un rifiuto. Mai `--force`."""
    trees = git.worktrees(main)
    holder = next((p for p, b in trees if b == branch), None)
    if holder is not None:
        if holder == trees[0][0]:
            return _refuse(f"il ramo {branch} è nel checkout principale {holder}: tollgate non lo "
                           "usa. Spostalo (`git switch` su un altro ramo) e rilancia")
        if not holder.is_dir():
            return _refuse(f"il worktree {holder} del ramo {branch} è registrato ma manca: "
                           "ripulisci con `git worktree prune` e rilancia")
        lines.append(f"worktree esistente riusato: {holder}")
        return holder, False, False
    wt = gitw.worktree_dir(main, branch)
    if wt.exists():
        return _refuse(f"{wt} esiste già e non è il worktree del ramo {branch}: rimuovilo o "
                       "spostalo")
    wt.parent.mkdir(parents=True, exist_ok=True)
    created = False
    if not local:
        # Il ramo si crea con un'operazione atomica: se esiste già è di un'altra sessione.
        created = gitw.create_branch(main, branch, sha)
        if not created and branch not in git.local_branches(main):
            return _refuse(f"creazione del ramo locale {branch} non riuscita")
    try:
        gitw.worktree_add(main, wt, branch=branch, start_point=None, new_branch=False)
    except gitw.GitWriteError as e:
        left = ""
        if created and not gitw.delete_branch(main, branch, sha):
            left = f"; il ramo {branch} è stato lasciato: toglilo a mano se è residuo"
        return _refuse(f"creazione del worktree {wt} (ramo {branch}) non riuscita: {e}{left}")
    lines.append(f"worktree creato: {wt}" + (f" (ramo {branch} preso da origin)" if created
                                              else ""))
    return wt, True, created


def _adopt(state, conn, main: Path, ref: str, cfg, key: str, issue: int, session: str,
           now) -> AdoptResult:
    act = acts.find_usable(conn, type_="adopt", target=str(issue), work=None, session=session,
                           now=now)
    if act is None:
        return _refuse(f"serve un atto dell'utente: /tollgate:adopt #{issue}")
    if phases.find_active(conn, key, issue) is not None:
        return _refuse(f"c'è già un lavoro attivo per #{issue}: si riprende con "
                       f"/tollgate:start #{issue}")
    found = _candidates(main, issue)
    if not found:
        return _refuse(f"nessun ramo tg/{issue}-* in locale né su origin: niente da adottare "
                       f"(un lavoro nuovo parte con /tollgate:start #{issue})")
    if len(found) > 1:
        return _refuse(f"più rami per #{issue}, tieni quello giusto e rilancia:",
                       *[f"{b} ({where})" for b, where in found])
    branch, where = found[0]
    local = where == "locale"
    sha = git.resolve_ref(main, f"refs/heads/{branch}" if local
                          else f"refs/remotes/origin/{branch}")
    if sha is None:
        return _refuse(f"il ramo {branch} è su origin ma non è stato scaricato "
                       "(git fetch origin non è riuscito?)")
    base = gitw.merge_base(main, ref, sha)
    if base is None:
        return _refuse(f"nessuna base comune tra {branch} e {ref}")

    warnings = list(cfg.warnings)
    remote_tip = git.resolve_ref(main, f"refs/remotes/origin/{branch}") if local else None
    if remote_tip is not None and remote_tip != sha:
        warnings.append(f"ramo locale e remoto diversi: uso la punta locale {sha[:12]}")
    found_ev = _gather(state, main, cfg, issue, branch, sha, base, warnings)
    if isinstance(found_ev, AdoptResult):
        return found_ev
    ev = found_ev
    lines: list[str] = []
    placed = _worktree(main, branch, sha, local, lines)
    if isinstance(placed, AdoptResult):
        return AdoptResult(REFUSED, [*[f"avviso: {w}" for w in warnings], *placed.lines])
    wt = placed[0]

    spec_path = _safe_rel(ev.spec_header.get("path")) if ev.spec_header else None
    try:
        work = phases.create_work(
            conn, repo_key=key, issue=issue, level=ev.level, now=now, session=session,
            branch=branch, worktree=str(wt), work_base_sha=base, gate_mode=cfg.get("gate.mode"),
            spec_path=spec_path, phase=ev.phase, cause="adopt")
    except (phases.WorkExists, sqlite3.Error, db.DbError) as e:
        return _refuse(f"{e} (ramo {branch} e worktree {wt} restano: adottali di nuovo con "
                       "/tollgate:adopt dopo aver risolto)", warnings=warnings)
    unconsumed = None
    try:
        acts.consume(conn, act["act_id"], type_="adopt", target=str(issue), work=None,
                     session=session, now=now)
    except acts.ActError as e:
        warnings.append(str(e))
    except sqlite3.Error as e:      # il lavoro esiste già: non è un rifiuto, come per `start`
        unconsumed = f"lavoro creato, atto non consumato: {e}"

    failed: list[str] = []

    def step(what, fn):
        try:
            return fn()
        except (ValueError, gitw.GitWriteError, OSError, sqlite3.Error, db.DbError,
                phases.TransitionError, git.GitError) as e:
            failed.append(f"{what}: {e}")
            return FAILED

    if ev.pr is not None:
        if step("PR", lambda: phases.set_pr(conn, work, ev.pr["number"], ev.pr.get("url"),
                                            now=now)) is not FAILED:
            lines.append(f"PR #{ev.pr['number']} aperta: fase pr_open")
    if ev.cap is not None:
        if step("tetto di livello", lambda: _apply_cap(conn, main, cfg, work, wt, base, ev, now,
                                                       session)) is not FAILED:
            lines.append(f"tetto {ev.cap[0]} ripristinato dalla PR")
    if ev.plan is not None:
        step("piano", lambda: _register_plan(conn, state, main, cfg, work, sha, ev, now, session,
                                             lines))
    step("deroghe", lambda: _waiver_line(main, sha, issue, lines))
    step("copia di sicurezza del database", lambda: db.backup(conn, state, "adopt"))
    step("radici attive", lambda: active.register(state, main, extra=[wt], force=True))
    step("segnalino della sessione", lambda: sessions.mark_bound(state, session))
    step("info/exclude", lambda: gitw.add_excludes(main, flow_start.EXCLUDES))
    step("testo dell'issue", lambda: _write_issue(state, main, wt, issue, warnings))

    row = phases.get_work(conn, work)
    out = [*[f"avviso: {w}" for w in warnings],
           *([f"avviso: {unconsumed}"] if unconsumed else []),
           *[f"avviso: registrazione incompleta: {x}" for x in failed],
           f"lavoro #{issue} adottato: livello {row['level']}, fase {row['phase']}, ramo {branch}",
           *lines,
           "gli intenti e i cicli di revisione non si ricostruiscono; i task del piano risultano "
           "pending e si rivedono una volta",
           f"prossimo passo: EnterWorktree {wt}"]
    return AdoptResult(INCOMPLETE if failed or unconsumed else OK, out, wt, work)


def _apply_cap(conn, main: Path, cfg, work: int, wt: Path, base: str, ev: _Evidence, now,
               session) -> None:
    """I percorsi sensibili del diff valgono come in `approve level`: il tetto decade quando ne
    compare uno nuovo."""
    changes = git.changes(wt, base, exclude=config.output_excludes(cfg))
    paths = [c.path for c in changes] + [c.old_path for c in changes if c.old_path]
    cap_paths = lv.sensitive_in(paths, cfg.get("levels.sensitive_paths"))
    phases.set_level_cap(conn, work, ev.cap[0], ev.cap[1], cap_paths, now=now, session=session)


def _register_plan(conn, state, main: Path, cfg, work: int, sha: str, ev: _Evidence, now,
                   session, lines: list[str]) -> None:
    """Scope e task `pending` dal piano. In L2 senza `plan-approval.md` il piano si registra solo
    come percorso (come fa l'hook): scope e task arrivano con `approve plan`."""
    path, check = ev.plan
    level = phases.get_work(conn, work)["level"]       # dopo l'eventuale tetto
    registered = level == "L1" or (level == "L2" and ev.plan_header is not None)
    if not registered:
        scope.set_plan_path(conn, work, path, now=now)
        lines.append(f"piano {path}: solo il percorso (manca plan-approval.md)")
        return
    plan_sha = git.run(main, "rev-parse", f"{sha}:{path}").strip()
    skills = [(t.number, prof.task_skills(t.files, cfg.profiles)[:3]) for t in check.tasks]
    scope.register_plan(conn, state, work, plan_path=path, plan_sha=plan_sha,
                        scope_paths=check.scope, plan_tasks=skills, advance=False, now=now,
                        session=session)
    lines.append(f"piano {path}: scope di {len(set(check.scope))} file, {len(check.tasks)} task "
                 "pending")


def _waiver_line(main: Path, sha: str, issue: int, lines: list[str]) -> None:
    text = git.text_at(main, sha, waivers.path_for(issue))
    if text is None:
        return
    try:
        found = waivers.parse(text).waivers
    except ValueError as e:
        lines.append(f"file delle deroghe non valido ({e}): nessuna deroga considerata")
        return
    lines.append(f"{len(found)} deroghe nel file del ramo, nessuna approvata: tornano in attesa "
                 "di /tollgate:approve waiver")


def _write_issue(state, main: Path, wt: Path, issue: int, warnings: list[str]) -> None:
    try:
        iss = gh.issue(state, main, issue)
    except gh.GhError as e:
        warnings.append(f"issue.md non scritto (issue non leggibile: {e})")
        return
    flow_start._write_issue(wt, iss, issue)
