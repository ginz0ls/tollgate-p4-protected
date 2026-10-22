"""`tollgate finish open-pr` (spec 6.4, decisioni 10 e 11 di P3b).

Le condizioni si raccolgono e si stampano tutte insieme (`rifiuto: …`, codice 1). Poi, nell'ordine
della decisione 10: intento `pr:<lavoro>:<sha>`, push dello SHA, `ls-remote`, PR esistente?
`pr edit` : `pr create`, numero e URL, evento, fase `pr_open`, intento eseguito e, per ultimo,
l'atto consumato: un'interruzione lascia l'atto valido e la ripetizione aggiorna la stessa PR."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from tollgate_analysis import (approvals as approvals_mod, level as lv, prblock, prbody,
                               profiles as prof, size, waivers)
from tollgate_core import (VERSION, acts, clock, config, db, dod, events, git, intents, phases,
                           receipts, reviews, sessions, stats, verify, violations)
from tollgate_core.paths import program_command

from . import finishcheck, gh, gitw, l2tree, prstate

OK, REFUSED = 0, 1
REVIEWER = "tollgate:final-reviewer"
SIDE_EFFECT_ERRORS = (sqlite3.Error, phases.TransitionError, config.ConfigError, gh.GhError,
                      git.GitError, gitw.GitWriteError, OSError, db.DbError)


_AUTO = object()


@dataclass
class OpenResult:
    code: int
    lines: list[str]
    url: str | None = None


@dataclass
class Review:
    """Il ciclo di revisione che vale per HEAD (o per lo stesso `patch-id`)."""
    required: bool
    ok: bool
    cycle: sqlite3.Row | None
    findings_cycle: int
    specialists: list[str] = field(default_factory=list)


def _refuse(*reasons: str, warnings=()) -> OpenResult:
    return OpenResult(REFUSED, [*warnings, *[f"rifiuto: {r}" for r in reasons]])


def open_pr(state, cwd, *, update: bool = False, now=None, argv: list[str] | None = None,
            via_sync: str | None = None, environ=None) -> OpenResult:
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        return _refuse(str(e))
    try:
        return _open(state, conn, Path(cwd), update, now, argv, via_sync, environ)
    except SIDE_EFFECT_ERRORS as e:
        return _refuse(str(e))
    finally:
        conn.close()


def _title(issue: int, branch: str) -> str:
    """`#<N> <slug del ramo con spazi>`: mai il titolo dell'issue, che è un dato non fidato."""
    slug = branch.removeprefix(f"tg/{issue}-")
    return f"#{issue} {slug.replace('-', ' ')}"


def review_state(conn, work, cfg, wt, base, head, comps) -> Review:
    required = work["level"] != "L0" and comps.get("final_review", True)
    if not required:
        return Review(False, True, None, 0)
    last = reviews.latest(conn, work["id"])
    same = False
    if last is not None:
        patch = git.patch_id(wt, base, head)
        same = last["sha"] == head or (patch is not None and last["patch_id"] == patch)
    on_head = same and last["stage"] == "closed"
    ok = bool(work["review_unverified"]) or (on_head and last["outcome"] == "ok")
    # anche con la revisione non verificata la DoD guarda l'ultimo ciclo chiuso su HEAD (8.7)
    specialists = ([r for r in json.loads(last["reviewers"]) if r != REVIEWER]
                   if on_head else [])
    return Review(True, ok, last if same else None, last["number"] if on_head else 0, specialists)


def _dod_line(item: dod.DodItem, details: dict[str, str]) -> str:
    mark = "n/d" if item.ok is None else ("sì" if item.ok else "no")
    detail = item.detail or details.get(item.key, "")
    return f"[{mark}] {item.label}" + (f": {detail}" if detail else "")


def _open_intent(conn, key: str) -> bool:
    row = conn.execute("SELECT state FROM intents WHERE idempotency_key = ?", (key,)).fetchone()
    return row is not None and row["state"] == "requested"


def _open(state, conn, cwd: Path, update: bool, now, argv, via_sync, environ) -> OpenResult:
    work = sessions.work_for_path(conn, cwd)
    if work is None:
        return _refuse("nessun lavoro attivo per questa cartella: lancia il comando dal "
                       "worktree del lavoro")
    wid, wt = work["id"], Path(work["worktree"])
    main = git.main_worktree(wt)
    prog = program_command(db.BIN_PATH)
    session = session_error = None
    try:
        session = sessions.cli_session(state, cwd, "finish", now=now, argv=argv)
    except sessions.CliSessionError as e:
        session_error = str(e)

    seen = prstate.detect(state, conn, work, main, now=now, session=session)
    warnings = [f"avviso: {seen.error}"] if seen.error else []
    if seen.kind == "merged":
        return _refuse(f"la PR #{seen.pr.get('number')} è stata unita: il lavoro è chiuso",
                       warnings=warnings)
    if seen.kind == "closed":
        return _refuse(prstate.closed_line(seen.pr), warnings=warnings)

    head, branch = git.head(wt), work["branch"]
    problems: list[str] = []
    key = f"pr:{wid}:{head}"
    resume = False
    if head is None:
        return _refuse("nessun commit da spingere", warnings=warnings)
    if work["phase"] == "review":
        pass
    elif work["phase"] == "pr_open" and head == work["finish_sha"] and _open_intent(conn, key):
        resume = True                                   # interrotto dopo il cambio di fase
    else:
        problems.append(f"la fase è {work['phase']}: `finish open-pr` si usa in review (la PR "
                        "aperta si aggiorna con un nuovo `finish`, o con /tollgate:sync)")
    if head != work["finish_sha"]:
        problems.append("HEAD non è lo SHA dell'ultimo `finish check` verde: rilancia "
                        f"{prog} finish check")

    used: list[dict] = []          # gli atti che autorizzano questa PR, da consumare per ultimi
    if via_sync is None:
        finish_act = acts.find_usable(conn, type_="finish", work=wid, session=None, now=now,
                                      head_sha=head)
        pr_act = acts.find_usable(conn, type_="approve", object_="pr", target=head, work=wid,
                                  session=session, now=now) if session else None
        if finish_act is not None:
            used.append(dict(act_id=finish_act["act_id"], type_="finish", object_=None,
                             target=None, work=wid, session=None, head_sha=head))
        if pr_act is not None:
            used.append(dict(act_id=pr_act["act_id"], type_="approve", object_="pr",
                             target=head, work=wid, session=session, head_sha=None))
        if not used:
            problems.append("serve un atto dell'utente su questo SHA: /tollgate:finish "
                            "(o /tollgate:approve pr)"
                            + (f" [{session_error}]" if session_error else ""))

    base = work["work_base_sha"] or git.default_ref(wt)
    if base is None:
        return _refuse("nessun riferimento remoto da cui leggere tollgate.toml",
                       warnings=warnings)
    cfg = config.load_config(state, wt, base, env=environ)
    comps = cfg.get("components")
    if not gitw.fetch(wt):
        warnings.append("avviso: git fetch origin non riuscito (senza rete?): si prosegue con i "
                        "riferimenti locali")

    review = review_state(conn, work, cfg, wt, base, head, comps)
    if review.required and not review.ok:
        problems.append("nessun ciclo di revisione `ok` su questo SHA: lancia "
                        f"{prog} review prepare")
    for b in conn.execute("SELECT id, type, reason FROM blocks WHERE work = ? AND closed IS NULL "
                          "ORDER BY id", (wid,)):
        problems.append(f"blocco {b['id']} aperto ({b['type']}): {b['reason']}")
    problems += _waiting(conn, work, cfg)
    for r in conn.execute("SELECT id FROM findings WHERE work = ? AND verification IS NULL "
                          "ORDER BY rowid", (wid,)):
        problems.append(f"rilievo {r['id']} senza esito: lancia {prog} review prepare")

    items, details = _compute_dod(conn, work, cfg, wt, base, head, review, problems)
    dod_lines = [_dod_line(i, details) for i in items]
    failed = [i for i in items if i.ok is not True]
    if failed:
        if comps.get("definition_of_done", True):
            problems += [f"Definition of Done: {_dod_line(i, details)}" for i in failed]
        else:
            warnings.append("avviso: componente definition_of_done spento: le voci [no] qui "
                            "sopra non fermano la PR")

    remote = None
    try:
        remote = gitw.remote_sha(wt, branch)
    except gitw.GitWriteError as e:
        problems.append(f"ramo remoto non leggibile: {e}")
    diverged = (remote is not None and remote != head and not gitw.is_ancestor(wt, remote, head))
    if diverged and not intents.force_authorized(conn, wid):
        problems.append(f"il ramo remoto {branch} ({remote[:7]}) non è antenato di HEAD: il push "
                        "forzato serve un'autorizzazione (/tollgate:sync oppure "
                        "/tollgate:approve rebase)")

    existing = None
    try:
        existing = gh.pr_for_branch(state, main, branch)
    except gh.GhError as e:
        problems.append(str(e))
    open_pr_ = existing if existing and existing.get("state") == "OPEN" else None
    if existing and (existing.get("state") == "MERGED" or existing.get("mergedAt")):
        problems.append(f"la PR #{existing['number']} del ramo risulta già unita")
    if update and open_pr_ is None:
        problems.append("--update richiede una PR aperta per il ramo " + branch)
    if problems:
        return _refuse(*problems, warnings=warnings)

    labels, label_warning = issue_labels(state, main, work)
    if label_warning:
        warnings.append(label_warning)
    if review.required and work["review_unverified"]:
        warnings.append("avviso: revisione non verificata (approvata dall'utente senza esito)")
    first_time = work["pr_number"] is None
    data = facts(conn, state, work, cfg, wt, head, now=now, dod=items, labels=labels,
                 cycle=review.cycle if review.required else None)
    block = prblock.build(data)
    body = prbody.render(issue=work["issue"], level=work["level"], dod_lines=dod_lines,
                         notes=_notes(conn, wid, review),
                         unverified=_unverified(conn, wid, review), waivers=_waiver_lines(work, cfg, conn),
                         warnings=[w.removeprefix("avviso: ") for w in warnings], block=block)
    body_file = wt / ".tollgate-run" / str(work["issue"]) / "pr-body.md"
    body_file.parent.mkdir(parents=True, exist_ok=True)
    body_file.write_text(body, encoding="utf-8")

    intents.request(conn, work=wid, action="pr", key=key, data={"sha": head, "branch": branch},
                    now=now)
    try:
        pr = _publish(state, conn, work, wt, main, branch, head, remote, diverged, open_pr_,
                      body_file, now)
    except SIDE_EFFECT_ERRORS as e:
        return _refuse(str(e), "la ripetizione riprende da qui: l'atto resta valido e non si "
                       "apre una seconda PR", warnings=warnings)

    phases.set_pr(conn, wid, pr["number"], pr["url"], now=now)
    events.record_event(conn, "pr_opened" if first_time else "pr_updated",
                        {"pr": pr["number"], "sha": head}, now=now, session=session, work=wid)
    if work["phase"] == "review" and not resume:
        phases.set_phase(conn, state, wid, "pr_open", "advance", now=now, session=session)
    intents.complete(conn, key, outcome=f"PR #{pr['number']}", now=now)
    for spec in used:                                     # l'atto si consuma per ultimo
        try:
            acts.consume(conn, now=now, **spec)
        except acts.ActError as e:
            warnings.append(f"avviso: {e}")
    verb = "aperta" if pr["created"] else "aggiornata"
    lines = [*warnings, f"PR #{pr['number']} {verb}: {pr['url']}", *dod_lines,
             "prossimo passo: attendi il gate su GitHub (tollgate/guard e tollgate/verdict); "
             "il merge è tuo"]
    return OpenResult(OK, lines, pr["url"])


def _publish(state, conn, work, wt, main, branch, head, remote, diverged, open_pr_, body_file,
             now) -> dict:
    """Push, controllo con `ls-remote`, poi `pr edit` o `pr create`. Dà numero, URL e se la PR
    è stata creata ora."""
    if remote != head:
        lease = None
        if diverged:
            if not intents.force_authorized(conn, work["id"]):
                raise gitw.GitWriteError("l'autorizzazione al push forzato non c'è più")
            lease = intents.force_lease(conn, work["id"]) or remote
        try:
            gitw.push_sha(wt, head, branch, lease=lease)
        except gitw.GitWriteError as e:
            if lease:
                raise gitw.GitWriteError(f"il ramo remoto è avanzato: /tollgate:sync ({e})") from e
            raise
        if diverged:        # si consuma solo a push riuscito: un guasto non la perde
            intents.take_force(conn, work["id"], now=now)
        if gitw.remote_sha(wt, branch) != head:
            raise gitw.GitWriteError(f"dopo il push il ramo {branch} di origin non punta a "
                                     f"{head[:7]}")
    if open_pr_ is not None:
        current = open_pr_
        if remote != head:      # la punta della PR si rilegge dopo il push
            current = gh.pr_for_branch(state, main, branch)
        if (current is None or current.get("number") != open_pr_["number"]
                or current.get("headRefOid") != head):
            oid = (current or {}).get("headRefOid") or "sconosciuto"
            raise gh.GhError(f"la PR #{open_pr_['number']} ha come punta {str(oid)[:7]} e non lo "
                             f"SHA spinto {head[:7]}: non la modifico (se GitHub è in ritardo, "
                             "ripeti il comando)")
        gh.pr_edit(state, main, open_pr_["number"], body_file=body_file)
        return {"number": open_pr_["number"], "url": open_pr_.get("url"), "created": False}
    base = git.default_branch(main)
    gh.pr_create(state, main, branch=branch, base=base, title=_title(work["issue"], branch),
                 body_file=body_file)
    made = gh.pr_for_branch(state, main, branch)
    if made is None or made.get("state") != "OPEN":
        raise gh.GhError("la PR risulta creata ma gh non la trova: ripeti il comando")
    return {"number": made["number"], "url": made.get("url"), "created": True}


def _waiting(conn, work, cfg) -> list[str]:
    out = []
    wf = violations.waiver_file(work)
    if wf is not None:
        sensitive = cfg.get("levels.sensitive_paths")
        status = waivers.status(wf, approved_ids=acts.approved_waivers(conn, work["id"]),
                                sensitive=lambda p: bool(lv.sensitive_in([p], sensitive)))
        out += [f"deroga {w.id} ({w.type}) in attesa: serve /tollgate:approve waiver {w.id}"
                for w in wf.waivers if status.get(w.id) == "pending"]
    for r in conn.execute("SELECT data FROM intents WHERE work = ? AND action = 'effect' "
                          "AND state = 'requested' ORDER BY id", (work["id"],)):
        eid = json.loads(r["data"] or "{}").get("id", "?")
        out.append(f"effetto {eid} in attesa: serve /tollgate:approve effect {eid}")
    return out


def _compute_dod(conn, work, cfg, wt, base, head, review, problems):
    """La DoD ricalcolata. `guard_scope`, `must_have` e `approvals` vengono da `finish check`
    (stesso SHA); il resto si ricalcola qui, con i rilievi dell'ultimo ciclo su HEAD (15)."""
    wid = work["id"]
    if not work["finish_report"]:
        problems.append("manca l'esito di `finish check`: rilancia finish check")
        return [], {}
    reported = json.loads(work["finish_report"])["items"]
    external = {k: reported.get(k) for k in ("guard_scope", "must_have", "approvals")}
    files = [c.path for c in git.changes(wt, base, head=head) if c.status != "D"]
    extra = verify.dod_commands(cfg, files)
    required = [s.name for s in verify.gate_commands(cfg, files) + extra]
    allow_unverified = acts.has_approval(conn, wid, "unverified-tests")
    allow_no_tests = cfg.get("project.allow_no_tests")
    profile_items, details = finishcheck.profile_receipts(conn, wid, head, extra,
                                                          allow_no_tests, allow_unverified)
    items = dod.compute_dod(conn, wid, head_sha=head, allow_no_tests=allow_no_tests,
                            required_commands=required, external=external,
                            profile_items=profile_items, allow_unverified=allow_unverified,
                            findings_cycle=review.findings_cycle,
                            specialists=review.specialists)
    return items, details


def _notes(conn, wid: int, review: Review) -> list[dict]:
    """I rilievi confermati dell'ultimo ciclo su HEAD che non fermano la PR (10): note."""
    if review.findings_cycle == 0:
        return []
    stopping = {r["id"] for r in reviews.blocking_open(conn, wid, review.findings_cycle)}
    return [dict(r) for r in conn.execute(
        "SELECT * FROM findings WHERE work = ? AND cycle = ? AND verification = 'confirmed' "
        "AND (user_decision IS NULL OR user_decision <> 'dismissed') ORDER BY rowid",
        (wid, review.findings_cycle)) if r["id"] not in stopping]


def _unverified(conn, wid: int, review: Review) -> list[dict]:
    """I rilievi `unverified` dell'ultimo ciclo su HEAD (non provati, oltre `max_findings` o di una
    revisione dichiarata non verificata): il blocco JSON non lo legge nessuno, il corpo sì."""
    if review.findings_cycle == 0:
        return []
    return [dict(r) for r in conn.execute(
        "SELECT * FROM findings WHERE work = ? AND cycle = ? AND verification = 'unverified' "
        "ORDER BY rowid", (wid, review.findings_cycle))]


def _waiver_lines(work, cfg, conn) -> list[str]:
    wf = violations.waiver_file(work)
    if wf is None or not wf.waivers:
        return []
    sensitive = cfg.get("levels.sensitive_paths")
    status = waivers.status(wf, approved_ids=acts.approved_waivers(conn, work["id"]),
                            sensitive=lambda p: bool(lv.sensitive_in([p], sensitive)))
    return [f"{w.id} {w.type} {w.file or w.pattern} [{status.get(w.id)}]: {w.choice} / {w.why} "
            f"(costo: {w.cost})" for w in wf.waivers]


def issue_labels(state, main, work) -> tuple[tuple[str, ...] | None, str | None]:
    """Le etichette dell'issue del lavoro e, se `gh` non le legge, l'avviso: senza etichette il
    livello minimo viene dal solo diff (`open-pr` e `finish check` lo dicono)."""
    try:
        return gh.issue(state, main, work["issue"]).labels, None
    except gh.GhError as e:
        return None, (f"avviso: etichette dell'issue non lette ({e}): level_minimum è "
                      "calcolato dal solo diff")


def _l2_dirs(wt: Path, head: str, work) -> tuple[str | None, dict, str | None]:
    """Cartelle 18.1 e intestazione dell'approvazione della spec, dall'albero di `head` (lo SHA
    spinto, decisione 15). La spec si approva solo in L2 ma conta `spec_path`: senza, nessuna
    cartella. L'approvazione trovata può essere di un'altra issue (fetta successiva); la
    cartella del piano è quella del lavoro se `plan-approval.md` esiste."""
    issue = work["issue"]
    plan_file = approvals_mod.approval_paths(issue)[1]
    plan_dir = plan_file.rpartition("/")[0] + "/" if git.exists_at(wt, head, plan_file) else None
    spec_path = work["spec_path"]
    if not spec_path:
        return None, {}, plan_dir
    found = l2tree.locate(wt, head, issue=issue, spec_path=spec_path,
                          spec_blob=git.blob_at(wt, head, spec_path))
    if found is None:
        return None, {}, plan_dir
    return found[0].rpartition("/")[0] + "/", found[1], plan_dir


def facts(conn, state, work, cfg, wt: Path, head: str, *, now, dod=None, labels=None,
          cycle=_AUTO) -> dict:
    """I campi del blocco 18.1 (decisione 11). `dod` sono le voci ricalcolate da `open-pr`,
    `labels` le etichette dell'issue (assenti: il livello minimo viene dal solo diff), `cycle`
    il ciclo di revisione che vale per HEAD (`None`: nessuno; omesso: l'ultimo chiuso sullo
    stesso SHA)."""
    wid, issue = work["id"], work["issue"]
    base = work["work_base_sha"] or git.default_ref(wt)
    exclude = config.output_excludes(cfg)
    changes = git.changes(wt, base, head=head, exclude=exclude)
    paths = [c.path for c in changes] + [c.old_path for c in changes if c.old_path]
    levels_cfg = cfg.get("levels")
    minimum = lv.diff_level(changes, diff_bytes=git.diff_size(wt, base, head=head,
                                                              exclude=exclude),
                            sensitive_paths=levels_cfg["sensitive_paths"],
                            l0_max_files=levels_cfg["l0_max_files"],
                            l0_max_lines=levels_cfg["l0_max_lines"],
                            l0_max_bytes=levels_cfg["l0_max_bytes"])
    profs = cfg.profiles
    minimum = lv.max_level(
        minimum, prof.min_level(prof.active_profiles(paths, profs, cfg.get("profiles.active")),
                                profs),
        lv.labels_level(labels or (), levels_cfg["sensitive_labels"]))

    spec_dir, spec_header, plan_dir = _l2_dirs(wt, head, work)
    if cycle is _AUTO:
        latest = reviews.latest(conn, wid)
        cycle = latest if latest is not None and latest["sha"] == head else None
    last_on_head = cycle if cycle is not None and cycle["stage"] == "closed" else None
    findings = [
        {"id": r["id"], "severity": r["severity"], "confidence": r["confidence"],
         "verification": r["verification"], "user_decision": r["user_decision"],
         "blocking": bool(r["blocking"])}
        for r in conn.execute("SELECT * FROM findings WHERE work = ? ORDER BY cycle, rowid",
                              (wid,))]
    agents = conn.execute("SELECT count(*), coalesce(sum(tokens), 0) FROM subagents "
                          "WHERE work = ?", (wid,)).fetchone()
    return {
        "schema_version": prblock.SCHEMA_VERSION,
        "tollgate_version": VERSION,
        "issue": issue,
        "level": work["level"],
        "level_minimum": minimum,
        "level_cap": work["level_cap"],
        "level_cap_reason": work["level_cap_reason"],
        "gate_mode": work["gate_mode"],
        "plan": work["plan_path"],
        "plan_sha": work["plan_sha"],
        "spec": work["spec_path"],
        "spec_reviews_dir": spec_dir,
        "plan_reviews_dir": plan_dir,
        "spec_audit": {"adversarial": spec_header.get("adversarial"),
                       "lens": spec_header.get("lens")},
        "head_sha": head,
        "receipts": [{"command": r["command"], "state": r["state"], "tests_run": r["tests_run"]}
                     for r in receipts.latest(conn, wid, head)],
        "waivers_file": waivers.path_for(issue),
        "blocks": [{"id": b["id"], "type": b["type"], "reason": b["reason"]}
                   for b in conn.execute("SELECT id, type, reason FROM blocks WHERE work = ? "
                                         "AND closed IS NULL ORDER BY id", (wid,))],
        "acts": [{"act_id": a["act_id"], "type": a["type"], "object": a["object"],
                  "target": a["target"], "at": a["at"], "state": a["state"]}
                 for a in conn.execute("SELECT * FROM acts WHERE work = ? AND type IN "
                                       "('approve', 'resolve', 'reopen') ORDER BY n", (wid,))],
        "dod": {"L": work["level"], "items": {i.key: i.ok for i in dod or []}},
        "verdict": {"outcome": last_on_head["outcome"] if last_on_head else None,
                    "cycles": reviews.count(conn, wid),
                    "findings_confirmed": (last_on_head["findings_confirmed"] or 0)
                    if last_on_head else 0,
                    "unverified": bool(work["review_unverified"])},
        "findings": findings,
        "fix_rounds": {str(t["number"]): t["fix_rounds"] for t in conn.execute(
            "SELECT number, fix_rounds FROM tasks WHERE work = ? AND fix_rounds > 0 "
            "ORDER BY number", (wid,))},
        "subagents": {"count": agents[0], "tokens": agents[1]},
        "effects": [{"command_hash": r["idempotency_key"].removeprefix("effect:"),
                     "at": json.loads(r["data"] or "{}").get("executed_at") or r["at"]}
                    for r in conn.execute("SELECT * FROM intents WHERE work = ? AND action = "
                                          "'effect' AND state = 'executed' ORDER BY id",
                                          (wid,))],
        "components_off": [k for k, v in cfg.get("components").items() if v is False],
        "off_periods": stats.off_periods(conn, clock.parse(work["created"]), now),
        "tasks_over": _tasks_over(conn, wt, work, cfg),
        "skills_absent": _skills_absent(conn, wid),
    }


def _size_reasons(conn, wid: int) -> dict[int, str]:
    """Il `size_reason` di ogni task: quello dell'ultimo evento `subagent_stop` che ne porta uno
    (un giro di correzione senza motivo non cancella il precedente)."""
    out: dict[int, str] = {}
    for r in conn.execute("SELECT data FROM events WHERE work = ? AND type = 'subagent_stop' "
                          "ORDER BY seq", (wid,)):
        data = json.loads(r["data"])
        if isinstance(data.get("task"), int) and data.get("size_reason"):
            out[data["task"]] = data["size_reason"]
    return out


def _tasks_over(conn, wt: Path, work, cfg) -> list[dict]:
    """I task oltre `task_lines_warn` righe (decisione 21): `size.task_lines` sui commit del
    task. Un task senza commit, o con commit che una riscrittura ha tolto dalla storia, non si
    misura."""
    warn = cfg.get("tasks.task_lines_warn")
    lockfiles = set(cfg.get("scope.lockfiles"))
    reasons = _size_reasons(conn, work["id"])
    out = []
    for t in conn.execute("SELECT number, commits FROM tasks WHERE work = ? ORDER BY number",
                          (work["id"],)):
        commits = json.loads(t["commits"])
        if not commits:
            continue
        try:
            changes = git.changes(wt, git.range_base(wt, commits[0]), head=commits[-1])
        except git.GitError:
            continue
        lines = size.task_lines(changes, lockfiles)
        if lines > warn:
            out.append({"task": t["number"], "lines": lines,
                        "size_reason": reasons.get(t["number"])})
    return out


def _skills_absent(conn, wid: int) -> list[dict]:
    """Le skill che `task start` ha tolto da un task perché assenti (evento `skills_absent`,
    decisione 21): per ogni task l'ultima registrazione."""
    latest: dict[int, list] = {}
    for r in conn.execute("SELECT data FROM events WHERE work = ? AND type = 'skills_absent' "
                          "ORDER BY seq", (wid,)):
        data = json.loads(r["data"])
        latest[data["task"]] = data["skills"]
    return [{"task": t, "skills": latest[t]} for t in sorted(latest)]
