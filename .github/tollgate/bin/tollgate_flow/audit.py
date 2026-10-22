"""`tollgate audit prepare` e `tollgate audit decline` (spec 6.2, decisioni 3, 4, 6, 21 di P3c).

`prepare` decide dallo stato il prossimo giro di audit (giri avversariali della spec, audit a
lenti, avversario del piano), scrive i brief degli agenti e stampa le righe di lancio come
`review prepare`. La decisione è una funzione senza scritture (`_decide_spec`, `_decide_plan`):
`prepare` la esegue, `peek` la legge soltanto (prossimo passo di `status`), `decline` la
riusa per le precondizioni. Il documento si legge sempre a HEAD: un file diverso dal blob in HEAD
si rifiuta con «committa» (i report non committati non contano).

Ordine dei rami in `spec_audit` (D2, variante B): giro aperto -> avversariale non passato ->
ciclo a lenti -> avversariale di conferma -> ciclo a lenti di conferma -> `approve spec`."""
from __future__ import annotations

import json
import secrets
import sqlite3
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from tollgate_analysis import (approvals, auditrules, brief as briefs, plan as planmod,
                               profiles as prof, specdoc)
from tollgate_core import audits, clock, config, db, git, phases, scope, sessions
from tollgate_core.paths import program_command

from . import adopt, finalreview, l2tree

OK, REFUSED, NEEDS_CONFIRM = 0, 1, 3
SPECS_DIR = "docs/superpowers/specs/"
SPEC_KINDS = ("spec-adversarial", "spec-lens")
PLAN_KIND = auditrules.PLAN_KIND
LENS_KIND = auditrules.LENS_KIND
ADV_KIND = "spec-adversarial"
LENS_MIN_CYCLES = len(auditrules.VIEWPOINTS) * auditrules.EMPTY_NEEDED

# Testi dei «prossimo passo:». Parte fissa senza segnaposto, segnaposto dopo (`<programma>` e
# `<id>` li sostituisce chi stampa, `<fette>` pure); il Task 13 confronta la parte fissa.
STEPS = {
    "launch": "lancia l'agente qui sopra (anche più di uno, se sono più righe); quando ha "
              "riportato, rilancia <programma> audit prepare",
    "fix_spec": "correggi la spec e committala, poi rilancia <programma> audit prepare",
    "fix_plan": "correggi il piano e committalo, poi rilancia <programma> audit prepare",
    "approve_spec": "chiedi all'utente /tollgate:approve spec <fette>",
    "approve_plan": "chiedi all'utente /tollgate:approve plan",
    "write_spec": "scrivi e committa la spec sotto docs/superpowers/specs/, poi rilancia "
                  "<programma> audit prepare",
    "write_plan": "scrivi il piano con superpowers:writing-plans (deve passare plan-check) e "
                  "committalo, poi rilancia <programma> audit prepare",
    "resolve": "serve una decisione dell'utente: /tollgate:resolve <id> <nota> sospende; "
               "oppure correggi e rilancia <programma> audit prepare dopo il resolve",
}
PLAN_CHANGED = ("il piano o la spec sono cambiati dopo l'ultimo giro dell'avversario "
                "({number}): riapri con /tollgate:reopen plan")
CONFIRM_STEP = ("chiedi all'utente se procedere: con il sì rilancia <programma> audit prepare "
                "--confirm, con il no lancia <programma> audit decline")
ERRORS = (sqlite3.Error, git.GitError, config.ConfigError, phases.TransitionError, OSError,
          db.DbError, UnicodeDecodeError)


class AuditError(Exception):
    pass


@dataclass
class PrepareResult:
    code: int
    lines: list[str] = field(default_factory=list)
    launches: list[finalreview.Launch] = field(default_factory=list)


def _prog() -> str:
    return program_command(db.BIN_PATH)


def _step_text(key: str, **subs) -> str:
    text = STEPS[key].replace("<programma>", _prog())
    for name, value in subs.items():
        text = text.replace(f"<{name}>", str(value))
    return text


class _Refuse(Exception):
    """Un rifiuto con il suo messaggio e, se c'è, la chiave del passo da fare."""

    def __init__(self, message: str, step: str | None = None, **subs):
        super().__init__(message)
        self.message, self.step, self.subs = message, step, subs
        self.supersede = None       # giro aperto su un altro SHA da chiudere anche rifiutando

    def lines(self) -> list[str]:
        out = [f"rifiuto: {self.message}"]
        if self.step:
            out.append(f"prossimo passo: {_step_text(self.step, **self.subs)}")
        return out

    def hint(self) -> str:
        return _step_text(self.step, **self.subs) if self.step else self.message


@dataclass
class _Ctx:
    conn: sqlite3.Connection
    wt: Path
    work: sqlite3.Row
    cfg: config.Config
    head: str
    base: str
    confirm: bool = False


@dataclass
class _Round:
    """Il giro da aprire o ristampare: il documento esaminato e la spec, tutti a HEAD."""
    kind: str
    doc_path: str
    doc_blob: str
    spec_path: str
    spec_blob: str
    viewpoint: str | None = None
    tasks: list[dict] = field(default_factory=list)


@dataclass
class _Act:
    kind: str       # open | reprint | confirm | approve_spec | approve_plan | advance
    round: _Round | None = None
    row: sqlite3.Row | None = None
    supersede: sqlite3.Row | None = None
    register_spec: str | None = None
    register_plan: str | None = None
    slices: int = 1


def comp(cfg, name: str) -> bool:
    return bool(cfg.get("components").get(name, True))


def on(cfg, kind: str) -> bool:
    """Il componente che governa il tipo di giro è acceso."""
    return comp(cfg, audits.COMPONENTS[kind])


def work_base(work, wt: Path) -> str | None:
    """La base del lavoro: `work_base_sha` o la punta del ramo predefinito di origin."""
    return work["work_base_sha"] or git.default_ref(git.main_worktree(wt))


def work_config(state, work) -> config.Config:
    """La configurazione del lavoro, letta dalla base (spec 3.2): l'unico punto che la carica per
    `audit`, `approve spec|plan` e `resolve`. `ConfigError` se manca il worktree o la base."""
    if not work["worktree"]:
        raise config.ConfigError("il lavoro non ha un worktree")
    wt = Path(work["worktree"])
    base = work_base(work, wt)
    if not base:
        raise config.ConfigError("manca la base del lavoro: nessun ramo predefinito su origin")
    return config.load_config(state, git.main_worktree(wt), base)


def _counts(row) -> dict | None:
    return json.loads(row["counts"]) if row["counts"] else None


def clean(row) -> bool:
    counts = _counts(row)
    return counts is not None and auditrules.is_clean(counts)


def passed(conn, work: int, row, kind: str) -> bool:
    """Un giro è «passato» se è pulito o è quello sospeso con `resolve` (decisione 7)."""
    return row is not None and (clean(row) or audits.suspended(conn, work).get(kind) ==
                                row["number"])


def last_round(conn, work: int, kind: str):
    rows = audits.rounds(conn, work, kind)
    return rows[-1] if rows else None


def adversarial_ok(conn, work: sqlite3.Row, cfg, spec_blob: str | None) -> bool:
    """La condizione avversariale di `approve spec` e dei rami di `prepare` (decisione 3):
    componente spento, oppure l'ultimo giro avversariale chiuso sta sul blob attuale ed è pulito
    o sospeso."""
    if not on(cfg, ADV_KIND):
        return True
    last = last_round(conn, work["id"], ADV_KIND)
    return (last is not None and spec_blob is not None and last["sha"] == spec_blob
            and passed(conn, work["id"], last, ADV_KIND))


def _check_path(path: str) -> None:
    """D12: un percorso con a capo, `"`, backtick o caratteri di controllo non entra in un brief,
    in una riga di lancio né in un file di approvazione (il backtick chiuderebbe un recinto)."""
    if any(unicodedata.category(c) in ("Cc", "Zl", "Zp") or c in '"`' for c in path):
        raise _Refuse("il percorso del documento contiene un a capo, delle virgolette, dei "
                      "backtick o caratteri di controllo: rinomina il file")


class Uncommitted(Exception):
    """Il documento non è in HEAD tale e quale: `missing` se non c'è nemmeno sul disco."""

    def __init__(self, path: str, missing: bool):
        super().__init__(path)
        self.path, self.missing = path, missing


def committed_blob(wt: Path, path: str) -> str:
    """Il blob di `path` a HEAD, solo se il file del worktree è identico; altrimenti
    `Uncommitted`. Chi chiama sceglie il messaggio."""
    blob = git.blob_at(wt, "HEAD", path)
    if blob is None:
        raise Uncommitted(path, missing=not (wt / path).exists())
    try:
        same = git.blob_sha(wt, path) == blob
    except git.GitError:
        same = False
    if not same:
        raise Uncommitted(path, missing=False)
    return blob


REGISTERED_NOTE = (": è il percorso registrato e il nome non si cambia, rimetti il contenuto "
                   "sotto questo nome")


def _committed(ctx: _Ctx, path: str, what: str, step: str) -> str:
    try:
        return committed_blob(ctx.wt, path)
    except Uncommitted as e:
        if e.missing:
            raise _Refuse(f"{what} {path} non è nel ramo"
                          + (REGISTERED_NOTE if path in (ctx.work["spec_path"],
                                                         ctx.work["plan_path"]) else ""),
                          step) from e
        raise _Refuse(f"committa {path} prima del giro") from e


def plan_check(cfg, text: str) -> planmod.PlanCheck:
    """Il plan-check di L2 con le soglie della config: lo stesso per `audit prepare` e per
    `approve plan`."""
    return planmod.check_plan(
        text, required_sections=cfg.get("plan.required_sections"),
        max_scope_files=cfg.get("plan.max_scope_files"),
        must_have_tests=comp(cfg, "must_have_tests"), level="L2", profiles=cfg.profiles,
        active_always=cfg.get("profiles.active"))


def _new_file(ctx: _Ctx, prefix: str) -> list[str]:
    changes = git.changes(ctx.wt, ctx.base, head=ctx.head,
                          exclude=config.output_excludes(ctx.cfg))
    return sorted(c.path for c in changes if c.status == "A" and c.path.startswith(prefix)
                  and c.path.endswith(".md"))


def _spec_doc(ctx: _Ctx) -> tuple[str, str, str, str | None]:
    """`(percorso, blob a HEAD, testo a HEAD, percorso da registrare)` della spec del lavoro."""
    path, register = ctx.work["spec_path"], None
    if not path:
        found = _new_file(ctx, SPECS_DIR)
        if not found:
            raise _Refuse("nessuna spec nel ramo", "write_spec")
        path = register = found[0]
    _check_path(path)
    blob = _committed(ctx, path, "la spec", "write_spec")
    return path, blob, git.text_at(ctx.wt, "HEAD", path) or "", register


def _spec_round(kind: str, spec: tuple, viewpoint: str | None = None) -> _Round:
    return _Round(kind, spec[0], spec[1], spec[0], spec[1], viewpoint)


def _adv_or_fix(ctx: _Ctx, last, spec: tuple, slices: int, supersede, register) -> _Act:
    """Avversariale da fare: se l'ultimo giro ha rilievi bloccanti sulla spec attuale (e non è
    sospeso) si corregge prima, altrimenti nuovo giro (o giro di conferma)."""
    if last is not None and last["sha"] == spec[1] and not passed(ctx.conn, ctx.work["id"],
                                                                   last, ADV_KIND):
        raise _Refuse(f"l'ultimo giro avversariale ({last['number']}) ha blocker o major sulla "
                      "spec attuale", "fix_spec")
    return _Act("open", _spec_round(ADV_KIND, spec), supersede=supersede,
                register_spec=spec[3], slices=slices)


def _decide_spec(ctx: _Ctx) -> _Act:
    conn, wid, cfg = ctx.conn, ctx.work["id"], ctx.cfg
    path, blob, text, register = _spec_doc(ctx)
    spec = (path, blob, text, register)
    slices = specdoc.slices(text)
    row = audits.open_round_row(conn, wid)
    if row is not None and row["kind"] in SPEC_KINDS and on(cfg, row["kind"]) \
            and row["sha"] == blob:
        return _Act("reprint", _spec_round(row["kind"], spec, row["viewpoint"]),
                    row=row, register_spec=register, slices=slices)
    stale = row         # giro aperto su un altro SHA, di un tipo spento o di un altro documento
    try:
        return _spec_branches(ctx, spec, slices, stale, register)
    except _Refuse as r:
        r.supersede = stale         # decisione 3: si chiude anche quando poi si rifiuta
        raise


def _spec_branches(ctx: _Ctx, spec: tuple, slices: int, stale, register) -> _Act:
    conn, wid, cfg, blob = ctx.conn, ctx.work["id"], ctx.cfg, spec[1]
    adv_on, lens_on = on(cfg, ADV_KIND), on(cfg, LENS_KIND)
    last_adv = last_round(conn, wid, ADV_KIND)
    # 2. avversariale non passato (qualunque SHA)
    if adv_on and not passed(conn, wid, last_adv, ADV_KIND):
        return _adv_or_fix(ctx, last_adv, spec, slices, stale, register)
    lens_rows = audits.rounds(conn, wid, LENS_KIND)
    state = auditrules.lens_state([(r["viewpoint"], r["outcome"]) for r in lens_rows])
    lens_done = state.closed or LENS_KIND in audits.suspended(conn, wid)
    last_lens = lens_rows[-1] if lens_rows else None
    # 3. ciclo a lenti
    if slices > 1 and lens_on and not lens_done:
        if last_lens is not None and last_lens["sha"] == blob and last_lens["outcome"] != "empty":
            raise _Refuse(f"l'ultimo ciclo a lenti ({last_lens['number']}) ha rilievi sulla "
                          "spec attuale", "fix_spec")
        if not audits.any_rows(conn, wid, LENS_KIND) and not ctx.confirm:
            return _Act("confirm", supersede=stale, register_spec=register, slices=slices)
        vp = auditrules.next_viewpoint(state, last_lens["viewpoint"] if last_lens else None)
        return _Act("open", _spec_round(LENS_KIND, spec, vp), supersede=stale,
                    register_spec=register, slices=slices)
    # 4. avversariale di conferma sulla versione finale
    if not adversarial_ok(conn, ctx.work, cfg, blob):
        return _adv_or_fix(ctx, last_adv, spec, slices, stale, register)
    # 5. ciclo a lenti di conferma, con l'avversariale spento
    if not adv_on and slices > 1 and lens_on and lens_done and last_lens is not None \
            and last_lens["sha"] != blob:
        vp = auditrules.next_viewpoint(state, last_lens["viewpoint"])
        return _Act("open", _spec_round(LENS_KIND, spec, vp), supersede=stale,
                    register_spec=register, slices=slices)
    return _Act("approve_spec", supersede=stale, register_spec=register, slices=slices)


def _spec_approval_current(ctx: _Ctx, spec_path: str, spec_blob: str) -> None:
    """D3: l'approvazione della spec si legge a HEAD e deve essere sullo `sha` attuale (la
    stessa ricerca di `approve plan`: `l2tree.spec_approval`)."""
    status, _ = l2tree.spec_approval(ctx.wt, "HEAD", issue=ctx.work["issue"],
                                     spec_path=spec_path, spec_blob=spec_blob)
    if status == l2tree.STALE:
        raise _Refuse("spec cambiata dopo approve spec: /tollgate:reopen spec")
    if status == l2tree.MISSING:
        own = approvals.approval_paths(ctx.work["issue"])[0]
        if (ctx.wt / own).exists():
            raise _Refuse(f"committa {own} prima del giro del piano")
        raise _Refuse("la spec non ha un file di approvazione nel ramo: rifai la spec con "
                      "/tollgate:reopen spec")


def _task_rows(ctx: _Ctx, check) -> list[dict]:
    warn = ctx.cfg.get("tasks.task_files_warn")
    rows = []
    for t in check.tasks:
        routing = prof.task_routing(t.files, ctx.cfg.profiles)
        rows.append({"number": t.number, "title": t.title, "files": len(t.files),
                     "implementer": routing.implementer,
                     "split_candidate": routing.split_candidate, "files_warn": len(t.files) > warn})
    return rows


def _decide_plan(ctx: _Ctx) -> _Act:
    conn, wid, cfg, work = ctx.conn, ctx.work["id"], ctx.cfg, ctx.work
    spec_path = work["spec_path"]
    if not spec_path:
        raise _Refuse("la spec del lavoro non è registrata: /tollgate:reopen spec")
    _check_path(spec_path)
    spec_blob = _committed(ctx, spec_path, "la spec", "write_spec")
    _spec_approval_current(ctx, spec_path, spec_blob)
    plan_path, register = work["plan_path"], None
    if not plan_path:
        found = adopt.find_plan(ctx.wt, cfg, ctx.head,
                                git.changes(ctx.wt, ctx.base, head=ctx.head,
                                            exclude=config.output_excludes(cfg)), "L2")
        if found is None:
            raise _Refuse("nessun piano valido nel ramo", "write_plan")
        plan_path = register = found[0]
    _check_path(plan_path)
    plan_blob = _committed(ctx, plan_path, "il piano", "write_plan")
    check = plan_check(cfg, git.text_at(ctx.wt, "HEAD", plan_path) or "")
    if not check.ok:
        raise _Refuse("il piano non passa plan-check:\n- " + "\n- ".join(check.problems),
                      "write_plan")
    row = audits.open_round_row(conn, wid)
    if not on(cfg, PLAN_KIND):
        return _Act("advance", supersede=row, register_plan=register)
    rnd = _Round(PLAN_KIND, plan_path, plan_blob, spec_path, spec_blob,
                 tasks=_task_rows(ctx, check))
    if row is not None and row["kind"] == PLAN_KIND and row["sha"] == plan_blob \
            and row["spec_sha"] == spec_blob:
        return _Act("reprint", rnd, row=row, register_plan=register)
    last = last_round(conn, wid, PLAN_KIND)
    same = last is not None and last["sha"] == plan_blob and last["spec_sha"] == spec_blob
    if same and passed(conn, wid, last, PLAN_KIND):
        return _Act("advance", supersede=row, register_plan=register)
    if same:
        refusal = _Refuse(f"l'ultimo giro del piano ({last['number']}) ha blocker o major sul "
                          "piano attuale", "fix_plan")
        refusal.supersede = row
        raise refusal
    return _Act("open", rnd, supersede=row, register_plan=register)


def _decide_approval(ctx: _Ctx) -> _Act:
    """In `approval` piano e spec in HEAD devono essere quelli dell'ultimo giro dell'avversario
    del piano (come per `approve plan`); se sono cambiati l'uscita è `reopen plan`."""
    work, cfg = ctx.work, ctx.cfg
    plan_path, spec_path = work["plan_path"], work["spec_path"]
    if on(cfg, PLAN_KIND) and plan_path and spec_path:
        last = last_round(ctx.conn, work["id"], PLAN_KIND)
        plan_blob = git.blob_at(ctx.wt, "HEAD", plan_path)
        spec_blob = git.blob_at(ctx.wt, "HEAD", spec_path)
        if last is not None and plan_blob is not None and spec_blob is not None \
                and (last["sha"], last["spec_sha"]) != (plan_blob, spec_blob):
            raise _Refuse(PLAN_CHANGED.format(number=last["number"]))
    if spec_path and not on(cfg, PLAN_KIND):
        # senza l'avversario non c'è un giro con cui confrontare: la spec in HEAD deve essere
        # ancora quella approvata, come per `approve plan` (caso (b))
        spec_blob = git.blob_at(ctx.wt, "HEAD", spec_path)
        if spec_blob is not None:
            _spec_approval_current(ctx, spec_path, spec_blob)
    return _Act("approve_plan")


def _context(state, conn, cwd: Path, confirm: bool) -> _Ctx:
    work = sessions.work_for_path(conn, cwd)
    if work is None:
        raise AuditError("nessun lavoro attivo per questa cartella: lancia il comando dal "
                         "worktree del lavoro")
    if work["level"] != "L2":
        raise _Refuse(f"l'audit di spec e piano è di L2 (questo lavoro è {work['level']})")
    if work["phase"] == "blocked":
        block = conn.execute("SELECT id, reason FROM blocks WHERE work = ? AND closed IS NULL "
                             "ORDER BY id DESC LIMIT 1", (work["id"],)).fetchone()
        raise _Refuse("il lavoro è bloccato" + (f" (blocco {block['id']}: {block['reason']})"
                                                if block else ""),
                      "resolve", id=block["id"] if block else "<id>")
    if work["phase"] not in ("spec_audit", "plan", "approval"):
        raise _Refuse(f"{_prog()} audit prepare vale in spec_audit, plan e approval "
                      f"(fase {work['phase']})")
    wt = Path(work["worktree"])
    base = work_base(work, wt)
    if not base:
        raise AuditError("manca la base del lavoro: nessun ramo predefinito su origin")
    head = git.head(wt)
    if head is None:
        raise AuditError("il worktree non ha commit")
    return _Ctx(conn, wt, work, work_config(state, work), head, base, confirm)


def _decide(ctx: _Ctx) -> _Act:
    phase = ctx.work["phase"]
    if phase == "spec_audit":
        return _decide_spec(ctx)
    if phase == "plan":
        return _decide_plan(ctx)
    return _decide_approval(ctx)


def _write_brief(ctx: _Ctx, rnd: _Round, number: int, code: str) -> Path:
    run_dir = ctx.wt / ".tollgate-run" / str(ctx.work["issue"])
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / f"{rnd.kind}-{number}.md"
    issue_file = run_dir / "issue.md"
    method = (Path(db.BIN_PATH).parent.parent / "skills" / "spec-audit" / "references"
              / "dimensioni.md") if rnd.kind == LENS_KIND else None
    path.write_text(briefs.audit_brief(briefs.AuditBrief(
        issue=ctx.work["issue"], kind=rnd.kind, number=number, code=code, doc_path=rnd.doc_path,
        doc_sha=rnd.doc_blob, spec_path=rnd.spec_path, spec_sha=rnd.spec_blob,
        reviews_dir=f"{approvals.REVIEWS_DIR}/{ctx.work['issue']}",
        issue_file=str(issue_file) if issue_file.is_file() else None,
        severity=ctx.cfg.get("severity"), viewpoint=rnd.viewpoint,
        method_path=str(method) if method else None, tasks=rnd.tasks)), encoding="utf-8")
    return path


def _launch(ctx: _Ctx, rnd: _Round, number: int, code: str, *, again: bool) -> PrepareResult:
    path = _write_brief(ctx, rnd, number, code)
    agent = audits.AGENTS[rnd.kind]
    launch = finalreview.Launch(agent, path, ctx.cfg.get("review.models").get(agent))
    what = {ADV_KIND: "giro avversariale della spec", LENS_KIND: "ciclo a lenti della spec",
            PLAN_KIND: "giro avversariale del piano"}[rnd.kind]
    vp = f", punto di vista {rnd.viewpoint}" if rnd.viewpoint else ""
    head = (f"{what} {number}{vp} su {rnd.doc_path} (blob {rnd.doc_blob[:7]})"
            + (": già aperto, stesso codice" if again else ""))
    return PrepareResult(OK, [head, finalreview.launch_line(launch),
                              f"prossimo passo: {_step_text('launch')}"], [launch])


def _next_report_number(ctx: _Ctx, kind: str) -> int:
    """Il numero che segue l'ultimo report del tipo già in `reviews/<N>/` a HEAD: dopo un DB perso
    la numerazione del DB riparte da 1 e il giro nuovo sovrascriverebbe un report committato."""
    folder = f"{approvals.REVIEWS_DIR}/{ctx.work['issue']}"
    paths = git.ls_files_at(ctx.wt, "HEAD", f"{folder}/")
    numbers = [int(name[len(kind) + 1:-3]) for name in
               (p.rpartition("/")[2] for p in approvals.report_listing(paths, [folder]))
               if name.startswith(f"{kind}-")]
    return max(numbers, default=0) + 1


def _execute(state, ctx: _Ctx, act: _Act, now) -> PrepareResult:
    conn, wid = ctx.conn, ctx.work["id"]
    if act.supersede is not None:
        audits.supersede(conn, wid, (act.supersede["kind"], act.supersede["number"]), now=now)
    if act.register_spec:
        phases.set_spec_path(conn, wid, act.register_spec, now=now)
    if act.register_plan:
        scope.set_plan_path(conn, wid, act.register_plan, now=now)
    if act.kind == "reprint":
        return _launch(ctx, act.round, act.row["number"], act.row["code"], again=True)
    if act.kind == "open":
        rnd = act.round
        code = secrets.token_hex(4)
        try:
            number = audits.open_round(conn, wid, kind=rnd.kind, sha=rnd.doc_blob,
                                       spec_sha=rnd.spec_blob, viewpoint=rnd.viewpoint,
                                       code=code, now=now,
                                       min_number=_next_report_number(ctx, rnd.kind))
        except ValueError as e:
            raise AuditError(str(e)) from e
        return _launch(ctx, rnd, number, code, again=False)
    if act.kind == "confirm":
        cap = ctx.cfg.get("spec_audit.spec_audit_cycles")
        return PrepareResult(NEEDS_CONFIRM, [
            f"conferma: audit a lenti: da {LENS_MIN_CYCLES} a {cap} cicli di "
            f"{audits.AGENTS[LENS_KIND]}, più i giri avversariali di conferma",
            f"prossimo passo: {CONFIRM_STEP.replace('<programma>', _prog())}"])
    if act.kind == "approve_spec":
        return PrepareResult(OK, ["audit della spec concluso",
                                  f"prossimo passo: {_step_text('approve_spec', fette=act.slices)}"])
    if act.kind == "advance":
        phases.set_phase(conn, state, wid, "approval", "audit_clean", now=now)
        return PrepareResult(OK, ["audit del piano concluso: fase approval",
                                  f"prossimo passo: {_step_text('approve_plan')}"])
    return PrepareResult(OK, [f"prossimo passo: {_step_text('approve_plan')}"])


def prepare(state, cwd, *, confirm: bool, now=None) -> PrepareResult:
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        raise AuditError(str(e)) from e
    try:
        ctx = _context(state, conn, Path(cwd), confirm)
        return _execute(state, ctx, _decide(ctx), now)
    except _Refuse as r:
        if r.supersede is not None:
            try:
                audits.supersede(conn, ctx.work["id"], (r.supersede["kind"],
                                                        r.supersede["number"]), now=now)
            except sqlite3.Error as e:
                raise AuditError(str(e)) from e
        return PrepareResult(REFUSED, r.lines())
    except ERRORS as e:
        raise AuditError(str(e)) from e
    finally:
        conn.close()


def decline(state, cwd, *, now=None) -> tuple[int, list[str]]:
    """Il no dell'utente al costo dell'audit a lenti: apre `needs_you` con `DECLINE_REASON`.
    Vale in `spec_audit`, con più di una fetta, con l'audit a lenti acceso e senza nessun ciclo
    a lenti già fatto o rifiutato."""
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        raise AuditError(str(e)) from e
    try:
        ctx = _context(state, conn, Path(cwd), False)
        wid = ctx.work["id"]
        if ctx.work["phase"] != "spec_audit":
            raise _Refuse(f"{_prog()} audit decline vale in spec_audit "
                          f"(fase {ctx.work['phase']})")
        if not on(ctx.cfg, LENS_KIND):
            raise _Refuse("l'audit a lenti è spento: non c'è nulla da rifiutare")
        if specdoc.slices(_spec_doc(ctx)[2]) <= 1:
            raise _Refuse("la spec ha una sola fetta: l'audit a lenti non si applica")
        if audits.any_rows(conn, wid, LENS_KIND) or LENS_KIND in audits.suspended(conn, wid):
            raise _Refuse("l'audit a lenti è già cominciato o già sospeso: non si rifiuta più")
        block = phases.open_block(conn, state, wid, "needs_you", audits.DECLINE_REASON, now=now)
        return OK, [f"audit a lenti rifiutato dall'utente: blocco {block} aperto",
                    f"prossimo passo: {_step_text('resolve', id=block)}"]
    except _Refuse as r:
        return REFUSED, r.lines()
    except ERRORS as e:
        raise AuditError(str(e)) from e
    finally:
        conn.close()


def peek(conn, work: sqlite3.Row) -> str:
    """Il passo di `prepare` senza scritture né giri aperti (decisione 20), per `next_step`.
    Mai un'eccezione: se qualcosa non si può leggere, «lancia <programma> audit prepare»."""
    fallback = f"lancia {_prog()} audit prepare"
    try:
        phase = work["phase"]
        if phase == "approval":
            fallback = _step_text("approve_plan")
        if work["level"] != "L2" or phase not in ("spec_audit", "plan", "approval") \
                or not work["worktree"]:
            return fallback
        wt = Path(work["worktree"])
        if not wt.is_dir():
            return fallback
        main = git.main_worktree(wt)
        base = work["work_base_sha"] or git.default_ref(main)
        head = git.head(wt)
        if not base or head is None:
            return fallback
        ctx = _Ctx(conn, wt, work, config.load_config_at(main, base), head, base)
        act = _decide(ctx)
    except _Refuse as r:
        return r.hint()
    except ERRORS:
        return fallback
    if act.kind == "approve_spec":
        return _step_text("approve_spec", fette=act.slices)
    if act.kind == "approve_plan":
        return _step_text("approve_plan")
    if act.kind == "confirm":
        return CONFIRM_STEP.replace("<programma>", _prog())
    return fallback
