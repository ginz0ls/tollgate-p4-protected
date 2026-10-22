"""Il calcolo del gate (spec 9.2, decisione 3): l'unico punto in cui si decidono le voci rosse e
quelle di `attenzione`, per `gate evaluate` su GitHub e per `finish check` in locale.

`evaluate(inputs)` costruisce un `Context` (i fatti derivati, calcolati una volta) e lo passa a
ogni famiglia di `FAMILIES`, nell'ordine. Una famiglia è una funzione `(ctx, ev) -> None` che
aggiunge voci a `ev`: per aggiungere una famiglia basta una funzione in più nell'elenco, senza
toccare le altre. Puro: legge solo git (il repo di `inputs`) e i dati ricevuti."""
from __future__ import annotations

import difflib
import posixpath
import re
import tomllib
from functools import cached_property

from tollgate_analysis import (approvals, globs, level as levelmod, mustcheck, plan as planmod,
                               prref, profiles as profmod, protected, waivers, workflows)
from tollgate_analysis.testguard import Violation
from tollgate_core import diffcheck, git, runner
from tollgate_core.config import output_excludes

from . import l2tree
from .model import (BASE_FROM_RUN, GITHUB, CommandResult, Evaluation, GateInputs, Item)

MAX_PLAN_DIFF_LINES = 200
# Le voci della DoD che il gate ricalcola: quella dichiarata nel blocco non conta (decisione 11).
RECOMPUTED_DOD = ("receipt", "guard_scope", "must_have", "approvals")
_BLOCKING_SEVERITIES = ("blocker", "major")
_FINDING_ID = re.compile(r"^f-(\d+)-\d+$")
_BLOB = re.compile(r"^[0-9a-f]{40,64}$")
_AUDIT_PARTS = {"adversarial": "avversario", "lens": "lenti"}
_FINGERPRINT = ".github/tollgate/FINGERPRINT"
_RANK = {"green": 0, "empty": 1, "uncounted": 2, "red": 3}
_WAIVER_KEYS = {"test": "waiver_test", "ci": "waiver_ci", "threshold": "waiver_threshold",
                "command": "waiver_command"}


def pr_issue_number(pr) -> int | None:
    """L'issue di una PR (decisione 8), l'unica regola: dal ramo `tg/<N>-*` (non da un fork),
    altrimenti da «Closes #N»."""
    branch = None if pr.cross_repo else prref.issue_from_branch(pr.head_ref)
    return branch or prref.closes_issue(pr.body)


class Context:
    """I fatti che più famiglie leggono, calcolati una sola volta."""

    def __init__(self, inputs: GateInputs):
        self.inputs = inputs
        self.cfg = inputs.cfg
        self.components: dict[str, bool] = dict(inputs.cfg.get("components"))

    @property
    def is_github(self) -> bool:
        return self.inputs.where == GITHUB

    @cached_property
    def is_work(self) -> bool:
        """La PR di un lavoro di tollgate: un ramo `tg/<N>-*` dello stesso repo (da un fork il nome
        lo sceglie chi apre la PR, decisione 4; in locale, il lavoro corrente)."""
        pr = self.inputs.pr
        if pr is None:
            return self.inputs.block is not None
        return prref.is_tg_branch(pr.head_ref) and not pr.cross_repo

    @cached_property
    def issue_no(self) -> int | None:
        """L'issue della PR (decisione 8): dal ramo `tg/<N>-*`, altrimenti da «Closes #N». In
        locale, senza PR, dal blocco o dall'issue letta."""
        i = self.inputs
        if i.pr is not None:
            return pr_issue_number(i.pr)
        if i.block and isinstance(i.block.get("issue"), int):
            return i.block["issue"]
        return i.issue.number if i.issue else None

    @cached_property
    def waiver_issue(self) -> int | None:
        """L'issue le cui deroghe valgono: `issue_no` se l'issue è valida (decisione 8), altrimenti
        `None` e nessuna deroga si applica."""
        n, i = self.issue_no, self.inputs
        if n is None:
            return None
        if i.issue is None:
            return None if self.is_github else n
        if i.issue.number != n or i.issue.state != "open" or i.issue.is_pr:
            return None
        if i.pr is not None and self.is_work:
            if prref.closes_issue(i.pr.body) != n or (
                    i.block is not None and i.block.get("issue") != n):
                return None
        return n

    @cached_property
    def waiver_file(self) -> waivers.WaiverFile | None:
        """Il file delle deroghe dell'issue, solo se è dell'issue giusta e (con una PR) del ramo
        della PR (8.3)."""
        i = self.inputs
        if i.waiver_text is None or self.waiver_issue is None:
            return None
        try:
            wf = waivers.parse(i.waiver_text)
        except ValueError:
            return None
        if wf.issue != self.waiver_issue or (i.pr is not None and wf.branch != i.pr.head_ref):
            return None
        return wf

    @cached_property
    def level(self) -> str:
        """Il livello dichiarato; senza blocco `L1` (nessun controllo di livello qui)."""
        block = self.inputs.block
        return block["level"] if block and isinstance(block.get("level"), str) else "L1"

    @cached_property
    def changes(self) -> list[git.Change]:
        i = self.inputs
        return git.changes(i.repo, i.base_sha, head=i.head_sha,
                           exclude=output_excludes(self.cfg))

    @cached_property
    def files(self) -> list[str]:
        """I file toccati e non cancellati: da qui i profili attivi, come in locale."""
        return [c.path for c in self.changes if c.status != "D"]

    @cached_property
    def is_config_branch(self) -> bool:
        """La PR di aggiornamento di tollgate: un ramo `tollgate-config/*` dello stesso repo (da
        un fork il nome lo sceglie chi apre la PR: vale come ramo qualunque, rilievo M-7)."""
        pr = self.inputs.pr
        return pr is not None and not pr.cross_repo and prref.is_config_branch(pr.head_ref)

    @cached_property
    def diff_level(self) -> str:
        """Il livello che viene dal solo diff (soglie di L0 e percorsi sensibili)."""
        i, cfg = self.inputs, self.cfg
        lv = cfg.get("levels")
        size = git.diff_size(i.repo, i.base_sha, head=i.head_sha, exclude=output_excludes(cfg))
        return levelmod.diff_level(
            [levelmod.FileChange(c.path, c.added, c.removed, c.binary, c.status, c.old_path)
             for c in self.changes],
            diff_bytes=size, sensitive_paths=lv["sensitive_paths"],
            l0_max_files=lv["l0_max_files"], l0_max_lines=lv["l0_max_lines"],
            l0_max_bytes=lv["l0_max_bytes"])

    @cached_property
    def min_level(self) -> str:
        """Il livello minimo, come lo calcola `open-pr`: il massimo tra diff, etichette
        dell'issue e `min_level` dei profili attivi (anche per i file cancellati)."""
        cfg, issue = self.cfg, self.inputs.issue
        paths = [c.path for c in self.changes] + [c.old_path for c in self.changes if c.old_path]
        active = profmod.active_profiles(paths, cfg.profiles, cfg.get("profiles.active"))
        return levelmod.max_level(
            self.diff_level,
            levelmod.labels_level(issue.labels if issue else (),
                                  cfg.get("levels.sensitive_labels")),
            profmod.min_level(active, cfg.profiles))

    @cached_property
    def required(self) -> list[runner.CommandSpec]:
        """I comandi che la testa deve avere eseguito: gate globali e dei profili attivi."""
        return runner.gate_commands(self.cfg, self.files)

    @cached_property
    def results(self) -> dict[str, CommandResult]:
        return {r.name: r for r in self.inputs.commands or []}

    @cached_property
    def registered_plan(self) -> str | None:
        """Il testo del piano alla versione registrata (`plan_sha`), se la testa lo contiene
        nella storia; `None` altrimenti."""
        i = self.inputs
        sha = i.block.get("plan_sha") if i.block else None
        if not isinstance(sha, str) or not sha:
            return None
        if not git.object_in_history(i.repo, sha, i.head_sha):
            return None
        return git.blob_text(i.repo, sha)

    @cached_property
    def plan_check(self) -> planmod.PlanCheck | None:
        text = self.registered_plan
        if text is None:
            return None
        cfg = self.cfg
        return planmod.check_plan(
            text, required_sections=cfg.get("plan.required_sections"),
            max_scope_files=cfg.get("plan.max_scope_files"),
            must_have_tests=self.components.get("must_have_tests", True), level=self.level,
            profiles=cfg.profiles, active_always=cfg.get("profiles.active"))

    def approved(self, object_: str) -> bool:
        """Un atto `approve <object_>` nel blocco dichiarato, in qualunque stato."""
        acts = self.inputs.block.get("acts") if self.inputs.block else None
        return any(isinstance(a, dict) and a.get("type") == "approve"
                   and a.get("object") == object_ for a in acts or [])


def _red(ev: Evaluation, key: str, family: str, text: str, data: str = "") -> None:
    ev.red.append(Item(key, family, text, data))


def _attention(ev: Evaluation, key: str, family: str, text: str, data: str = "") -> None:
    ev.attention.append(Item(key, family, text, data))


def components_off(ctx: Context, ev: Evaluation) -> None:
    """Ogni componente spento nella configurazione del predefinito (decisione 23)."""
    off = [k for k, v in ctx.components.items() if v is False]
    if off:
        _attention(ev, "components_off", "components",
                   "componenti spenti sul ramo predefinito: " + ", ".join(off))


# --- comandi -------------------------------------------------------------------------------

def _command_state(spec: runner.CommandSpec, r: CommandResult, allow_no_tests: bool) -> str:
    """Lo stato dichiarato e quello ricalcolato da uscita e JUnit: vale il peggiore (un `|| true`
    con un fallito nel report è rosso, 8.1)."""
    if r.state == "unverified":
        return "unverified"
    recomputed = runner.receipt_state(
        exit_code=-1 if r.exit is None else r.exit, report_configured=bool(spec.report),
        junit=r.junit, allow_no_tests=allow_no_tests)
    stated = r.state if r.state in _RANK else "red"
    return max(stated, recomputed, key=_RANK.__getitem__)


def commands(ctx: Context, ev: Evaluation) -> None:
    """Spec 8.1 e 9.2: ogni comando richiesto ha un risultato verde; `empty` e `uncounted` solo
    con `allow_no_tests`, `unverified` solo con `approve unverified-tests` dichiarato. Un
    `setup` rosso (decisione 5) vale come comando rosso."""
    if ctx.inputs.commands is None:
        if ctx.is_github:
            ev.errors.append("risultati dei comandi del gate assenti")
        return
    allow = bool(ctx.cfg.get("project.allow_no_tests"))
    # i nomi del `results.json` li scrive codice della PR: solo quelli della configurazione
    # arrivano nel testo di una voce
    setups = ["setup"] + [f"profile:{p}:setup" for p in ctx.cfg.profiles]
    for name in setups:
        r = ctx.results.get(name)
        if r is not None and r.state == "red":
            _red(ev, "command_red", "commands", f"il comando «{name}» è rosso")
    counted = False
    for spec in ctx.required:
        r = ctx.results.get(spec.name)
        if r is None:
            _red(ev, "command_missing", "commands",
                 f"il comando «{spec.name}» manca: nessun risultato per la testa")
            continue
        state = _command_state(spec, r, allow)
        if state == "green":
            continue
        if state == "unverified":
            if ctx.approved("unverified-tests"):
                _attention(ev, "unverified_tests", "commands",
                           f"il comando «{spec.name}» non è configurato: approvato "
                           f"`approve unverified-tests`")
            else:
                _red(ev, "command_unverified", "commands",
                     f"il comando «{spec.name}» non è configurato (unverified): serve "
                     f"`approve unverified-tests`")
        elif state == "red":
            detail = f" (uscita {r.exit})" if r.exit not in (None, 0) else ""
            if r.junit is not None and r.junit.failed:
                detail += f", {r.junit.failed} test falliti nel report"
            _red(ev, "command_red", "commands", f"il comando «{spec.name}» è rosso{detail}")
        elif runner.counts_green(state, 0, allow):
            counted = True
            _attention(ev, "no_tests_counted", "commands",
                       f"il comando «{spec.name}» ({state}) vale verde solo per allow_no_tests")
        elif state == "empty":
            _red(ev, "command_empty", "commands",
                 f"il comando «{spec.name}» non ha eseguito nessun test")
        else:
            _red(ev, "command_uncounted", "commands",
                 f"il comando «{spec.name}» non ha un report: i test non sono contati")
    if allow and not counted:
        _attention(ev, "allow_no_tests", "commands", "allow_no_tests è acceso")


# --- identificativi della base --------------------------------------------------------------

def base_path(test_id: str) -> str:
    """Il file di un identificativo `classname::name`: il `classname` se contiene `/`; altrimenti
    il modulo con i punti, come percorso `.py` (senza le classi in coda: i segmenti che
    cominciano con una maiuscola, come `tests.test_x.TestFoo`)."""
    classname = test_id.partition("::")[0]
    if "/" in classname:
        return classname
    parts = classname.split(".")
    while len(parts) > 1 and parts[-1][:1].isupper():
        parts.pop()
    return "/".join(parts) + ".py"


def base_ids(ctx: Context, ev: Evaluation) -> None:
    """Gli identificativi della base, per comando (decisione 12, criteri 10 e 32): ogni test
    eseguito e non saltato nella base deve esserlo anche nella testa, salvo deroghe `test` che
    li elencano tutti. Solo su GitHub e con il componente `base_test_ids` acceso."""
    i = ctx.inputs
    if not ctx.is_github or not ctx.components.get("base_test_ids", True):
        return
    if i.base_ids is None:
        ev.errors.append("identificativi della base non disponibili")
        return
    if i.commands is None:
        return      # l'errore lo dà `commands`
    if i.base_ids_source == BASE_FROM_RUN:
        _attention(ev, "base_ids_from_run", "base_ids",
                   "gli identificativi della base vengono da un run della PR, non dalla cache")
    missing_by_path: dict[str, set[str]] = {}
    failing: set[str] = set()
    for spec in ctx.required:
        r = ctx.results.get(spec.name)
        if r is None or r.junit is None:
            continue
        base = set(i.base_ids.get(spec.name, ()))
        executed = runner.executed_ids(r.junit)
        for tid in base - executed:
            missing_by_path.setdefault(base_path(tid), set()).add(tid)
        failing |= base & set(r.junit.ids_failed)
    found = [Violation("base_id_missing", path, "test della base mancanti nella testa", "test",
                       tuple(sorted(ids)))
             for path, ids in sorted(missing_by_path.items())]
    for v in waivers.unresolved(found, ctx.waiver_file):
        _red(ev, "base_id_missing", "base_ids",
             f"{len(v.ids)} test della base non sono eseguiti nella testa (uno saltato conta "
             f"come mancante)", f"{v.path}: " + ", ".join(v.ids))
    if failing:
        _attention(ev, "base_failing_on_head", "base_ids",
                   f"{len(failing)} test della base falliscono sulla testa",
                   ", ".join(sorted(failing)))


# --- diff: test-guard, scope, piano ---------------------------------------------------------

def _text_diff(old: str, new: str, old_name: str, new_name: str) -> str:
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), old_name, new_name,
                                      lineterm=""))
    if len(lines) > MAX_PLAN_DIFF_LINES:
        lines = lines[:MAX_PLAN_DIFF_LINES] + ["…"]
    return "\n".join(lines)


def _plan_diff(registered: str, head: str) -> str:
    return _text_diff(registered, head, "registrato", "testa")


def _over_l0(ctx: Context) -> bool:
    """Il diff supera le soglie di L0 (file, righe, byte) o tocca un percorso sensibile."""
    return ctx.diff_level != "L0"


def _scope(ctx: Context, ev: Evaluation) -> tuple[set[str] | None, set[str], tuple | None,
                                                  tuple | None]:
    """`(scope, locked, registered_plan, approved_spec)` per `diffcheck`. Solo la PR di un lavoro
    con un blocco ha uno scope: quello del piano alla versione registrata (decisione 9)."""
    i, block = ctx.inputs, ctx.inputs.block
    if not ctx.is_work or block is None:
        return None, set(), None, None
    plan_sha, plan_path = block.get("plan_sha"), block.get("plan")
    registered = (plan_path, plan_sha) if isinstance(plan_path, str) and plan_path \
        and ctx.registered_plan is not None else None
    if ctx.level == "L0":
        if not plan_sha and _over_l0(ctx):
            _red(ev, "plan_absent", "diff",
                 "nessun piano registrato e il diff supera le soglie di L0")
        return None, set(), registered, None
    if not plan_sha:
        _red(ev, "plan_sha_absent", "diff", "il blocco non dichiara il piano registrato (plan_sha)")
        return None, set(), None, None
    if ctx.plan_check is None:
        _red(ev, "plan_sha_absent", "diff",
             "il piano registrato (plan_sha) non è nella storia della testa")
        return None, set(), None, None
    locked = {plan_path} if registered else set()
    approved = None
    spec_path = block.get("spec")
    if isinstance(spec_path, str) and spec_path and ctx.issue_no is not None:
        found = l2tree.locate(i.repo, i.head_sha, issue=ctx.issue_no, spec_path=spec_path,
                              spec_blob=None)
        if found is not None:
            locked.add(spec_path)
            approved = (spec_path, found[1]["sha"])
    return set(ctx.plan_check.scope), locked, registered, approved


def _plan_changed(ctx: Context, ev: Evaluation, registered: tuple | None) -> None:
    """Il piano in testa è diverso da quello registrato (criterio 36): `attenzione` con il diff,
    solo nel gate (in locale è una violazione di scope, più severa).
    I file che il piano nuovo aggiunge sono fuori scope, perché lo scope resta quello registrato."""
    if registered is None or ctx.registered_plan is None:
        return
    path, sha = registered
    i = ctx.inputs
    if git.blob_at(i.repo, i.head_sha, path) == sha:
        return
    head_text = git.text_at(i.repo, i.head_sha, path) or ""
    _attention(ev, "plan_changed", "diff",
               "il piano in testa è diverso da quello registrato", _plan_diff(ctx.registered_plan,
                                                                               head_text))


def _waiver_items(ctx: Context, ev: Evaluation) -> None:
    """Le deroghe in vigore nel file dell'issue, anche quelle già nella base (8.3, criterio 44)."""
    wf = ctx.waiver_file
    if wf is None:
        return
    sensitive_paths = ctx.cfg.get("levels.sensitive_paths")
    scope_seen = 0
    for w in wf.waivers:
        what = f"deroga {w.id} ({w.type})"
        data = f"{w.file if w.pattern is None else w.pattern}\n{w.choice}\n{w.why}\n{w.cost}"
        if w.pattern is not None:
            _attention(ev, "waiver_pattern", "diff", f"{what} per pattern", data)
        elif w.type == "scope":
            scope_seen += 1
            if scope_seen > waivers.IMMEDIATE_SCOPE or globs.match_any(sensitive_paths, w.file):
                _attention(ev, "waiver_scope_over_two", "diff",
                           f"{what} oltre la seconda o su un file sensibile", data)
            else:
                _attention(ev, "waiver_scope", "diff", what, data)
        else:
            _attention(ev, _WAIVER_KEYS[w.type], "diff", what, data)


def diff(ctx: Context, ev: Evaluation) -> None:
    """test-guard su ogni PR; scope e piano solo per le PR dei lavori (spec 9.2). Le deroghe
    valide sciolgono le violazioni, con le stesse regole di `finish check` in locale: l'unica
    differenza voluta è il piano cambiato dopo la registrazione, che qui è `plan_changed`."""
    if ctx.is_config_branch:
        return      # una PR di configurazione non ha scope né test-guard (9.2, 9.4)
    i = ctx.inputs
    scope, locked, registered, approved = _scope(ctx, ev)
    check = diffcheck.diff_check(
        ctx.cfg, repo=i.repo, issue=ctx.issue_no or 0, level=ctx.level, base_ref=i.base_sha,
        head_ref=i.head_sha, changes=ctx.changes, scope=scope, locked=locked,
        registered_plan=registered, approved_spec=approved, waiver_file=ctx.waiver_file,
        components=ctx.components, plan_change_is_attention=ctx.is_github)
    for v in check.violations:
        # la parte dopo «: » del dettaglio è letta dal codice della PR (identificativi di test,
        # soglie): va in `data`, nel testo resta la frase di tollgate
        said, _, read = v.detail.partition(": ")
        _red(ev, v.kind, "diff", f"{said} ({v.waiver_type})", f"{v.path}\n{read}" if read else v.path)
    ev.watch = list(check.watched)
    if ctx.is_github:
        _plan_changed(ctx, ev, registered)
    _waiver_items(ctx, ev)


# --- must-have ------------------------------------------------------------------------------

def must_have(ctx: Context, ev: Evaluation) -> None:
    """I must-have del piano registrato, ricalcolati dal JUnit della testa (spec 8.7, criterio
    42). Solo per le PR dei lavori in L1 e L2, con il componente `must_have_tests` acceso."""
    if not ctx.components.get("must_have_tests", True) or not ctx.is_work \
            or ctx.level == "L0" or ctx.plan_check is None or ctx.inputs.commands is None:
        return
    ids_run: set[str] = set()
    ids_failed: set[str] = set()
    for r in ctx.results.values():
        if r.junit is not None:
            ids_run.update(r.junit.ids_run)
            ids_failed.update(r.junit.ids_failed)
    res = mustcheck.check(ctx.plan_check.must_haves, ids_run | ids_failed, ids_failed)
    if res.missing:
        _red(ev, "must_have_missing", "must_have",
             f"{len(res.missing)} test dei must-have non sono nel report della testa",
             "; ".join(res.missing))
    if res.failed:
        _red(ev, "must_have_failed", "must_have",
             f"{len(res.failed)} test dei must-have falliscono nella testa", "; ".join(res.failed))
    if res.manual:
        _attention(ev, "manual_must_have", "must_have",
                   f"must-have con test manuale: {len(res.manual)}", ", ".join(res.manual))


# --- livello e L2 ---------------------------------------------------------------------------

def level(ctx: Context, ev: Evaluation) -> None:
    """Livello dichiarato contro minimo (spec 5, 9.2, criterio 22): rosso se è sotto il minimo
    senza un tetto dichiarato; `level_cap` («da leggere») ogni volta che il blocco dichiara un
    tetto. Solo per le PR dei lavori."""
    block = ctx.inputs.block
    if block is None or not ctx.is_work:
        return
    declared = block.get("level")
    if declared not in levelmod.LEVELS:
        _red(ev, "level_invalid", "level", "livello dichiarato nel blocco non valido")
        return
    minimum = ctx.min_level
    below = levelmod.LEVELS.index(declared) < levelmod.LEVELS.index(minimum)
    if block.get("level_cap") in levelmod.LEVELS:
        _attention(ev, "level_cap", "level",
                   f"livello dichiarato {declared} sotto il minimo {minimum}, con un tetto "
                   f"dichiarato" if below else f"tetto di livello dichiarato ({declared})",
                   str(block.get("level_cap_reason") or ""))
    elif below:
        _red(ev, "level_below_minimum", "level",
             f"livello dichiarato {declared} sotto il minimo {minimum}")


def _path(value) -> str | None:
    return value if isinstance(value, str) and value else None


def _old_blob_text(ctx: Context, sha) -> str | None:
    """Il testo di un blob approvato che sta nella storia della testa; `None` altrimenti."""
    i = ctx.inputs
    if not isinstance(sha, str) or not _BLOB.match(sha) \
            or not git.object_in_history(i.repo, sha, i.head_sha):
        return None
    return git.blob_text(i.repo, sha)


def _stale_diffs(ctx: Context, files: dict[str, str], *, issue: int, spec: tuple,
                 plan: tuple) -> list[str]:
    """Il diff tra il testo approvato e quello in testa, per la spec e per il piano la cui
    approvazione è superata. `spec` e `plan` sono `(percorso, blob in testa)`."""
    i = ctx.inputs
    out = []
    if spec[0] and spec[1]:
        judged = approvals.judge_spec(files, issue=issue, spec_path=spec[0], spec_blob=spec[1])
        if judged.status == approvals.STALE and judged.approval is not None:
            out.append((spec[0], judged.approval[1]["sha"], spec[1]))
    plan_header = approvals.parse_approval(files.get(approvals.approval_paths(issue)[1], ""))
    if plan[0] and plan[1] and plan_header is not None and plan_header["kind"] == "plan-approval" \
            and plan_header["path"] == plan[0] and not approvals.is_current(plan_header, plan[1]):
        out.append((plan[0], plan_header["sha"], plan[1]))
    diffs = []
    for path, approved, current in out:
        old = _old_blob_text(ctx, approved)
        new = git.blob_text(i.repo, current)
        diffs.append(f"{path}\n" + (_text_diff(old, new or "", "approvato", "testa")
                                    if old is not None else "diff non disponibile"))
    return diffs


def l2(ctx: Context, ev: Evaluation) -> None:
    """File di approvazione e report di L2 (decisione 10, criteri 10 e 35), letti dall'albero
    della testa. Mancanti o non validi: rosso. Superati (`sha` diverso dalla testa) o in una
    cartella diversa da `spec_reviews_dir`: `approval_stale` con il diff. L'audit della spec
    spento o sospeso nel blocco: `audit_off` e `audit_suspended`."""
    block = ctx.inputs.block
    if block is None or not ctx.is_work or ctx.level != "L2":
        return
    audit = block.get("spec_audit")
    if isinstance(audit, dict):
        for state, key, label in (("off", "audit_off", "spento"),
                                  ("suspended", "audit_suspended", "sospeso")):
            parts = [name for name in _AUDIT_PARTS if audit.get(name) == state]
            if parts:
                _attention(ev, key, "l2", f"audit della spec {label}: "
                           + ", ".join(_AUDIT_PARTS[n] for n in parts))
    issue = ctx.issue_no
    if issue is None:
        return
    i = ctx.inputs
    spec_path, plan_path = _path(block.get("spec")), _path(block.get("plan"))
    spec_blob = git.blob_at(i.repo, i.head_sha, spec_path) if spec_path else None
    plan_blob = git.blob_at(i.repo, i.head_sha, plan_path) if plan_path else None
    files, found = l2tree.collect(i.repo, i.head_sha, issue=issue, spec_path=spec_path,
                                  spec_blob=spec_blob)
    problems = approvals.check_l2_detail(
        files, issue=issue, spec_path=spec_path, spec_blob=spec_blob, plan_path=plan_path,
        plan_blob=plan_blob, components=ctx.components)
    missing = [p.text for p in problems if p.kind == approvals.MISSING]
    stale = [p.text for p in problems if p.kind == approvals.STALE]
    if missing:
        _red(ev, "l2_missing", "l2",
             f"{len(missing)} {'problema' if len(missing) == 1 else 'problemi'} nei file di "
             f"approvazione e nei report di L2", "\n".join(missing))
    declared_dir = block.get("spec_reviews_dir")
    if found is not None and isinstance(declared_dir, str) \
            and declared_dir.rstrip("/") != found[0].rpartition("/")[0]:
        stale.append(f"spec_reviews_dir dichiarata {declared_dir}, ma l'approvazione della spec "
                     f"è in {found[0].rpartition('/')[0]}/")
    if stale:
        diffs = _stale_diffs(ctx, files, issue=issue, spec=(spec_path, spec_blob),
                             plan=(plan_path, plan_blob))
        _attention(ev, "approval_stale", "l2",
                   "approvazione di L2 superata: spec o piano cambiati dopo l'approvazione, o "
                   "report in un'altra cartella", "\n".join(stale + diffs))


# --- issue, blocco, rilievi e DoD dichiarata ------------------------------------------------

def _config_keys(old: str | None, new: str | None) -> list[str]:
    """Le chiavi (puntate) di due testi TOML con valore diverso o presenti in uno solo."""
    def flat(text: str | None) -> dict | None:
        if text is None:
            return {}
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return None
        out, stack = {}, [("", data)]
        while stack:
            prefix, table = stack.pop()
            for k, v in table.items():
                if isinstance(v, dict):
                    stack.append((f"{prefix}{k}.", v))
                else:
                    out[f"{prefix}{k}"] = v
        return out
    before, after = flat(old), flat(new)
    if before is None or after is None:
        return ["tollgate.toml non leggibile"]
    return sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))


def _fingerprint(ctx: Context, ref: str) -> str:
    text = git.text_at(ctx.inputs.repo, ref, _FINGERPRINT)
    return text.strip()[:100] if text is not None else "assente"


def _config_item(ctx: Context, ev: Evaluation) -> None:
    i = ctx.inputs
    keys = _config_keys(git.text_at(i.repo, i.base_sha, "tollgate.toml"),
                        git.text_at(i.repo, i.head_sha, "tollgate.toml"))
    _attention(ev, "tollgate_config", "issue", "PR di aggiornamento della configurazione di "
               "tollgate (nessun controllo di scope né di test-guard)",
               "tollgate.toml: " + (", ".join(keys) or "nessuna chiave cambiata")
               + f"\nFINGERPRINT: {_fingerprint(ctx, i.head_sha)} "
                 f"(base: {_fingerprint(ctx, i.base_sha)})")


def _issue_state(ev: Evaluation, facts, number: int) -> None:
    if facts is None or facts.number != number:
        _red(ev, "issue_invalid", "issue", f"l'issue #{number} della PR non risulta")
    elif facts.is_pr:
        _red(ev, "issue_invalid", "issue", f"#{number} è una PR, non un'issue")
    elif facts.state != "open":
        _red(ev, "issue_invalid", "issue", f"l'issue #{number} della PR non è aperta")


def issue(ctx: Context, ev: Evaluation) -> None:
    """L'issue della PR e il blocco (spec 9.2, decisioni 6 e 8, criterio 33). Solo nel gate.
    Ramo `tg/<N>-*`: blocco valido, «Closes #N» e `issue` del blocco uguali a N, issue aperta.
    Altri rami: `not_tg_branch`; con «Closes #M» l'issue M aperta, senza `no_issue`.
    Ramo `tollgate-config/*`: la sola voce `tollgate_config`."""
    i = ctx.inputs
    if not ctx.is_github or i.pr is None:
        return
    if ctx.is_config_branch:
        _config_item(ctx, ev)
        return
    closes = prref.closes_issue(i.pr.body)
    if not ctx.is_work:
        _attention(ev, "not_tg_branch", "issue", "PR fuori dai rami tg/*: nessun controllo di "
                   "scope, piano e livello")
        if closes is None:
            _attention(ev, "no_issue", "issue", "la PR non chiude nessuna issue")
        else:
            _issue_state(ev, i.issue, closes)
        return
    number = prref.issue_from_branch(i.pr.head_ref)
    if i.block is None:
        _red(ev, "block_missing", "issue", "blocco JSON di tollgate assente o non valido nel "
             "corpo della PR")
    elif i.block.get("issue") != number:
        _red(ev, "block_issue_mismatch", "issue",
             f"l'issue dichiarata nel blocco non è quella del ramo (#{number})")
    if closes != number:
        _red(ev, "closes_mismatch", "issue",
             f"«Closes #N» del corpo della PR non è quella del ramo (#{number})")
    _issue_state(ev, i.issue, number)


def _finding_cycle(finding: dict) -> int | None:
    m = _FINDING_ID.match(finding["id"]) if isinstance(finding.get("id"), str) else None
    return int(m.group(1)) if m else None


def _effective_severity(finding: dict) -> str | None:
    """La gravità dopo la decisione dell'utente: `None` se archiviato."""
    decision = finding.get("user_decision")
    if decision is None:
        return finding.get("severity")
    if decision == "dismissed":
        return None
    if isinstance(decision, str) and decision.startswith("downgraded:"):
        return decision.partition(":")[2]
    return finding.get("severity")


def _findings(ctx: Context, ev: Evaluation) -> None:
    """Rilievi (decisione 11): il bloccante dell'ultimo ciclo è rosso anche con
    `verdict.unverified`; quelli archiviati o declassati sotto `major` sono «da leggere»."""
    block = ctx.inputs.block
    findings = _entries(block.get("findings"))
    verdict = block.get("verdict")
    last = verdict.get("cycles") if isinstance(verdict, dict) else None
    blocking, overridden = [], []
    for f in findings:
        if f.get("verification") != "confirmed" or f.get("blocking") is False:
            continue
        severity = _effective_severity(f)
        if severity in _BLOCKING_SEVERITIES:
            # senza un ultimo ciclo leggibile nessun rilievo si scarta (fail-closed)
            if not isinstance(last, int) or _finding_cycle(f) in (None, last):
                blocking.append(str(f.get("id")))
        elif f.get("severity") in _BLOCKING_SEVERITIES:
            overridden.append(f"{f.get('id')}: {f.get('user_decision')}")
    if blocking:
        _red(ev, "finding_blocking", "declared",
             f"{len(blocking)} rilievi bloccanti dell'ultimo ciclo senza `approve finding`",
             ", ".join(blocking))
    if overridden:
        _attention(ev, "findings_overridden", "declared",
                   f"{len(overridden)} rilievi blocker o major archiviati o declassati",
                   "\n".join(overridden))


def declared(ctx: Context, ev: Evaluation) -> None:
    """La DoD e i rilievi dichiarati nel blocco (spec 8.7, decisione 11). Solo nel gate e con il
    componente `definition_of_done` acceso (decisione 23). Le voci che il gate ricalcola
    (`RECOMPUTED_DOD`) prevalgono su quelle dichiarate; ogni altra voce `false` è rossa."""
    block = ctx.inputs.block
    if not ctx.is_github or block is None or not ctx.is_work \
            or not ctx.components.get("definition_of_done", True):
        return
    dod = block.get("dod")
    items = dod.get("items") if isinstance(dod, dict) else None
    false = sorted(str(k) for k, v in (items if isinstance(items, dict) else {}).items()
                   if v is False and k not in RECOMPUTED_DOD)
    if false:
        _red(ev, "dod_false", "declared", f"{len(false)} voci della DoD dichiarate false",
             ", ".join(false))
    _findings(ctx, ev)


def _entries(value, *keys) -> list[dict]:
    """Le voci di un elenco del blocco che sono dizionari con tutte le `keys`."""
    return [e for e in value or [] if isinstance(e, dict) and all(k in e for k in keys)] \
        if isinstance(value, list) else []


def notes(ctx: Context, ev: Evaluation) -> None:
    """Voci di `attenzione` che vengono dal blocco e dagli ingressi (solo nel gate):
    `sentinel_open`, `review_unverified`, `off_periods`, `task_over_*` e `skills_absent`
    (decisione 21, criterio 39)."""
    i = ctx.inputs
    if not ctx.is_github:
        return
    if i.sentinel_open:
        _attention(ev, "sentinel_open", "notes",
                   f"merge non verificati segnalati da sentinel: {len(i.sentinel_open)}",
                   ", ".join(str(n) for n in i.sentinel_open))
    block = i.block
    if block is None or not ctx.is_work:
        return
    verdict = block.get("verdict")
    if isinstance(verdict, dict) and verdict.get("unverified"):
        _attention(ev, "review_unverified", "notes",
                   "revisione finale non verificata: rilievi non provati")
    periods = _entries(block.get("off_periods"), "from", "to")
    if periods:
        _attention(ev, "off_periods", "notes",
                   f"periodi con tollgate spento dichiarati: {len(periods)}",
                   "\n".join(f"{p['from']} -> {p['to']}" for p in periods))
    warn, high = ctx.cfg.get("tasks.task_lines_warn"), ctx.cfg.get("tasks.task_lines_max")
    over = [e for e in _entries(block.get("tasks_over"), "task", "lines")
            if isinstance(e["lines"], int)]
    small = [e for e in over if e["lines"] <= high]
    big = [e for e in over if e["lines"] > high]
    if small:
        _attention(ev, "task_over_warn", "notes",
                   f"task oltre {warn} righe: {len(small)}",
                   "\n".join(f"task {e['task']}: {e['lines']} righe" for e in small))
    if big:
        _attention(ev, "task_over_max", "notes",
                   f"task oltre {high} righe: {len(big)}",
                   "\n".join(f"task {e['task']}: {e['lines']} righe: {e.get('size_reason')}"
                             for e in big))
    absent = _entries(block.get("skills_absent"), "task", "skills")
    if absent:
        _attention(ev, "skills_absent", "notes",
                   f"task con skill dei profili segnate come assenti: {len(absent)}",
                   "\n".join(f"task {e['task']}: " + ", ".join(
                       str(skill) for skill in (e["skills"] if isinstance(e["skills"], list)
                                                else [])) for e in absent))


# --- lockfile, workflow, file di tollgate ---------------------------------------------------

def lockfiles(ctx: Context, ev: Evaluation) -> None:
    """Un lockfile cambiato senza il manifest della stessa cartella (spec 9.2)."""
    manifests = ctx.cfg.get("scope.lockfiles")
    touched = {c.path for c in ctx.changes}
    lone = [c.path for c in ctx.changes if c.status != "D"
            and posixpath.basename(c.path) in manifests
            and posixpath.join(posixpath.dirname(c.path),
                               manifests[posixpath.basename(c.path)]) not in touched]
    if lone:
        _attention(ev, "lockfile_without_manifest", "diff",
                   f"lockfile cambiati senza il manifest: {len(lone)}", "\n".join(lone))


def _project_workflow(path: str) -> bool:
    return workflows.is_workflow_path(path) and not protected.is_tollgate_file(path)


def _workflow_problems(ctx: Context, path: str) -> list[str]:
    text = git.text_at(ctx.inputs.repo, ctx.inputs.head_sha, path)
    return workflows.problems(text) if text is not None else ["il file non si legge"]


def workflow_rules(ctx: Context, ev: Evaluation) -> None:
    """I workflow del progetto (decisione 15): quelli cambiati con una deroga `ci` che li copre
    sono `ci_waived_workflow`; nel gate quelli già presenti che violano le regole di `guard` (che
    controlla solo i cambiati) sono la voce informativa `existing_workflow_rules`."""
    i = ctx.inputs
    changed = [c.path for c in ctx.changes if c.status != "D" and _project_workflow(c.path)]
    wf = ctx.waiver_file
    if wf is not None:
        waived = [p for p in changed if any(
            waivers.covers(w, Violation("ci_changed", p, "", "ci")) for w in wf.waivers)]
        if waived:
            _attention(ev, "ci_waived_workflow", "workflows",
                       f"workflow del progetto modificati con una deroga ci: {len(waived)}",
                       "\n".join(waived))
    if not ctx.is_github:
        return
    touched = {c.path for c in ctx.changes}
    found = {}
    for path in git.ls_files_at(i.repo, i.head_sha, ".github/workflows/"):
        if _project_workflow(path) and path not in touched:
            found[path] = _workflow_problems(ctx, path)
    found = {p: probs for p, probs in found.items() if probs}
    if found:
        _attention(ev, "existing_workflow_rules", "workflows",
                   f"workflow del progetto già presenti che violano le regole di guard: "
                   f"{len(found)}",
                   "\n".join(f"{p}: {m}" for p, probs in sorted(found.items()) for m in probs))


def tollgate_files_in_work(changes) -> list[str]:
    """I file di tollgate (anche col vecchio nome, se spostati) tra `changes`, ordinati."""
    return sorted({p for c in changes for p in (c.path, c.old_path)
                   if p and protected.is_tollgate_file(p)})


def tollgate_files_changed(repo, base_ref: str, head_ref: str) -> list[str]:
    """I file di tollgate diversi tra `base_ref` (la punta del ramo predefinito) e `head_ref`, per
    insieme di percorsi e blob: aggiunti, cambiati, cancellati o spostati (9.2, `gate guard`)."""
    return tollgate_files_in_work(git.changes(repo, base_ref, head=head_ref))


def guard_local(ctx: Context, ev: Evaluation) -> None:
    """File di tollgate e workflow del progetto, solo in locale: su GitHub li controlla `gate
    guard` (decisione 3, spec 9.2)."""
    if ctx.is_github:
        return
    paths = tollgate_files_in_work(ctx.changes)
    if paths:
        _red(ev, "guard_local", "guard_local",
             f"file di tollgate modificati rispetto alla base del lavoro: {len(paths)}",
             "\n".join(paths))
    bad = [f"{c.path}: {m}" for c in ctx.changes
           if c.status != "D" and _project_workflow(c.path)
           for m in _workflow_problems(ctx, c.path)]
    if bad:
        _red(ev, "guard_workflow", "guard_local",
             f"workflow del progetto che violano le regole di guard: {len(bad)}", "\n".join(bad))


FAMILIES = (components_off, commands, base_ids, diff, must_have, level, l2, issue, declared,
            notes, lockfiles, workflow_rules, guard_local)


def evaluate(inputs: GateInputs) -> Evaluation:
    """Il giudizio sul gate: voci rosse, voci di `attenzione`, file osservati ed errori. Un
    errore di git o di lettura è un `error` con il motivo, mai un traceback."""
    ev = Evaluation()
    ctx = Context(inputs)
    for family in FAMILIES:
        try:
            family(ctx, ev)
        except git.GitError as e:
            ev.errors.append(f"{family.__name__}: {e}")
    return ev
