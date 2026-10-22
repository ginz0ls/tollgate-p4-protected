"""`tollgate finish check` (spec 6.4, decisioni 3 e 20 di P4): la copia locale del gate.

Esegue il gate e i `dod` dei profili, poi chiama lo stesso calcolo del gate su GitHub
(`tollgate_gate.evaluate`, con `where="local"`) e stampa la DoD voce per voce: `guard_scope` viene
dalla famiglia `diff`, `must_have` da `must_have`, `approvals` da `l2`. Le altre voci rosse del
gate (livello, file di tollgate) fermano il lavoro, quelle di `attenzione` si stampano. Verde: fase
`review`. Rosso: la fase resta com'è."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from tollgate_analysis import prblock, waivers
from tollgate_core import (acts, clock, config, db, dod, events, git, phases, receipts,
                           sessions, verify)
from tollgate_core.paths import program_command
from tollgate_gate import attention, evaluate
from tollgate_gate.model import LOCAL, CommandResult, GateInputs, IssueFacts, Item

from . import gitw, prstate

OK, RED, REFUSED = 0, 1, 2
SKIP = ("findings", "specialists")      # si valutano dopo la revisione (decisione 15)
MAX_LISTED = 5
MANUAL = "manual_must_have"
# Le famiglie del gate che la DoD mostra come sue voci: il resto si stampa a parte.
FOLDED = {"diff": "guard_scope", "must_have": "must_have", "l2": "approvals"}


@dataclass
class CheckResult:
    code: int
    lines: list[str]
    items: list[dod.DodItem] = field(default_factory=list)


def _refuse(*lines: str) -> CheckResult:
    return CheckResult(REFUSED, [f"rifiuto: {x}" for x in lines])


def _label(key: str) -> str:
    return dod.LABELS.get(key) or f"Voce del profilo {key.removeprefix('profile:')}"


def _line(item: dod.DodItem, details: dict[str, str]) -> str:
    if item.ok is None and item.detail == dod.SKIPPED_DETAIL:
        return f"[dopo la revisione] {item.label}"
    detail = item.detail or details.get(item.key, "")
    return f"[{'sì' if item.ok else 'no'}] {item.label}" + (f": {detail}" if detail else "")


def _next_step(level: str, ok: bool) -> str:
    prog = program_command(db.BIN_PATH)
    if not ok:
        return f"prossimo passo: correggi le voci [no] e rilancia {prog} finish check"
    return f"prossimo passo: {prog} " + ("finish open-pr" if level == "L0" else "review prepare")


def check(state, cwd, *, now=None, environ=None) -> CheckResult:
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        return _refuse(str(e))
    try:
        return _check(state, conn, Path(cwd), now, environ)
    except (sqlite3.Error, phases.TransitionError, config.ConfigError, git.GitError,
            OSError) as e:
        return _refuse(str(e))
    finally:
        conn.close()


def _check(state, conn, cwd: Path, now, environ) -> CheckResult:
    work = sessions.work_for_path(conn, cwd)
    if work is None:
        return _refuse("nessun lavoro attivo per questa cartella: lancia il comando dal "
                       "worktree del lavoro")
    wt = Path(work["worktree"])
    seen = prstate.detect(state, conn, work, git.main_worktree(wt), now=now)
    if seen.kind == "merged":
        return _refuse(f"la PR #{seen.pr.get('number')} è stata unita: il lavoro è chiuso")
    if seen.kind == "closed":
        return _refuse(prstate.closed_line(seen.pr))
    if work["phase"] not in ("execution", "review"):
        return _refuse(f"la fase è {work['phase']}: `finish check` si usa in execution (o in "
                       "review, per ripeterlo)")
    sha = git.head(wt)
    if sha is None:
        return _refuse("nessun commit da verificare")
    if work["phase"] == "review" and work["finish_sha"] == sha and work["finish_report"]:
        saved = _saved(work, sha)
        if seen.error:
            saved.lines.insert(0, f"avviso: {seen.error}")
        return saved

    lines: list[str] = [f"avviso: {seen.error}"] if seen.error else []
    if not gitw.fetch(wt):
        lines.append("avviso: git fetch origin non riuscito (senza rete?): si prosegue con i "
                     "riferimenti locali")
    level = work["level"]
    if level != "L0":
        open_tasks = [str(r["number"]) for r in conn.execute(
            "SELECT number, state, verdict FROM tasks WHERE work = ? ORDER BY number",
            (work["id"],)) if r["state"] != "done" or r["verdict"] != "approved"]
        if open_tasks:
            return _refuse("task non chiusi con verdetto approved: " + ", ".join(open_tasks))

    base = work["work_base_sha"] or git.default_ref(wt)
    if base is None:
        return _refuse("nessun riferimento remoto da cui leggere tollgate.toml")
    cfg = config.load_config(state, wt, base, env=environ)
    files = [c.path for c in git.changes(wt, base, head=sha) if c.status != "D"]
    extra = verify.dod_commands(cfg, files)
    required = [s.name for s in verify.gate_commands(cfg, files) + extra]

    run = verify.run_gate(state, cwd, produced_by="finish", extra=extra, now=now,
                          environ=environ)
    if run.sha is None:
        return _refuse(*run.lines)
    sha = run.sha
    lines += run.lines
    wid = work["id"]
    details: dict[str, str] = {}

    inputs = _gate_inputs(state, conn, work, cfg, wt, sha, run, now=now, environ=environ,
                          warnings=lines)
    ev = evaluate.evaluate(inputs)
    if ev.errors:
        return _refuse(*ev.errors)
    red = _by_family(ev.red)
    external = {"guard_scope": "diff" not in red}
    if "diff" in red:
        details["guard_scope"] = _listed(red["diff"])
    manual: list[str] = []
    if level != "L0":
        external["must_have"] = "must_have" not in red
        if "must_have" in red:
            details["must_have"] = " | ".join(_said(i) for i in red["must_have"])
        manual = [m for i in ev.attention if i.key == MANUAL for m in i.data.split(", ")]
    if level == "L2":
        stale = [i for i in ev.attention if i.key == "approval_stale"]
        external["approvals"] = "l2" not in red and not stale
        if not external["approvals"]:
            details["approvals"] = "; ".join(_head_lines([*red.get("l2", []), *stale]))

    allow_unverified = acts.has_approval(conn, wid, "unverified-tests")
    allow_no_tests = cfg.get("project.allow_no_tests")
    profile_items, why = profile_receipts(conn, wid, sha, extra, allow_no_tests,
                                          allow_unverified)
    details.update(why)

    items = dod.compute_dod(conn, wid, head_sha=sha, allow_no_tests=allow_no_tests,
                            required_commands=required, external=external,
                            profile_items=profile_items, allow_unverified=allow_unverified,
                            skip=SKIP)
    green = dod.dod_passes([i for i in items if i.key not in SKIP]) and not ev.red
    lines += [_line(i, details) for i in items]
    lines += [f"rosso: {_said(i)}" for i in ev.red if i.family not in FOLDED]
    if manual:
        lines.append("da leggere: must-have con test manuale: " + ", ".join(manual))
    lines += _attention_lines([i for i in ev.attention if i.key != MANUAL])

    if green:
        gate = {"red": _keys(ev.red), "attention": _keys(ev.attention)}
        phases.set_finish(conn, wid, sha, {"items": {i.key: i.ok for i in items},
                                           "manual": manual, "gate": gate}, now=now)
        if work["phase"] == "execution":
            phases.set_phase(conn, state, wid, "review", "finish_check_green", now=now)
    events.record_event(conn, "finish_check", {"sha": sha, "ok": green}, now=now, work=wid)
    lines.append(_next_step(level, green))
    return CheckResult(OK if green else RED, lines, items)


def profile_receipts(conn, wid: int, sha: str, extra, allow_no_tests: bool,
                     allow_unverified: bool) -> tuple[dict[str, bool], dict[str, str]]:
    """Le voci `dod` dei profili attive dalle ricevute su `sha` (anche per `open-pr`) e, per
    quelle non verdi, il motivo."""
    items: dict[str, bool] = {}
    details: dict[str, str] = {}
    for spec in extra:
        rows = [r for r in receipts.latest(conn, wid, sha) if r["command"] == spec.name]
        items[spec.name], why = dod.receipt_verdict(rows, sha, allow_no_tests, [spec.name],
                                                    allow_unverified)
        if not spec.command and not items[spec.name]:
            why = (f"il comando «{spec.name.rsplit(':', 1)[-1]}» non è in [commands]: "
                   "dichiaralo, oppure serve /tollgate:approve unverified-tests")
        if why:
            details[spec.name] = why
    return items, details


def _gate_inputs(state, conn, work, cfg, wt: Path, sha: str, run, *, now, environ,
                 warnings: list[str] | None = None) -> GateInputs:
    """Gli ingressi del calcolo del gate per il lavoro in locale (decisione 20): la configurazione
    della base del lavoro, le ricevute di questa esecuzione di `verify.run_gate` (`run`), il blocco
    18.1 che scriverebbe `open-pr` (`openpr.facts`) e le etichette dell'issue se `gh` le legge:
    senza, il livello minimo viene dal solo diff e l'avviso va in `warnings`. Il diff parte dalla
    base del lavoro. `environ` non serve: `gh` legge l'ambiente del processo."""
    from . import openpr        # openpr importa questo modulo
    base = work["work_base_sha"] or git.default_ref(wt)
    labels, warning = openpr.issue_labels(state, git.main_worktree(wt), work)
    if warning and warnings is not None:
        warnings.append(warning)
    block = prblock.parse(prblock.render(prblock.build(
        openpr.facts(conn, state, work, cfg, wt, sha, now=now, labels=labels, cycle=None))))
    saved = {r["command"]: r for r in receipts.latest(conn, work["id"], sha)}
    commands = [CommandResult(name, saved[name]["state"], saved[name]["exit"],
                              saved[name]["tests_run"], run.junits.get(name))
                for name in run.states if name in saved]
    issue = None if labels is None else IssueFacts(work["issue"], "open", tuple(labels))
    return GateInputs(
        where=LOCAL, repo=wt, cfg=cfg, base_sha=base, head_sha=sha, pr=None, block=block,
        issue=issue, commands=commands, base_ids=None, base_ids_source=None,
        waiver_text=git.text_at(wt, sha, waivers.path_for(work["issue"])))


def _by_family(items: list[Item]) -> dict[str, list[Item]]:
    out: dict[str, list[Item]] = {}
    for item in items:
        out.setdefault(item.family, []).append(item)
    return out


def _keys(items: list[Item]) -> list[str]:
    return list(dict.fromkeys(i.key for i in items))


def _data_lines(item: Item) -> list[str]:
    return [x for x in item.data.splitlines() if x.strip()]


def _head_lines(items: list[Item]) -> list[str]:
    """Le prime righe del dato di ciascuna voce (i diff dei documenti si fermano lì)."""
    return [x for i in items for x in _data_lines(i)[:MAX_LISTED]]


def _said(item: Item) -> str:
    """Il testo di una voce con le prime righe del suo dato (nomi di file, identificativi)."""
    data = _data_lines(item)[:MAX_LISTED]
    return item.text + (": " + "; ".join(data) if data else "")


def _listed(items: list[Item]) -> str:
    """Le violazioni di `diff` come «<tipo> <percorso>», al più `MAX_LISTED`."""
    shown = []
    for i in items[:MAX_LISTED]:
        path = (_data_lines(i) or [""])[0]
        shown.append(f"{i.key} {path}" if path else i.text)
    more = len(items) - len(shown)
    return ", ".join(shown) + (f" (+{more})" if more else "")


def _attention_lines(items: list[Item]) -> list[str]:
    out = []
    for item in items:
        data = _data_lines(item)[:MAX_LISTED]
        label = "da leggere" if attention.group(item.key) == attention.READ else "informative"
        out.append(f"{label}: {item.text}" + (f" ({'; '.join(data)})" if data else ""))
    return out


def _saved(work, sha: str) -> CheckResult:
    """Lo stesso SHA in `review`: l'esito salvato, senza rieseguire il gate (criterio 28)."""
    report = json.loads(work["finish_report"])
    items = [dod.DodItem(k, _label(k), ok, dod.SKIPPED_DETAIL if ok is None else "")
             for k, ok in report["items"].items()]
    lines = [f"finish check già verde su {sha[:7]}: esito salvato"]
    lines += [_line(i, {}) for i in items]
    if report.get("manual"):
        lines.append("da leggere: must-have con test manuale: " + ", ".join(report["manual"]))
    keys = [k for k in report.get("gate", {}).get("attention", []) if k != MANUAL]
    for label, group in (("da leggere", attention.READ), ("informative", attention.INFO)):
        listed = [k for k in keys if attention.GROUPS.get(k) == group]
        if listed:
            lines.append(f"{label} (voci del gate): " + ", ".join(listed))
    lines.append(_next_step(work["level"], True))
    return CheckResult(OK, lines, items)
