"""Atti dell'utente di L2 (spec 6.2, 8.4; decisioni 7, 9, 10, 12, 13 di P3c): `approve spec
<fette>`, `approve plan`, `reopen spec|plan` e le sospensioni dei tetti dell'audit scritte da
`resolve`.

Gli applicatori hanno la firma di `actapply.APPLIERS` (`conn, state, work, act, args, now,
session -> str`). I rifiuti sollevano `Refused`, che `actapply.apply_act` converte in
`ActApplyError`: questo modulo non importa `actapply`. L'atto è già consumato quando si arriva
qui (un rifiuto non lo lascia pronto per un secondo tentativo)."""
from __future__ import annotations

import re
from pathlib import Path

from tollgate_analysis import (approvals, auditrules, brief as briefs, profiles as prof,
                               specdoc)
from tollgate_core import audits, clock, config, db, git, phases, scope, subagents
from tollgate_core.paths import program_command

from . import audit, l2tree

ADV_KIND, LENS_KIND, PLAN_KIND = audit.ADV_KIND, audit.LENS_KIND, audit.PLAN_KIND
SPEC_KINDS = audit.SPEC_KINDS


class Refused(Exception):
    """Rifiuto di un atto: il messaggio va all'utente così com'è."""


def _program() -> str:
    return program_command(db.BIN_PATH)


def _cfg(state, work) -> config.Config:
    try:
        return audit.work_config(state, work)
    except config.ConfigError as e:
        raise Refused(f"configurazione non valida: {e}") from e


def _check_ready(conn, work, phase: str | tuple[str, ...], what: str) -> Path:
    """Fase giusta (un lavoro bloccato rimanda a `resolve`), worktree presente: dà il worktree."""
    allowed = (phase,) if isinstance(phase, str) else phase
    if work["phase"] == "blocked":
        block = conn.execute("SELECT id, reason FROM blocks WHERE work = ? AND closed IS NULL "
                             "ORDER BY id DESC LIMIT 1", (work["id"],)).fetchone()
        tail = f" (blocco {block['id']}: {block['reason']})" if block else ""
        ident = block["id"] if block else "<id>"
        raise Refused(f"il lavoro è bloccato{tail}: risolvi con /tollgate:resolve {ident} "
                      f"<nota> prima di {what}")
    if work["phase"] not in allowed:
        raise Refused(f"{what} vale in fase {' o '.join(allowed)} (fase {work['phase']})")
    wt = Path(work["worktree"]) if work["worktree"] else None
    if wt is None or not wt.is_dir():
        raise Refused("worktree del lavoro assente")
    return wt


def _no_open_round(conn, work) -> None:
    row = audits.open_round_row(conn, work["id"])
    if row is not None:
        raise Refused(f"giro {row['kind']} {row['number']} ancora aperto: aspetta il report o "
                      f"rilancia {_program()} audit prepare")


def _committed(wt: Path, path: str, what: str) -> tuple[str, str]:
    """`(blob a HEAD, testo a HEAD)` di `path`, solo se il file del worktree è identico. I
    percorsi qui sono sempre quelli registrati nel lavoro."""
    try:
        blob = audit.committed_blob(wt, path)
    except audit.Uncommitted as e:
        if e.missing:
            raise Refused(f"{what} {path} non è nel ramo{audit.REGISTERED_NOTE}") from e
        raise Refused(f"committa {path} prima di approvare") from e
    return blob, git.text_at(wt, "HEAD", path) or ""


def _outcome_label(last) -> str:
    """Per un giro già «passato»: `closed` se è pulito, `suspended` se è quello sospeso."""
    return "closed" if audit.clean(last) else "suspended"


def _write(wt: Path, rel: str, fields: dict) -> None:
    try:
        text = approvals.render_approval(fields)
    except ValueError as e:
        raise Refused(f"file di approvazione non scrivibile: {e}") from e
    target = wt / rel
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    except OSError as e:
        raise Refused(f"{rel}: {e.strerror}") from e


# --- approve spec --------------------------------------------------------------------------


def _target_slices(act) -> int | None:
    t = act["target"]
    return int(t) if t and re.fullmatch(r"[0-9]{1,6}", t) else None


def _adversarial_check(conn, work, cfg, blob: str) -> str:
    """Il valore di `adversarial` del file, oppure il rifiuto che dice cosa manca."""
    if not audit.on(cfg, ADV_KIND):
        return "off"
    last = audit.last_round(conn, work["id"], ADV_KIND)
    if last is None:
        raise Refused(f"nessun giro avversariale della spec: lancia {_program()} audit prepare")
    if last["sha"] != blob:
        raise Refused(f"la spec è cambiata dopo l'ultimo giro avversariale ({last['number']}): "
                      f"lancia {_program()} audit prepare")
    if not audit.passed(conn, work["id"], last, ADV_KIND):
        raise Refused(f"l'ultimo giro avversariale ({last['number']}) ha blocker o major: "
                      f"correggi la spec e rilancia {_program()} audit prepare, oppure "
                      "/tollgate:resolve se il tetto è raggiunto")
    return _outcome_label(last)


def _lens_check(conn, work, cfg, slices: int) -> str | None:
    """Il valore di `lens`: `None` con una fetta sola, `off`, `closed` o `suspended`."""
    if slices <= 1:
        return None
    if not audit.on(cfg, LENS_KIND):
        return "off"
    rows = audits.rounds(conn, work["id"], LENS_KIND)
    state = auditrules.lens_state([(r["viewpoint"], r["outcome"]) for r in rows])
    if state.closed:
        return "closed"
    if LENS_KIND in audits.suspended(conn, work["id"]):
        return "suspended"
    raise Refused("la spec ha più fette: l'audit a lenti non è chiuso né sospeso: lancia "
                  f"{_program()} audit prepare")


def _issue_proposal(spec_path: str, text: str, slices: int) -> list[str]:
    """Le righe che propongono un'issue per le fette 2..n. I titoli sono testo della spec, non
    fidato: stanno solo in un recinto marcato come dato, mai in un comando."""
    titles = specdoc.slice_titles(text)
    name = Path(spec_path).name
    rows = [f"fetta {k}/{slices} di {name}: {titles[k - 1]}" for k in range(2, slices + 1)]
    rows += ["", f'/tollgate:start #<numero dell\'issue> --spec "{spec_path}"']
    body = "\n".join(rows)
    fence = briefs.fence(body)
    return ["", f"Fette successive: propongo un'issue per ciascuna, con il titolo della riga. "
                f"{briefs.DATA_NOTE}",
            fence, body, fence,
            "Da creare tu, oppure dall'agente dopo /tollgate:approve effect. Dopo il merge di "
            "questa fetta, avvia ciascuna con il comando dell'ultima riga del recinto."]


def approve_spec(conn, state, work, act, args, now, session) -> str:
    wt = _check_ready(conn, work, "spec_audit", "approve spec")
    spec_path = work["spec_path"]
    if not spec_path:
        raise Refused(f"nessuna spec registrata: lancia {_program()} audit prepare")
    cfg = _cfg(state, work)
    blob, text = _committed(wt, spec_path, "la spec")
    slices = specdoc.slices(text)
    got = _target_slices(act)
    if got != slices:
        raise Refused(f"la spec prevede {slices} fette: /tollgate:approve spec {slices}")
    _no_open_round(conn, work)
    last = audits.last_closed(conn, work["id"], SPEC_KINDS)
    if last is not None and last["sha"] != blob:
        raise Refused(f"la spec è cambiata dopo l'ultimo giro ({last['kind']} {last['number']}): "
                      f"lancia {_program()} audit prepare")
    adversarial = _adversarial_check(conn, work, cfg, blob)
    lens = _lens_check(conn, work, cfg, slices)
    rel = approvals.approval_paths(work["issue"])[0]
    _write(wt, rel, {"kind": "spec-approval", "path": spec_path, "sha": blob, "slices": slices,
                     "adversarial": adversarial, "lens": lens, "act_id": act["act_id"],
                     "approved_at": clock.fmt(now)})
    phases.set_phase(conn, state, work["id"], "plan", "approve_spec", now=now, session=session)
    out = [f"spec approvata ({slices} fette): {rel} scritto, fase plan "
           f"(avversariale: {adversarial}, lenti: {lens})"]
    if slices > 1:
        out += _issue_proposal(spec_path, text, slices)
    out.append(f"Committa {rel} con i report, poi scrivi il piano.")
    return "\n".join(out)


# --- approve plan --------------------------------------------------------------------------


def _spec_approved(wt: Path, work, spec_blob: str) -> None:
    """D3: l'approvazione della spec si cerca nei file in HEAD, con lo `sha` attuale."""
    status, _ = l2tree.spec_approval(wt, "HEAD", issue=work["issue"],
                                     spec_path=work["spec_path"], spec_blob=spec_blob)
    if status == l2tree.STALE:
        raise Refused("spec cambiata dopo approve spec: /tollgate:reopen spec")
    if status == l2tree.MISSING:
        own = approvals.approval_paths(work["issue"])[0]
        if (wt / own).exists():
            raise Refused(f"committa {own} prima di approve plan")
        raise Refused("la spec non ha un file di approvazione nel ramo: /tollgate:reopen spec")


def _plan_adversarial(conn, work, cfg, plan_blob: str, spec_blob: str) -> str:
    if not audit.on(cfg, PLAN_KIND):
        return "off"
    last = audit.last_round(conn, work["id"], PLAN_KIND)
    if last is None:
        raise Refused(f"nessun giro dell'avversario del piano: lancia {_program()} audit prepare")
    if last["sha"] != plan_blob or last["spec_sha"] != spec_blob:
        raise Refused(audit.PLAN_CHANGED.format(number=last["number"]))
    if not audit.passed(conn, work["id"], last, PLAN_KIND):
        raise Refused(f"l'ultimo giro dell'avversario del piano ({last['number']}) ha blocker o "
                      f"major: correggi il piano e rilancia {_program()} audit prepare, oppure "
                      "/tollgate:resolve se il tetto è raggiunto")
    return _outcome_label(last)


def approve_plan(conn, state, work, act, args, now, session) -> str:
    wt = _check_ready(conn, work, "approval", "approve plan")
    _no_open_round(conn, work)
    plan_path, spec_path = work["plan_path"], work["spec_path"]
    if not plan_path:
        raise Refused(f"nessun piano registrato: lancia {_program()} audit prepare")
    if not spec_path:
        raise Refused("la spec del lavoro non è registrata: /tollgate:reopen spec")
    cfg = _cfg(state, work)
    plan_blob, plan_text = _committed(wt, plan_path, "il piano")
    spec_blob = git.blob_at(wt, "HEAD", spec_path)
    if spec_blob is None:
        raise Refused(f"la spec {spec_path} non è nel ramo: /tollgate:reopen spec")
    _spec_approved(wt, work, spec_blob)
    check = audit.plan_check(cfg, plan_text)
    if not check.ok:
        raise Refused("il piano non passa plan-check:\n- " + "\n- ".join(check.problems))
    adversarial = _plan_adversarial(conn, work, cfg, plan_blob, spec_blob)
    if work["plan_sha"] != plan_blob:           # già registrato: ripetizione dopo interruzione
        plan_tasks = [(t.number, prof.task_skills(t.files, cfg.profiles)[:3])
                      for t in check.tasks]
        try:
            scope.register_plan(conn, state, work["id"], plan_path=plan_path, plan_sha=plan_blob,
                                scope_paths=check.scope, plan_tasks=plan_tasks, advance=False,
                                now=now, session=session)
        except ValueError as e:
            raise Refused(str(e)) from e
    rel = approvals.approval_paths(work["issue"])[1]
    _write(wt, rel, {"kind": "plan-approval", "path": plan_path, "sha": plan_blob,
                     "spec_sha": spec_blob, "adversarial": adversarial,
                     "act_id": act["act_id"], "approved_at": clock.fmt(now)})
    phases.set_phase(conn, state, work["id"], "execution", "approve_plan", now=now,
                     session=session)
    return (f"piano approvato: scope di {len(set(check.scope))} file e {len(check.tasks)} task "
            f"registrati, {rel} scritto, fase execution (avversario del piano: {adversarial}). "
            f"Committa {rel} con i report, poi /tollgate:execute.")


# --- reopen spec|plan ------------------------------------------------------------------------

_REOPEN_FROM = {"spec": ("plan", "approval", "execution"), "plan": ("approval", "execution")}
_REOPEN_TO = {"spec": ("spec_audit", "reopen_spec"), "plan": ("plan", "reopen_plan")}


def reopen(conn, state, work, act, args, now, session) -> str:
    """Riporta la fase a `spec_audit` (solo L2) o a `plan`, supera il giro aperto e toglie la
    registrazione del piano. I file di approvazione restano come storico (decisione 12)."""
    what = act["object"]
    reason = " ".join(args[1:]).strip()
    if not reason:
        raise Refused(f"reopen {what} vuole un motivo: /tollgate:reopen {what} <motivo>")
    wt = _check_ready(conn, work, _REOPEN_FROM[what], f"reopen {what}")
    target, cause = _REOPEN_TO[what]
    if what == "spec" and work["level"] != "L2":
        raise Refused("reopen spec vale solo in L2: la spec c'è solo lì")
    try:
        phases.check_transition(work["level"], work["phase"], target, cause)
    except phases.TransitionError as e:
        raise Refused(f"reopen {what} non vale in {work['level']}: {e}") from e
    busy = subagents.in_use(conn, work["id"], lambda: _cfg(state, work))   # config solo se serve
    if busy is not None and busy.kind == "task":
        raise Refused(f"il task {busy.ident} è in corso o ha commit non chiusi: chiudi o "
                      f"riporta in attesa il task {busy.ident}, poi /tollgate:reopen {what}")
    if busy is not None:
        raise Refused(f"l'implementatore {busy.ident} sta scrivendo nel worktree: attendi che "
                      f"finisca (o interrompilo con /tollgate:resolve writer), poi "
                      f"/tollgate:reopen {what}")
    open_row = audits.open_round_row(conn, work["id"])
    if open_row is not None:
        audits.supersede(conn, work["id"], (open_row["kind"], open_row["number"]), now=now)
    removed = scope.reset_plan(conn, work["id"], now=now, session=session)   # prima della fase
    phases.set_phase(conn, state, work["id"], target, cause, now=now, session=session)
    parts = [f"{what} riaperto ({reason}): fase {target}"]
    if open_row is not None:
        parts.append(f"giro {open_row['kind']} {open_row['number']} superato")
    if removed:
        parts.append(f"registrazione del piano tolta (task {', '.join(map(str, removed))})")
    if what == "plan" and work["level"] == "L1":
        nxt = "correggi il piano: si registra da solo con la prossima modifica (post_edit)"
    elif what == "plan":
        nxt = (f"correggi il piano, committalo e riparti da {_program()} audit prepare "
               "per l'avversario del piano")
    else:
        nxt = f"correggi la spec, committala e riparti da {_program()} audit prepare"
    return (", ".join(parts) + f". I file di approvazione restano come storico e non valgono "
            f"più: {nxt}.")


# --- sospensioni dei tetti, da `resolve` ---------------------------------------------------


def suspend_on_resolve(conn, work: int, block_reason: str, *, now,
                       cfg: config.Config | None = None) -> str | None:
    """Scrive la sospensione di un tetto dell'audit se `block_reason` è il motivo di un blocco
    del tetto E la condizione del tetto vale nel DB (decisione 7, D6); altrimenti `None` e
    `resolve` chiude soltanto. Idempotente: gira prima di `close_block`, e se il processo muore
    tra le due un nuovo `resolve` riscrive la stessa sospensione. `cfg` dà i tetti; senza, i
    predefiniti."""
    kind = audits.cap_kind(block_reason)
    if kind is None:
        return None
    caps = config.DEFAULTS["spec_audit"] if cfg is None else cfg.get("spec_audit")
    number: int | None = None
    if block_reason == audits.DECLINE_REASON:
        number = 0
    elif kind == LENS_KIND:
        rows = audits.rounds(conn, work, LENS_KIND)
        state = auditrules.lens_state([(r["viewpoint"], r["outcome"]) for r in rows])
        if len(rows) >= caps["spec_audit_cycles"] and not state.closed:
            number = rows[-1]["number"]
    else:
        cap = caps["spec_rounds" if kind == ADV_KIND else "plan_rounds"]
        rows = audits.rounds(conn, work, kind)
        if rows and len(rows) >= cap and not audit.clean(rows[-1]):
            number = rows[-1]["number"]
    if number is None:
        return None
    audits.suspend(conn, work, kind, number, now=now)
    return audits.SUSPENDED_LABELS[kind]
