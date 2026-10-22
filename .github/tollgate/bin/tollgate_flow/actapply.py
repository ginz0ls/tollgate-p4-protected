"""`tollgate act apply [<id>]` (spec 8.4, decisione 13): effetti degli atti che non valgono dal DB.

L'hook registra l'atto, la CLI lo applica. L'atto si consuma sempre e una volta sola, prima
dell'applicatore: un rifiuto dell'applicatore non lo lascia pronto per un secondo tentativo.
`approve waiver` e `approve effect` non passano di qui (valgono già dal DB, 8.4 e 8.5)."""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from tollgate_analysis import level as lv
from tollgate_core import (acts, audits, clock, config, db, events, git, intents, phases,
                           reviews, sessions, subagents, tasks)
from tollgate_core.paths import program_command

from . import audit, gitw, l2acts


FIX_CAP = re.compile(r"giri di correzione esauriti sul task ([0-9]+)")     # motivo di taskcmd


class ActApplyError(Exception):
    pass


def _label(row) -> str:
    return " ".join(x for x in (row["type"], row["object"], row["target"]) if x)


def _config(state, work) -> config.Config:
    try:
        return audit.work_config(state, work)
    except config.ConfigError as e:
        raise ActApplyError(f"configurazione non valida: {e}") from e


def _resolve(conn, state, work, act, args, now, session) -> str:
    if act["target"] == "writer":
        cfg = _config(state, work)
        stopped = [r["id"] for r in subagents.running(conn, work=work["id"])
                   if not config.is_readonly(cfg, r["type"])]
        for agent_id in stopped:
            subagents.interrupt(conn, agent_id, now=now, session=session)
        return ("implementatori interrotti: " + ", ".join(stopped)) if stopped \
            else "nessun implementatore in corso da interrompere"
    block = None
    if re.fullmatch(r"[0-9]+", act["target"]):
        block = conn.execute("SELECT id, reason FROM blocks WHERE id = ? AND work = ? "
                             "AND closed IS NULL", (int(act["target"]), work["id"])).fetchone()
    if block is None:
        raise ActApplyError(f"blocco {act['target']}: non è un blocco aperto di questo lavoro")
    note = " ".join(args[1:]).strip() or "risolto dall'utente"
    if block["reason"] == reviews.CAP_REASON:
        _grant_cycles(conn, work, 1, now)       # decisione 13: `resolve` concede un ciclo
    suspended = None
    if audits.cap_kind(block["reason"]) is not None:    # tetti dell'audit (decisione 7)
        # senza worktree la config non si legge: valgono i tetti predefiniti
        cfg = _config(state, work) if work["worktree"] else None
        suspended = l2acts.suspend_on_resolve(conn, work["id"], block["reason"], now=now,
                                              cfg=cfg)
    phase = phases.close_block(conn, state, block["id"], note, now=now, session=session)
    unblocked = tasks.unblock_all(conn, work["id"], now=now, session=session) \
        if phase != "blocked" else []
    msg = f"blocco {block['id']} chiuso; fase {phase}"
    if suspended:
        msg += f"; {suspended}"
    if unblocked:
        msg += "; task di nuovo pending: " + ", ".join(str(n) for n in unblocked)
    return msg


def _grant_cycles(conn, work, n: int, now) -> int:
    """`n` cicli di revisione oltre i quattro; i cicli fatti più `n` non superano 8."""
    done = reviews.count(conn, work["id"])
    if done + n > reviews.MAX_CYCLES:
        raise ActApplyError(
            f"cicli di revisione: {done} fatti, {n} in più superano il tetto di "
            f"{reviews.MAX_CYCLES}; oltre serve /tollgate:approve unverified-review")
    return phases.add_extra_cycles(conn, work["id"], n, now=now)


def _open_blocks(conn, work_id: int) -> list:
    return conn.execute("SELECT id, reason FROM blocks WHERE work = ? AND closed IS NULL "
                        "ORDER BY id", (work_id,)).fetchall()


def _cycles_block(conn, work_id: int):
    return next((b for b in _open_blocks(conn, work_id) if b["reason"] == reviews.CAP_REASON),
                None)


def _approve_rounds(conn, state, work, act, args, now, session) -> str:
    if not re.fullmatch(r"[0-9]+", act["target"]) or int(act["target"]) < 1:
        raise ActApplyError("approve rounds vuole un numero intero positivo: "
                            "/tollgate:approve rounds <n>")
    n = int(act["target"])
    caps = []
    for b in _open_blocks(conn, work["id"]):
        fix = FIX_CAP.fullmatch(b["reason"])
        if fix or b["reason"] == reviews.CAP_REASON:
            caps.append((b, fix))
    if not caps:
        raise ActApplyError("nessun tetto raggiunto: serve un blocco «cicli di revisione "
                            "esauriti» o «giri di correzione esauriti sul task k»")
    if len(caps) > 1:
        raise ActApplyError("più tetti raggiunti insieme: risolvine uno alla volta con "
                            "/tollgate:resolve <id del blocco>")
    block, fix_block = caps[0]
    if fix_block is None:
        total = _grant_cycles(conn, work, n, now)
        msg = f"cicli di revisione concessi: {total} oltre i quattro; blocco {block['id']} chiuso"
    else:
        number = int(fix_block.group(1))
        try:
            total = tasks.add_extra_rounds(conn, work["id"], number, n)
        except ValueError as e:
            raise ActApplyError(str(e)) from e
        msg = (f"task {number}: {total} giri di correzione oltre i {tasks.BASE_FIX_ROUNDS}; "
               f"blocco {block['id']} chiuso; riprendi con "
               f"{program_command(db.BIN_PATH)} task start {number} --fix")
    phase = phases.close_block(conn, state, block["id"], f"approve rounds {n}", now=now,
                               session=session)
    return f"{msg}; fase {phase}"


def _approve_finding(conn, state, work, act, args, now, session) -> str:
    fid, choice, reason = act["target"], (args[2] if len(args) > 2 else ""), \
        " ".join(args[3:]).strip()
    if choice != "dismiss" and choice not in reviews.SEVERITY_ORDER:
        raise ActApplyError("approve finding vuole <id> <gravità: blocker|major|moderate|minor, "
                            "oppure dismiss> <motivo>")
    if not reason:
        raise ActApplyError("approve finding vuole un motivo: /tollgate:approve finding "
                            "<id> <gravità|dismiss> <motivo>")
    decision = "dismissed" if choice == "dismiss" else f"downgraded:{choice}"
    try:
        reviews.set_decision(conn, work["id"], fid, decision, now=now, session=session)
    except ValueError as e:
        raise ActApplyError(str(e)) from e
    cycle = conn.execute("SELECT cycle FROM findings WHERE work = ? AND id = ?",
                         (work["id"], fid)).fetchone()[0]
    msg = f"rilievo {fid}: {decision} ({reason})"
    row = conn.execute("SELECT stage FROM review_cycles WHERE work = ? AND number = ?",
                       (work["id"], cycle)).fetchone()
    if row is None or row["stage"] != "closed":
        return msg
    try:
        outcome = reviews.recompute_outcome(conn, work["id"], cycle, now=now)
    except ValueError as e:         # ciclo superseded: la decisione è già scritta (decisione 25)
        raise ActApplyError(f"{msg}; esito del ciclo {cycle} non ricalcolabile: {e}") from e
    msg += f"; esito del ciclo {cycle}: {outcome}"
    block = _cycles_block(conn, work["id"])
    if block is not None:       # spec 10: il blocco si scioglie anche con approve finding
        phase = phases.close_block(conn, state, block["id"], f"approve finding {fid}", now=now,
                                   session=session)
        msg += f"; blocco {block['id']} chiuso, fase {phase}"
    return msg


def _approve_unverified_review(conn, state, work, act, args, now, session) -> str:
    done = reviews.count(conn, work["id"])
    if done < reviews.MAX_CYCLES:
        raise ActApplyError(f"approve unverified-review vale solo dopo {reviews.MAX_CYCLES} "
                            f"cicli di revisione: ne risultano {done}")
    last = reviews.latest(conn, work["id"])
    with db.tx(conn):
        phases.set_review_unverified(conn, work["id"], now=now)
        if last is not None:        # nessun rilievo resta senza esito (spec 8.6)
            reviews.mark_unverified(conn, work["id"], last["number"],
                                    reviews.UNVERIFIED_REVIEW_REASON, now=now)
    msg = "revisione finale dichiarata non verificata"
    block = _cycles_block(conn, work["id"])
    if block is not None:
        phase = phases.close_block(conn, state, block["id"], "approve unverified-review",
                                   now=now, session=session)
        msg += f"; blocco {block['id']} chiuso, fase {phase}"
    return msg


def _approve_rebase(conn, state, work, act, args, now, session) -> str:
    block = next((b for b in _open_blocks(conn, work["id"])
                  if b["reason"].startswith(intents.SYNC_CONFLICT_REASON)), None)
    if block is None:
        raise ActApplyError("approve rebase vale solo con un blocco aperto per il conflitto "
                            "di `sync` (non c'è)")
    wt = Path(work["worktree"])
    if not wt.is_dir():
        raise ActApplyError("worktree del lavoro assente: il rebase non è verificabile")
    if gitw.rebase_in_progress(wt):
        raise ActApplyError("il rebase è ancora in corso nel worktree: finiscilo (o "
                            "`git rebase --abort`) e ridai /tollgate:approve rebase")
    ref = git.default_ref(git.main_worktree(wt))
    base = gitw.merge_base(wt, "HEAD", ref) if ref else None
    if base is None:
        raise ActApplyError("nessuna base comune tra HEAD e il ramo predefinito di origin")
    phases.set_base(conn, work["id"], base, cause="approve_rebase", now=now, session=session)
    events.record_commits(conn, work["id"], wt, base, now=now, session=session)
    phase = phases.close_block(conn, state, block["id"], "approve rebase", now=now,
                               session=session)
    if phase == "pr_open":
        phases.set_phase(conn, state, work["id"], "execution", "sync", now=now, session=session)
        phase = "execution"
    try:
        lease = gitw.remote_sha(wt, work["branch"])
    except gitw.GitWriteError:
        lease = None            # open-pr userà lo SHA letto prima del push (decisione 10)
    intents.authorize_force(conn, work["id"], reason="approve rebase", now=now, lease=lease)
    return (f"base riallineata a {base[:12]}; blocco {block['id']} chiuso; fase {phase}; "
            "push forzato autorizzato per il prossimo open-pr")


def _approve_level(conn, state, work, act, args, now, session) -> str:
    cap = act["target"]
    if cap not in phases.LEVELS:
        raise ActApplyError(f"livello sconosciuto: {cap} (L0, L1 o L2)")
    reason = " ".join(args[2:]).strip()
    if not reason:
        raise ActApplyError("approve level vuole un motivo: /tollgate:approve level <L> <motivo>")
    cfg = _config(state, work)
    wt, base = Path(work["worktree"]), work["work_base_sha"]
    if not base or not wt.is_dir():
        raise ActApplyError("lavoro senza base o worktree: il diff non è calcolabile")
    changes = git.changes(wt, base, exclude=config.output_excludes(cfg))
    paths = [c.path for c in changes] + [c.old_path for c in changes if c.old_path]
    cap_paths = lv.sensitive_in(paths, cfg.get("levels.sensitive_paths"))
    try:
        phases.set_level_cap(conn, work["id"], cap, reason, cap_paths, now=now, session=session)
    except phases.TransitionError as e:
        raise ActApplyError(str(e)) from e
    level = phases.get_work(conn, work["id"])["level"]
    return f"tetto {cap} fissato (livello {level}), valido finché il diff non tocca un " \
           f"percorso sensibile nuovo; percorsi sensibili attuali: {len(cap_paths)}"


APPLIERS = {
    ("resolve", None): _resolve,
    ("approve", "level"): _approve_level,
    ("approve", "finding"): _approve_finding,
    ("approve", "rounds"): _approve_rounds,
    ("approve", "unverified-review"): _approve_unverified_review,
    ("approve", "rebase"): _approve_rebase,
    ("approve", "spec"): l2acts.approve_spec,
    ("approve", "plan"): l2acts.approve_plan,
    ("reopen", "spec"): l2acts.reopen,
    ("reopen", "plan"): l2acts.reopen,
}


def _pick(conn, work, act_id, session, now):
    if act_id is not None:
        row = conn.execute("SELECT * FROM acts WHERE act_id = ?", (act_id,)).fetchone()
        if row is None:
            raise ActApplyError(f"atto {act_id} inesistente")
        if (row["type"], row["object"]) not in APPLIERS:
            raise ActApplyError(f"atto {act_id} ({_label(row)}) non si applica con act apply")
        return row
    marks = ",".join("(?, ?)" for _ in APPLIERS)
    keys = [x for k in APPLIERS for x in (k[0], k[1] or "")]
    row = conn.execute(
        "SELECT * FROM acts WHERE state = 'pending' AND session = ? AND work = ? "
        f"AND expires_at > ? AND (type, coalesce(object, '')) IN (VALUES {marks}) "
        "ORDER BY n DESC LIMIT 1", [session, work["id"], clock.fmt(now), *keys]).fetchone()
    if row is None:
        raise ActApplyError("nessun atto da applicare per questa sessione: dai prima "
                            "/tollgate:resolve, un /tollgate:approve (level, finding, rounds, "
                            "unverified-review, rebase, spec, plan) o /tollgate:reopen")
    return row


def apply_act(state, cwd, act_id: str | None, *, now=None,
              argv: list[str] | None = None) -> str:
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        raise ActApplyError(str(e)) from e
    try:
        try:
            session = sessions.cli_session(state, cwd, "act", now=now, argv=argv)
        except sessions.CliSessionError as e:
            raise ActApplyError(str(e)) from e
        work = sessions.work_for_path(conn, cwd)
        if work is None:
            raise ActApplyError("nessun lavoro attivo per questa cartella: lancia il comando "
                                "dal worktree del lavoro")
        act = _pick(conn, work, act_id, session, now)
        try:
            acts.consume(conn, act["act_id"], type_=act["type"], object_=act["object"],
                         target=act["target"], now=now, work=work["id"], session=session)
        except acts.ActError as e:
            raise ActApplyError(str(e)) from e
        applier = APPLIERS[(act["type"], act["object"])]
        try:
            msg = applier(conn, state, work, act, json.loads(act["args"]), now, session)
        except (sqlite3.Error, phases.TransitionError, tasks.TaskTransitionError,
                git.GitError, gitw.GitWriteError, l2acts.Refused) as e:
            raise ActApplyError(str(e)) from e
        return f"atto {act['act_id']} applicato ({_label(act)}): {msg}"
    finally:
        conn.close()
