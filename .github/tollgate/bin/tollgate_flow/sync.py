"""`tollgate sync` (spec 6.5, decisione 17 di P3b): rimette il ramo del lavoro sul predefinito.

Dopo l'atto `sync` della sessione, in `execution` o `pr_open`: intento `sync:<lavoro>:<atto>` con
gli SHA di partenza e di arrivo, `fetch`, i commit remoti del ramo (per esempio «Update branch»)
integrati con `merge --ff-only`, `rebase` sul predefinito. Con un conflitto il rebase si annulla,
base e fase restano e si apre `needs_you` con le due strade. Riuscito: i commit riscritti diventano
eventi `commit` (gli hook non li trattano come nuovi), la base si riallinea alla punta del
predefinito, la fase torna a `execution`, il push forzato è autorizzato; poi `finish check` e, se il
contenuto non è cambiato (stesso `patch-id`), `open-pr --update`. Un `sync` interrotto lo completa
la ripresa (`complete_interrupted`), senza ripetere il rebase."""
from __future__ import annotations

import json
import shlex
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from tollgate_core import (acts, clock, config, db, events, git, intents, phases, sessions,
                           subagents)
from tollgate_core.paths import program_command

from . import finishcheck, gh, gitw, openpr, prstate

OK, REFUSED, BLOCKED, REVIEW_NEEDED = 0, 1, 2, 3
ERRORS = (sqlite3.Error, phases.TransitionError, config.ConfigError, gh.GhError, git.GitError,
          gitw.GitWriteError, OSError, db.DbError)


@dataclass
class SyncResult:
    code: int
    lines: list[str]


def _refuse(*reasons: str, warnings=()) -> SyncResult:
    return SyncResult(REFUSED, [*warnings, *[f"rifiuto: {r}" for r in reasons]])


def sync(state, cwd, *, now=None, argv: list[str] | None = None, environ=None) -> SyncResult:
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        return _refuse(str(e))
    try:
        return _sync(state, conn, Path(cwd), now, argv, environ)
    except ERRORS as e:
        return _refuse(str(e), "se il rebase è stato fatto, la ripresa (start) o un nuovo "
                       "/tollgate:sync completano il riallineamento senza ripeterlo")
    finally:
        conn.close()


def _remote_conflict(conn, wid: int, wt: Path, branch: str, head: str,
                     issue: int) -> str | None:
    """Integra i commit remoti del ramo: avanzamento rapido, oppure nulla se sono già in HEAD o
    sono un nostro push precedente poi riscritto (lo sostituisce il push forzato). Dà il motivo del
    blocco se i rami sono divergenti."""
    remote = git.resolve_ref(wt, f"origin/{branch}")
    if remote is None or remote == head or gitw.is_ancestor(wt, remote, head):
        return None
    if gitw.is_ancestor(wt, head, remote):
        if not gitw.merge_ff_only(wt, remote):
            raise gitw.GitWriteError(f"git merge --ff-only {remote[:7]} non riuscito")
        return None
    if remote in events.known_commits(conn, wid):
        return None
    return (f"sync: il ramo remoto {branch} ({remote[:7]}) e HEAD ({head[:7]}) sono divergenti: "
            "integra a mano i commit remoti e chiudi il blocco con /tollgate:resolve <id>, "
            f"oppure abbandona con /tollgate:abandon #{issue}")


def _realign(conn, state, wid: int, wt: Path, tip: str, branch: str, key: str, *, now,
             session) -> list[str]:
    """I passi dopo il rebase, ognuno ripetibile (un `sync` interrotto li riprende): base alla
    punta del predefinito, eventi `commit` dei commit non ancora noti, fase `execution`, push
    forzato autorizzato se il remoto non è antenato di HEAD, intento eseguito."""
    notes = []
    work = phases.get_work(conn, wid)
    head = git.head(wt)
    if work["work_base_sha"] != tip:
        phases.set_base(conn, wid, tip, cause="sync", now=now, session=session)
        notes.append(f"base riallineata a {tip[:12]}")
    new = events.record_commits(conn, wid, wt, tip, now=now, session=session)
    if new:
        notes.append(f"{new} commit registrati")
    if work["phase"] == "pr_open":
        phases.set_phase(conn, state, wid, "execution", "sync", now=now, session=session)
        notes.append("fase execution")
    remote = git.resolve_ref(wt, f"origin/{branch}")
    if remote is not None and remote != head and not gitw.is_ancestor(wt, remote, head):
        if not intents.force_authorized(conn, wid):
            intents.authorize_force(conn, wid, reason="sync", now=now, lease=remote)
            notes.append("push forzato autorizzato")
        elif intents.force_lease(conn, wid) != remote:      # remoto avanzato e integrato (I-4)
            intents.refresh_lease(conn, wid, remote)
            notes.append(f"lease del push forzato rinnovato a {remote[:7]}")
    intents.complete(conn, key, outcome="riallineato", now=now)
    return notes


def complete_interrupted(conn, state, work, wt: Path, *, now, session=None) -> str | None:
    """La ripresa di un `sync` interrotto dopo il rebase: con un intento `sync` richiesto, nessun
    rebase in corso e la punta di arrivo antenata di HEAD completa base, eventi e fase. Dà la riga
    d'avviso, oppure `None` se non c'è nulla da completare."""
    pending = intents.pending(conn, work["id"], "sync")
    if not pending or not wt.is_dir() or gitw.rebase_in_progress(wt):
        return None
    done = []
    for row in pending:
        tip = json.loads(row["data"] or "{}").get("to")
        head = git.head(wt)
        if not tip or head is None or not gitw.is_ancestor(wt, tip, head):
            continue
        notes = _realign(conn, state, work["id"], wt, tip, work["branch"], row["idempotency_key"],
                         now=now, session=session)
        done.append(f"intento {row['idempotency_key']}: " + (", ".join(notes) or "già allineato"))
    if not done:
        return None
    return ("sync interrotto completato senza ripetere il rebase (" + "; ".join(done) + "): "
            "per aggiornare la PR rilancia /tollgate:finish")


def _conflict_reason(wt: Path, ref: str, tip: str, issue: int) -> str:
    return (f"{intents.SYNC_CONFLICT_REASON} su {ref} ({tip[:7]}): due strade, o risolvi fuori da "
            f"Claude Code (`git -C {shlex.quote(str(wt))} rebase {ref}`, poi finiscilo) e dai "
            f"/tollgate:approve rebase, oppure abbandona con /tollgate:abandon #{issue}")


def _in_use(conn, state, work, environ) -> str | None:
    """Il motivo per cui i commit non si possono riscrivere ora (regola di `subagents.in_use`)."""
    def load():
        base = work["work_base_sha"] or git.default_ref(git.main_worktree(Path(work["worktree"])))
        return config.load_config(state, Path(work["worktree"]), base, env=environ)

    busy = subagents.in_use(conn, work["id"], load)
    if busy is None:
        return None
    if busy.kind == "task":
        return (f"il task {busy.ident} è in corso o ha commit non chiusi: chiudi o riporta in "
                f"attesa il task {busy.ident}, poi /tollgate:sync")
    return (f"l'implementatore {busy.ident} sta scrivendo nel worktree: attendi che "
            "finisca (o interrompilo con /tollgate:resolve writer), poi /tollgate:sync")


def _sync(state, conn, cwd: Path, now, argv, environ) -> SyncResult:
    work = sessions.work_for_path(conn, cwd)
    if work is None:
        return _refuse("nessun lavoro attivo per questa cartella: lancia il comando dal "
                       "worktree del lavoro")
    wid, wt, branch = work["id"], Path(work["worktree"]), work["branch"]
    main = git.main_worktree(wt)
    try:
        session = sessions.cli_session(state, cwd, "sync", now=now, argv=argv)
    except sessions.CliSessionError as e:
        return _refuse(str(e))
    act = acts.find_usable(conn, type_="sync", work=wid, session=session, now=now)
    if act is None:
        return _refuse("serve un atto dell'utente: /tollgate:sync")

    seen = prstate.detect(state, conn, work, main, now=now, session=session)
    warnings = [f"avviso: {seen.error}"] if seen.error else []
    if seen.kind == "merged":
        return _refuse(f"la PR #{seen.pr.get('number')} è stata unita: il lavoro è chiuso",
                       warnings=warnings)
    if seen.kind == "closed":
        return _refuse(prstate.closed_line(seen.pr), warnings=warnings)
    phase = work["phase"]
    if phase not in ("execution", "pr_open") and not (phase == "review"
                                                      and work["pr_number"] is not None):
        return _refuse(f"la fase è {phase}: `sync` si usa in execution o pr_open",
                       warnings=warnings)
    busy = _in_use(conn, state, work, environ)
    if busy:
        return _refuse(busy, warnings=warnings)
    if gitw.rebase_in_progress(wt):
        return _refuse("c'è un rebase in corso nel worktree: finiscilo o annullalo "
                       f"(`git -C {shlex.quote(str(wt))} rebase --abort`) e rilancia",
                       warnings=warnings)
    if not gitw.fetch(wt):
        return _refuse("git fetch origin non riuscito (senza rete?): sync lavora sul "
                       "predefinito aggiornato", warnings=warnings)
    ref = git.default_ref(main)
    tip = git.resolve_ref(main, ref) if ref else None
    head0 = git.head(wt)
    if tip is None or head0 is None:
        return _refuse("nessun ramo predefinito di origin da cui riallineare", warnings=warnings)

    key = f"sync:{wid}:{act['act_id']}"
    intents.request(conn, work=wid, action="sync", key=key,
                    data={"branch": branch, "from": head0, "to": tip,
                          "base": work["work_base_sha"]}, now=now)
    try:
        divergent = _remote_conflict(conn, wid, wt, branch, head0, work["issue"])
        if git.head(wt) != head0:       # integrati con --ff-only: noti prima di ogni altro passo
            events.record_commits(conn, wid, wt, work["work_base_sha"], now=now, session=session)
        if divergent is None and not gitw.is_ancestor(wt, tip, git.head(wt)):
            if not gitw.rebase(wt, tip):
                gitw.rebase_abort(wt)
                return _block(conn, state, work, act, key, _conflict_reason(
                    wt, ref, tip, work["issue"]), "conflitto nel rebase", warnings, now, session)
    except ERRORS as e:
        intents.complete(conn, key, outcome=f"non riuscito: {e}", now=now)
        raise
    if divergent is not None:
        return _block(conn, state, work, act, key, divergent, "rami divergenti", warnings, now,
                      session)

    notes = _realign(conn, state, wid, wt, tip, branch, key, now=now, session=session)
    for row in intents.pending(conn, wid, "sync"):      # tentativi precedenti rimasti a metà
        intents.complete(conn, row["idempotency_key"], outcome=f"superato da {key}", now=now)
    _consume(conn, act, wid, session, now, warnings)
    lines = [*warnings, f"rebase su {ref} ({tip[:7]}) riuscito"
             + (": " + ", ".join(notes) if notes else "")]
    return _finish(state, conn, wt, wid, tip, act["act_id"], lines, now, environ)


def _consume(conn, act, wid: int, session, now, warnings: list[str]) -> None:
    try:
        acts.consume(conn, act["act_id"], type_="sync", work=wid, session=session, now=now)
    except acts.ActError as e:
        warnings.append(f"avviso: {e}")


def _block(conn, state, work, act, key: str, reason: str, outcome: str, warnings, now,
           session) -> SyncResult:
    """`needs_you`: base e fase restano quelle di prima (la fase torna con la chiusura del
    blocco)."""
    phases.open_block(conn, state, work["id"], "needs_you", reason, now=now, session=session)
    intents.complete(conn, key, outcome=outcome, now=now)
    _consume(conn, act, work["id"], session, now, warnings)
    return SyncResult(BLOCKED, [*warnings, f"needs_you: {reason}"])


def _finish(state, conn, wt: Path, wid: int, tip: str, act_id: str, lines: list[str], now,
            environ) -> SyncResult:
    prog = program_command(db.BIN_PATH)
    checked = finishcheck.check(state, wt, now=now, environ=environ)
    if checked.code != finishcheck.OK:
        why = ("finish check non è verde dopo il rebase" if checked.code == finishcheck.RED
               else "finish check ha rifiutato dopo il rebase (non ha verificato nulla)")
        return SyncResult(REFUSED, [*lines, *checked.lines,
                                    f"rifiuto: {why}: correggi e rilancia {prog} finish check"])
    lines.append("finish check verde")
    work = phases.get_work(conn, wid)
    if work["pr_number"] is None:
        return SyncResult(OK, [*lines, "PR non ancora aperta: /tollgate:finish"])
    head = git.head(wt)
    cfg = config.load_config(state, wt, tip, env=environ)
    review = openpr.review_state(conn, work, cfg, wt, tip, head, cfg.get("components"))
    if review.required and not review.ok:
        return SyncResult(REVIEW_NEEDED, [
            *lines, "il contenuto è cambiato nel rebase (patch-id diverso dall'ultima revisione "
            "ok): nessun push", "serve una nuova revisione: /tollgate:finish"])
    opened = openpr.open_pr(state, wt, update=True, now=now, via_sync=act_id, environ=environ)
    return SyncResult(opened.code, [*lines, *opened.lines])
