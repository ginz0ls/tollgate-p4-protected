"""`tollgate abandon N` e `tollgate cleanup` (spec 12.4, decisioni 19 e 20 di P3b).

Entrambi si lanciano dopo l'atto dell'utente, da una sessione non legata al lavoro (l'atto ha
`work` nullo). `abandon` chiude il lavoro e lascia ramo, worktree e PR. `cleanup` toglie rami e
worktree dei lavori chiusi (e, con `--orphans`, dei rami `tg/<N>-*` senza riga nel DB): senza
`--confirm` elenca soltanto e non consuma l'atto. Il worktree si toglie sempre senza `--force`,
mai se ha modifiche; il ramo solo se punta ancora allo SHA letto in quel momento e non è quello
del checkout principale."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from tollgate_analysis import prref
from tollgate_core import acts, clock, db, git, phases, sessions
from tollgate_core.paths import State, program_command, repo_key

from . import gh, gitw, start as flow_start

OK, REFUSED, NEEDS_CONFIRM = 0, 1, 3
ERRORS = (sqlite3.Error, phases.TransitionError, gh.GhError, git.GitError, gitw.GitWriteError,
          OSError, db.DbError)


@dataclass(frozen=True)
class CleanupItem:
    """Un ramo e/o un worktree da togliere. `kind`: `closed` (lavoro chiuso) oppure `orphan`
    (ramo `tg/<N>-*` senza riga nel DB). `sha` è `None` se il ramo locale non esiste più."""
    kind: str
    issue: int | None
    branch: str
    sha: str | None
    worktree: Path | None
    dirty: bool


def _refuse(*reasons: str) -> tuple[int, list[str]]:
    return REFUSED, [f"rifiuto: {r}" for r in reasons]


def _context(state: State, cwd: Path, subcommand: str, now, argv):
    """`((checkout principale, chiave del repo, sessione), None)` oppure `(None, rifiuto)`."""
    top = git.toplevel(cwd)
    if top is None:
        return None, _refuse("la cartella corrente non è in un repo git")
    main = git.main_worktree(top)
    url = git.origin_url(main)
    if not url:
        return None, _refuse("il repo non ha il remote origin")
    try:
        session = sessions.cli_session(state, cwd, subcommand, now=now, argv=argv)
    except sessions.CliSessionError as e:
        return None, _refuse(str(e))
    return (main, repo_key(url), session), None


def abandon(state: State, cwd: Path, issue: int, *, now=None,
            argv: list[str] | None = None) -> tuple[int, list[str]]:
    now = now or clock.now()
    ctx, refusal = _context(state, Path(cwd), "abandon", now, argv)
    if refusal:
        return refusal
    _, key, session = ctx
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        return _refuse(str(e))
    try:
        act = acts.find_usable(conn, type_="abandon", target=str(issue), work=None,
                               session=session, now=now)
        if act is None:
            return _refuse(f"serve un atto dell'utente: /tollgate:abandon #{issue}")
        row = phases.find_active(conn, key, issue)
        if row is None:
            return _refuse(f"nessun lavoro attivo per #{issue} in questo repo")
        phases.set_phase(conn, state, row["id"], "closed", "abandoned", now=now,
                         session=session)
        lines = []
        try:
            acts.consume(conn, act["act_id"], type_="abandon", target=str(issue), work=None,
                         session=session, now=now)
        except acts.ActError as e:
            lines.append(f"avviso: {e}")
        lines.append(f"lavoro #{issue} abbandonato: fase closed")
        lines.append(f"ramo {row['branch']}, worktree {row['worktree']} e PR restano: si tolgono "
                     "con /tollgate:cleanup (la PR su GitHub)")
        return OK, lines
    except ERRORS as e:
        return _refuse(str(e))
    finally:
        conn.close()


def _wt_state(wt: Path, warnings: list[str]) -> bool:
    """Il worktree ha modifiche. Se non si riesce a leggerlo vale come sporco (si salta)."""
    try:
        return gitw.is_dirty(wt, flow_start.EXCLUDES)
    except git.GitError as e:
        warnings.append(f"stato del worktree {wt} non leggibile ({e}): non si tocca")
        return True


def collect(conn, main: Path, key: str, *, orphans: bool, cwd: Path,
            warnings: list[str]) -> tuple[list[CleanupItem], list[CleanupItem]]:
    """`(da togliere, orfani solo indicati)`. Con `orphans` gli orfani sono già nel primo elenco.
    Mai nell'elenco: il ramo del checkout principale, un ramo di un lavoro attivo, un worktree
    in cui si trova `cwd`."""
    rows = conn.execute("SELECT issue, branch, phase FROM work_items WHERE repo_key = ? "
                        "AND branch IS NOT NULL ORDER BY id", (key,)).fetchall()
    active = {r["branch"] for r in rows if r["phase"] != "closed"}
    known = {r["branch"] for r in rows}
    closed = {}
    for r in rows:
        if r["phase"] == "closed" and r["branch"] not in active:
            closed.setdefault(r["branch"], r["issue"])
    local = git.local_branches(main)
    trees = git.worktrees(main)
    main_tree = trees[0][0]
    holder = {b: p for p, b in trees[1:] if b}
    here = Path(cwd).resolve()

    def item(kind, issue, branch):
        sha = git.resolve_ref(main, f"refs/heads/{branch}") if branch in local else None
        wt = holder.get(branch)
        if branch == trees[0][1]:
            warnings.append(f"ramo {branch}: è quello del checkout principale {main_tree}, "
                            "non si tocca")
            return None
        if wt is not None and not wt.is_dir():
            wt = None                    # registrazione rimasta senza cartella
        if sha is None and wt is None:
            return None
        if wt is not None and (here == wt or wt in here.parents):
            warnings.append(f"ramo {branch}: sei dentro il worktree {wt}, che non si toglie "
                            "da dentro. Lancia il comando da un'altra cartella")
            return None
        return CleanupItem(kind, issue, branch, sha, wt,
                           _wt_state(wt, warnings) if wt is not None else False)

    found = [it for b, n in closed.items() if (it := item("closed", n, b))]
    orphan_items = []
    for b in sorted(local):
        n = prref.issue_from_branch(b)
        if n is not None and b not in known and (it := item("orphan", n, b)):
            orphan_items.append(it)
    return (found + orphan_items, []) if orphans else (found, orphan_items)


def _describe(it: CleanupItem) -> str:
    parts = [f"{'lavoro chiuso' if it.kind == 'closed' else 'orfano'} "
             f"#{it.issue}: ramo {it.branch}"]
    if it.sha:
        parts.append(f"({it.sha[:10]})")
    if it.worktree is not None:
        parts.append(f"worktree {it.worktree}")
    if it.dirty:
        parts.append("- ha modifiche non committate: non verrà rimosso")
    return " ".join(parts)


def _remove(main: Path, it: CleanupItem) -> list[str]:
    """Toglie worktree e poi ramo. Se il worktree resta, il ramo resta con lui."""
    lines = []
    if it.worktree is not None:
        if it.dirty:
            return [f"avviso: {it.branch}: il worktree {it.worktree} ha modifiche non "
                    "committate: né worktree né ramo rimossi"]
        try:
            gitw.worktree_remove(main, it.worktree)
        except gitw.GitWriteError as e:
            return [f"avviso: {it.branch}: worktree {it.worktree} non rimosso, il ramo resta "
                    f"({e})"]
        lines.append(f"worktree {it.worktree} rimosso")
    if it.sha is not None:
        if gitw.delete_branch(main, it.branch, it.sha):
            lines.append(f"ramo {it.branch} tolto (puntava a {it.sha}: per recuperarlo "
                         f"`git branch {it.branch} {it.sha}`)")
        else:
            lines.append(f"avviso: ramo {it.branch} non tolto: non punta più a {it.sha[:10]}")
    return lines


def cleanup(state: State, cwd: Path, *, confirm: bool, orphans: bool, now=None,
            argv: list[str] | None = None) -> tuple[int, list[str]]:
    now = now or clock.now()
    ctx, refusal = _context(state, Path(cwd), "cleanup", now, argv)
    if refusal:
        return refusal
    main, key, session = ctx
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        return _refuse(str(e))
    try:
        act = acts.find_usable(conn, type_="cleanup", work=None, session=session, now=now)
        if act is None:
            return _refuse("serve un atto dell'utente: /tollgate:cleanup")
        warnings: list[str] = []
        todo, hints = collect(conn, main, key, orphans=orphans, cwd=Path(cwd),
                              warnings=warnings)
        lines = [f"avviso: {w}" for w in warnings]
        lines += [f"orfano: ramo {it.branch}" + (f" (worktree {it.worktree})" if it.worktree
                                                  else "") +
                  f": adottalo con /tollgate:adopt #{it.issue}, se non c'è già un lavoro "
                  "attivo; oppure toglilo con cleanup --orphans" for it in hints]
        if not todo:
            return OK, [*lines, "niente da ripulire"]
        if not confirm:
            flags = " --orphans" if orphans else ""
            return NEEDS_CONFIRM, [
                *lines, *[f"da togliere: {_describe(it)}" for it in todo],
                f"per procedere: {program_command(db.BIN_PATH)} cleanup{flags} --confirm"]
        try:
            acts.consume(conn, act["act_id"], type_="cleanup", work=None, session=session,
                         now=now)
        except acts.ActError as e:
            return _refuse(str(e))
        for it in todo:
            lines += _remove(main, it)
        return OK, lines
    except ERRORS as e:
        return _refuse(str(e))
    finally:
        conn.close()
