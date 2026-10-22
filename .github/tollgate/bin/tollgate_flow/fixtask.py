"""`tollgate task start --from-findings <ciclo>` e `--from-gate` (spec 6.3, decisione 16).

Creano un task di correzione (`kind = "fix"`) dai rilievi confermati bloccanti di un ciclo o
dall'ultimo commento del gate sulla PR, senza toccare il piano. Il testo sta in
`tasks.task_text`; da lì in poi il task passa da `task start --fix`, `review-prepare` e
`task done` come un task del piano."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from tollgate_analysis import brief as briefs
from tollgate_core import (clock, db, ghcli, git, phases, reviews, scope as scopes, sessions,
                           tasks)
from tollgate_gate import comment

from . import gh, taskcmd
from .taskcmd import TaskError

GATE_MARKER = "<!-- tollgate-verdict"     # il prefisso del marcatore che `comment.marker` scrive
MAX_COMMENT = 20000


def from_findings(state, cwd: Path, cycle: int, *, claude_dir: Path,
                  now=None) -> tuple[Path, str]:
    return _create(state, Path(cwd), claude_dir, now, lambda conn, work, wt: _findings(
        conn, work, cycle))


def from_gate(state, cwd: Path, *, claude_dir: Path, now=None) -> tuple[Path, str]:
    return _create(state, Path(cwd), claude_dir, now, lambda conn, work, wt: _gate(
        state, work, wt))


def _findings(conn, work, cycle: int) -> tuple[str, str]:
    row = conn.execute("SELECT * FROM review_cycles WHERE work = ? AND number = ?",
                       (work["id"], cycle)).fetchone()
    if row is None:
        raise TaskError(f"ciclo {cycle} inesistente nel lavoro #{work['issue']}")
    if row["outcome"] != "needs_fix":
        raise TaskError(f"il ciclo {cycle} ha esito {row['outcome'] or 'aperto'}, non "
                        "needs_fix: un task di correzione nasce solo da un ciclo needs_fix")
    found = [dict(r) for r in reviews.blocking_open(conn, work["id"], cycle)]
    if not found:
        raise TaskError(f"il ciclo {cycle} non ha rilievi bloccanti confermati ancora aperti")
    text = briefs.findings_task_text(cycle, found, sorted(scopes.paths(conn, work["id"])))
    return f"cycle:{cycle}", text


def _gate(state, work, wt: Path) -> tuple[str, str]:
    if not work["pr_number"]:
        raise TaskError("nessuna PR nota per questo lavoro: il commento del gate si legge dalla "
                        "PR, aprila prima con /tollgate:finish")
    try:
        comments = gh.pr_comments(state, git.main_worktree(wt), work["pr_number"])
    except gh.GhError as e:
        raise TaskError(f"commenti della PR non leggibili: {e}") from e
    # il marcatore lo scrive chiunque sappia commentare: contano solo i commenti del bot
    marked = [c["body"] for c in comments
              if isinstance(c.get("body"), str) and c["body"].lstrip().startswith(GATE_MARKER)
              and (c.get("author") or {}).get("login") in ghcli.BOT_LOGINS]
    if not marked:
        raise TaskError(f"nessun commento del gate sulla PR #{work['pr_number']} (deve "
                        f"cominciare con {GATE_MARKER} e essere del bot di GitHub Actions)")
    # lo SHA è quello che il gate ha giudicato, non la punta di adesso
    sha = comment.marker_sha(marked[-1])
    if sha is None:
        raise TaskError("commento del gate senza SHA: il marcatore non porta la testa giudicata")
    return f"gate:{sha}", briefs.gate_task_text(sha, marked[-1].strip()[:MAX_COMMENT])


def _create(state, cwd: Path, claude_dir: Path, now, make) -> tuple[Path, str]:
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        raise TaskError(str(e)) from e
    try:
        work = sessions.work_for_path(conn, cwd)
        if work is None:
            raise TaskError("nessun lavoro attivo per questa cartella: lancia il comando dal "
                            "worktree del lavoro")
        if work["level"] == "L0":
            raise TaskError("in L0 lavora la sessione principale: non ci sono task da assegnare")
        if work["phase"] != "execution":
            raise TaskError(f"la fase è {work['phase']}: un task di correzione si crea in "
                            "execution")
        source, text = make(conn, work, Path(work["worktree"]))
        # Una sola transazione: se il brief o l'assegnazione falliscono il task non resta.
        with db.tx(conn):
            if conn.execute("SELECT 1 FROM tasks WHERE work = ? AND source = ?",
                            (work["id"], source)).fetchone():
                raise TaskError(f"esiste già un task di correzione con origine {source}")
            number = tasks.next_number(conn, work["id"])
            tasks.add_task(conn, work["id"], number, source=source, kind="fix",
                           task_text=text, now=now)
            return taskcmd._task_start(state, conn, cwd, number, fix=False,
                                       claude_dir=Path(claude_dir), now=now)
    except (sqlite3.Error, tasks.TaskTransitionError, phases.TransitionError,
            git.GitError) as e:
        raise TaskError(str(e)) from e
    finally:
        conn.close()
