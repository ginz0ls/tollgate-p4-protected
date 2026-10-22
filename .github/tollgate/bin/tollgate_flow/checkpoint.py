"""`tollgate status --checkpoint` (spec 6.3, 12.4): punto di ripresa nel worktree.

Il file `docs/superpowers/reviews/<N>/checkpoint.md` è ignorato da git (info/exclude): non sporca
il worktree. `SessionStart` ne inietta le ultime righe, perciò il prossimo passo è l'ultima."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from tollgate_analysis import profiles as prof
from tollgate_core import audits, clock, db, reviews, sessions
from tollgate_core.paths import program_command
from tollgate_core.tasks import STATES

from . import audit, gitw

# Prefisso del motivo del blocco -> nome del tetto. I tetti dell'audit (decisione 20) non sono
# in `CAP_PREFIXES`: il loro passo è `resolve`, non `approve rounds`.
CAPS = {"budget superato": "budget del task", "giri di correzione esauriti": "giri di correzione",
        reviews.CAP_REASON: "cicli di revisione",
        audits.CAP_REASONS["spec-adversarial"]: "giri avversariali della spec",
        audits.CAP_REASONS["plan-adversarial"]: "giri avversariali del piano",
        audits.CAP_REASONS["spec-lens"]: "audit a lenti",
        audits.DECLINE_REASON: "audit a lenti"}
CAP_PREFIXES = ("giri di correzione esauriti sul task", reviews.CAP_REASON)
MAX_NOTES = 5
EXCLUDE = "docs/superpowers/reviews/*/checkpoint.md"
NOTES_HEADER = "## Note"
NEXT_PREFIX = "prossimo passo:"


class CheckpointError(Exception):
    pass


def stopped_by(conn, work: int) -> list[str]:
    out = []
    for b in conn.execute("SELECT id, reason FROM blocks WHERE work = ? AND closed IS NULL "
                          "ORDER BY id", (work,)):
        for prefix, name in CAPS.items():
            if b["reason"].startswith(prefix):
                out.append(f"tetto: {name} (blocco {b['id']})")
                break
    return out


ROUNDS_ASK = ("serve una decisione dell'utente: /tollgate:approve rounds <n>, "
              "/tollgate:resolve {block} o /tollgate:abandon #{issue}")


def _cap_step(conn, work: int, issue: int) -> str | None:
    """Tetto dei giri di correzione, dei cicli di revisione (m12, decisione 13) o dell'audit."""
    for b in conn.execute("SELECT id, reason FROM blocks WHERE work = ? AND closed IS NULL "
                          "ORDER BY id", (work,)):
        if audits.cap_kind(b["reason"]) is not None:
            return audit.STEPS["resolve"].replace("<id>", str(b["id"]))
        if b["reason"].startswith(CAP_PREFIXES):
            return f"{b['reason']}: " + ROUNDS_ASK.format(block=b["id"], issue=issue)
    return None


def _review_brief(worktree: str, issue: int) -> str | None:
    """L'ultimo brief del revisore di task scritto da `review-prepare` (`review-<k>.md`)."""
    run_dir = Path(worktree) / ".tollgate-run" / str(issue)
    if not run_dir.is_dir():
        return None
    found = [(int(p.stem.split("-")[1]), p) for p in run_dir.glob("review-*.md")
             if p.stem.split("-")[1].isdigit()]
    return str(max(found)[1]) if found else None


def _closing_step(conn, item, prog: str) -> str:
    """Prossimo passo a task tutti `done`, secondo fase e ultimo ciclo di revisione."""
    phase, issue, wid = item["phase"], item["issue"], item["id"]
    if phase == "pr_open":
        if not item["pr_number"]:
            return (f"PR chiusa senza merge: /tollgate:start #{issue} --reopen-execution, poi "
                    f"/tollgate:finish per aprirne una nuova (oppure /tollgate:abandon #{issue})")
        return (f"PR #{item['pr_number']} aperta: attendi il gate; per correggere "
                f"/tollgate:start #{issue} --reopen-execution; se il predefinito è avanzato "
                "/tollgate:sync")
    if phase not in ("execution", "review"):
        return "/tollgate:finish"
    cycle = reviews.latest(conn, wid)
    if cycle is not None and cycle["outcome"] == "needs_fix":
        n = cycle["number"]
        if not conn.execute("SELECT 1 FROM tasks WHERE work = ? AND source = ?",
                            (wid, f"cycle:{n}")).fetchone() and reviews.blocking_open(conn, wid, n):
            return f"{prog} task start --from-findings {n}"
    if phase == "execution":
        return "/tollgate:finish"
    if item["level"] == "L0":
        return f"{prog} finish open-pr"
    if cycle is None or cycle["outcome"] == "superseded":
        return f"revisione finale da preparare: {prog} review prepare"
    n = cycle["number"]
    if cycle["stage"] == "review":
        return f"ciclo {n} in stadio review: {prog} review prepare (elenca i revisori da lanciare)"
    if cycle["stage"] == "verify":
        return (f"ciclo {n} in stadio verify: {prog} review prepare (prepara il brief del "
                "verificatore da lanciare)")
    if cycle["outcome"] == "ok":
        return f"{prog} finish open-pr"
    if cycle["outcome"] == "needs_you":
        return "serve una decisione dell'utente (blocco needs_you): /tollgate:resolve"
    return "/tollgate:finish"


def next_step(conn, work: int) -> str:
    item = conn.execute("SELECT * FROM work_items WHERE id = ?", (work,)).fetchone()
    capped = _cap_step(conn, work, item["issue"])
    if capped:
        return capped
    row = conn.execute("SELECT * FROM tasks WHERE work = ? AND state <> 'done' "
                       "ORDER BY number LIMIT 1", (work,)).fetchone()
    prog = program_command(db.BIN_PATH)
    if row is None:
        phase = item["phase"]
        if item["level"] == "L2" and phase in ("spec_audit", "plan", "approval"):
            return audit.peek(conn, item)
        if phase == "plan":
            return ("scrivi il piano con superpowers:writing-plans (intestazioni di 7.5), "
                    "committalo, poi /tollgate:execute")
        return _closing_step(conn, item, prog)
    k, state = row["number"], row["state"]
    if state == "pending":
        return f"task {k} pending: {prog} task start {k}"
    if state == "running":
        who = row["implementer"] or "del task"
        return f"task {k} running: attendi o riprendi l'implementatore {who}"
    if state == "blocked":
        return f"task {k} blocked: /tollgate:resolve"
    if row["verdict"] == "approved":
        return f"task {k} in review, approvato: {prog} task done {k}"
    if row["verdict"] == "changes" and row["review_sha"] is not None:
        return f"task {k} in review, da correggere: {prog} task start {k} --fix"
    if (row["verdict"] is None and row["review_sha"] is not None
            and row["review_code"] is not None):
        brief = _review_brief(item["worktree"], item["issue"])
        if brief is not None:
            who = row["reviewer_type"] or prof.DEFAULT_REVIEWER
            return (f"task {k} in review, revisione preparata: lancia il revisore {who} "
                    f'con il brief "{brief}"')
    return f"task {k} in review: {prog} task review-prepare {k}"


def _previous_notes(path: Path) -> list[list[str]]:
    """Le note già scritte: una voce inizia con «- », le righe che seguono sono rientrate."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    notes: list[list[str]] = []
    inside = False
    for ln in lines:
        if ln == NOTES_HEADER:
            inside = True
        elif inside and ln.startswith("- "):
            notes.append([ln])
        elif inside and ln.startswith("  ") and notes:
            notes[-1].append(ln)
        elif inside:
            break
    return notes


def _note_lines(note: str, now) -> list[str]:
    parts = [p.rstrip() for p in note.strip().splitlines()] or [""]
    return [f"- {clock.fmt(now)} {parts[0]}"] + [f"  {p}" for p in parts[1:]]


def write_checkpoint(state, cwd, *, note: str | None, now=None) -> Path:
    now = now or clock.now()
    try:
        conn = db.open_db(state)
    except db.DbError as e:
        raise CheckpointError(str(e)) from e
    try:
        work = sessions.work_for_path(conn, cwd)
        if work is None:
            raise CheckpointError("nessun lavoro attivo per questa cartella: lancia il comando "
                                  "dal worktree del lavoro")
        counts = {r["state"]: r["n"] for r in conn.execute(
            "SELECT state, count(*) AS n FROM tasks WHERE work = ? GROUP BY state",
            (work["id"],))}
        stops, step = stopped_by(conn, work["id"]), next_step(conn, work["id"])
    except sqlite3.Error as e:
        raise CheckpointError(str(e)) from e
    finally:
        conn.close()

    wt = Path(work["worktree"])
    path = wt / "docs" / "superpowers" / "reviews" / str(work["issue"]) / "checkpoint.md"
    notes = _previous_notes(path)
    if note and note.strip():
        notes.append(_note_lines(note, now))
    notes = notes[-MAX_NOTES:]

    plan = (f"{work['plan_path']} (plan_sha {work['plan_sha']})" if work["plan_path"]
            else "nessuno")
    tasks_line = ", ".join(f"{counts[s]} {s}" for s in STATES if s in counts) or "nessuno"
    lines = [f"# Checkpoint #{work['issue']}", f"fase: {work['phase']}, livello {work['level']}",
             f"piano: {plan}", f"task: {tasks_line}", *stops, NOTES_HEADER,
             *[ln for n in notes for ln in n], f"{NEXT_PREFIX} {step}"]
    try:
        gitw.add_excludes(wt, [EXCLUDE])
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    except (OSError, gitw.GitWriteError) as e:
        raise CheckpointError(f"scrittura del checkpoint non riuscita: {e}") from e
    return path
