"""SubagentStop (spec 7.2, 8.1, 6.3, 7.3): implementatori e sola lettura. Il revisore del task in
attesa è di `task_verdict`, i revisori finali e il verificatore in attesa di `final_review`,
gli agenti di un giro di audit aperto (avversari e auditor di spec e piano) di `audit_round`."""
from __future__ import annotations

import json
from pathlib import Path

from tollgate_analysis import report, size
from tollgate_core import dod, git, receipts, subagents
from tollgate_core.paths import program_command
from tollgate_core.verify import counts_green, gate_commands
from tollgate_hooks.model import deny, record

from . import _common

CHECK = {"api": 1, "events": ["subagent_stop"], "component": None, "order": 20}
MAX_VETOES = 2
MAX_SIZE_REASON = 500


def _readonly(ctx, row, work):
    """7.3: un subagente di sola lettura che cambia l'impronta del worktree non vale."""
    if ctx.component("readonly_check") and work is not None and work["worktree"] \
            and _common.fingerprint_changed(ctx, row, Path(work["worktree"])):
        return _common.tampered_records(row, work)
    return [record("subagent_finish", agent_id=row["id"], state="done")]


def _task_lines(ctx, wt: Path, base: str, head: str) -> int:
    return size.task_lines(git.changes(wt, base, head=head), set(ctx.cfg("scope.lockfiles")))


def _size_reason(rep) -> str | None:
    """Il motivo dichiarato per un task oltre `task_lines_max`: va nell'evento, da cui lo legge
    il blocco 18.1 (decisione 21). Testo del subagente, quindi tagliato."""
    reason = rep.data.get("size_reason") if rep.valid else None
    return str(reason)[:MAX_SIZE_REASON] if reason else None


def _skill_missing(task) -> list[str]:
    used = json.loads(task["skills_used"])
    tail = {u.split(":")[-1] for u in used}
    return [s for s in json.loads(task["skills_required"])
            if s not in used and s.split(":")[-1] not in tail]


def _receipt_ok(ctx, work, head: str, wt: Path) -> bool:
    """Decisione 24: una ricevuta `related` green sull'ultimo commit basta. Altrimenti vale la
    stessa regola della DoD (`dod.receipt_verdict`): tutti i comandi del gate, profili attivi
    compresi, presenti e green. Una `related` vuota o rossa non pesa sul gate."""
    allow = ctx.cfg("project.allow_no_tests")
    latest = receipts.latest(ctx.db, work["id"], head)
    if any(r["command"] == "related" and counts_green(r["state"], r["exit"], allow)
           for r in latest):
        return True
    base = work["work_base_sha"]
    files = [c.path for c in git.changes(wt, base, head=head) if c.status != "D"] if base else []
    required = [s.name for s in gate_commands(ctx.config, files)]
    return dod.receipt_verdict([r for r in latest if r["command"] != "related"], head, allow,
                               required)[0]


def decide(event, ctx):
    if not event.agent_type or not event.agent_id:
        return []
    row = subagents.get(ctx.db, event.agent_id)
    if row is None or row["started"] is None:
        return []      # subagente interno di Claude Code, mai visto a SubagentStart (P0)
    if row["state"] != "running":
        return []      # già chiuso (es. `cut` da post_agent o prompt_submit): non si riscrive
    work = ctx.db.execute("SELECT * FROM work_items WHERE id = ?",
                          (row["work"],)).fetchone() if row["work"] is not None else None
    if ctx.readonly(event.agent_type):
        if _common.awaiting_review(ctx, row) or _common.awaiting_final(ctx, row) \
                or _common.awaiting_audit(ctx, row):
            return []      # lo chiude task_verdict (decisione 11), final_review o audit_round
        return _readonly(ctx, row, work)
    msg = event.raw.get("last_assistant_message")
    # Il report resta nel DB anche in modalità manuale: `review-prepare` ne legge i dubbi.
    saved = [record("subagent_report", agent_id=row["id"], text=msg)] \
        if isinstance(msg, str) and msg else []
    return saved + _implementer(event, ctx, row, work)


def _implementer(event, ctx, row, work):
    if work is None or not work["worktree"]:
        return [record("subagent_finish", agent_id=row["id"], state="done")]
    wid, aid = work["id"], row["id"]
    task = None
    if row["task"] is not None:
        task = ctx.db.execute("SELECT * FROM tasks WHERE work = ? AND number = ?",
                              (wid, row["task"])).fetchone()
    running = task is not None and task["state"] == "running"
    tokens = report.transcript_tokens(event.raw.get("agent_transcript_path") or "")
    cap = ctx.cfg("tasks.max_tokens").get(work["level"], 0)
    if ctx.component("task_budget") and cap and tokens > cap and running:
        return [record("subagent_finish", agent_id=aid, state="budget", tokens=tokens),
                record("task", work=wid, number=task["number"], event="budget_exceeded"),
                record("block", work=wid, type="needs_you",
                       reason=f"budget superato: {tokens} token oltre il tetto di {cap} sul task "
                              f"{task['number']}. Proposta: dividere il task")]
    rep = report.parse_report(event.raw.get("last_assistant_message") or row["report"])

    def veto(msg: str):
        if row["vetoes"] >= MAX_VETOES:
            out = [record("subagent_finish", agent_id=aid, state="done",
                          declared_status=rep.status if rep.valid else None, tokens=tokens,
                          size_reason=_size_reason(rep))]
            if running:
                out.append(record("task", work=wid, number=task["number"],
                                  event="report_blocked"))
            return out + [record("block", work=wid, type="needs_you",
                                 reason=f"implementatore chiuso dopo {MAX_VETOES} veti: {msg}")]
        return [record("subagent_veto", agent_id=aid),
                deny(f"{msg} (veto {row['vetoes'] + 1} di {MAX_VETOES})",
                     rule="subagent_stop")]

    if ctx.component("report_fields") and not rep.valid:
        why = ("status sconosciuto" if rep.unknown_status and not rep.missing
               else "mancano " + ", ".join(rep.missing))
        return veto(f"report finale non valido: {why}. Chiudi con un blocco JSON con i campi "
                    f"di 18.5")
    wt = Path(work["worktree"])
    head, base = git.head(wt), row["agent_base_sha"]
    commits = git.rev_list(wt, base, head) if base and head and base != head else []
    if ctx.component("task_size") and commits and not rep.data.get("size_reason"):
        lines = _task_lines(ctx, wt, base, head)
        if lines > ctx.cfg("tasks.task_lines_max"):
            return veto(f"il task cambia {lines} righe, oltre task_lines_max "
                        f"({ctx.cfg('tasks.task_lines_max')}): aggiungi size_reason al report "
                        f"oppure dividi il task")
    done = rep.status in ("DONE", "DONE_WITH_CONCERNS")
    if ctx.component("subagent_receipt_gate"):
        if done and commits:
            if not _receipt_ok(ctx, work, head, wt):
                return veto(f"DONE senza ricevuta green su {head[:10]}: lancia "
                            f"{program_command(ctx.plugin_bin)} verify")
        elif done:
            if _common.fingerprint_changed(ctx, row, wt):
                return veto("file modificati senza commit: committa e verifica")
        else:
            has_block = ctx.db.execute("SELECT 1 FROM blocks WHERE work = ? AND closed IS NULL",
                                       (wid,)).fetchone() is not None
            if not has_block and not receipts.any_since(ctx.db, wid, row["started"]):
                prog = program_command(ctx.plugin_bin)
                return veto(f"con {rep.status} serve una ricevuta ({prog} verify) "
                            f"oppure un blocco ({prog} block open <tipo> --reason …)")
    if done and task is not None:
        missing = _skill_missing(task)
        if missing:
            return veto("skill dei profili non usate: " + ", ".join(missing))
    out = [record("subagent_finish", agent_id=aid, state="done", declared_status=rep.status,
                  tokens=tokens, size_reason=_size_reason(rep))]
    if running:
        if done:
            out.append(record("task", work=wid, number=task["number"], event="report_done"))
        elif rep.status == "BLOCKED":
            out.append(record("task", work=wid, number=task["number"], event="report_blocked"))
            if ctx.db.execute("SELECT 1 FROM blocks WHERE work = ? AND closed IS NULL",
                              (wid,)).fetchone() is None:
                out.append(record("block", work=wid, type="needs_you",
                                  reason=f"task {task['number']} BLOCKED: "
                                         f"{rep.data.get('concerns') or rep.data.get('left') or ''}"[:500]))
    return out
