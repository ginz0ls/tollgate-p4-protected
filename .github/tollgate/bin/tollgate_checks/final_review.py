"""SubagentStop (spec 8.6, 7.3; decisioni 6, 7 e 8 di P3b): verdetti della revisione finale.

Possiede la chiusura dei revisori finali (e degli specialisti di L2) e del verificatore in
attesa: sola lettura, verdetto e riga del subagente. `subagent_stop` li salta
(`_common.awaiting_final`). Qui si registra solo il riporto; l'esito del ciclo e i blocchi li
decide `reviews` dalle operazioni `review_report` e `finding_verify` (non dall'`outcome`
dichiarato, salvo `needs_you`). Un verdetto non valido non ha veti: chiude la riga e apre un
blocco `needs_you`."""
from __future__ import annotations

from pathlib import Path

from tollgate_analysis import report, verdicts
from tollgate_core import reviews, subagents
from tollgate_hooks.model import record

from . import _common

CHECK = {"api": 1, "events": ["subagent_stop"], "component": "final_review", "order": 15}


def _invalid(row, work, tokens, what: str, problems: list[str]) -> list:
    return [record("subagent_finish", agent_id=row["id"], state="done", tokens=tokens),
            record("block", work=work["id"], type="needs_you",
                   reason=f"{what} non valido: {'; '.join(problems)}"[:500])]


def decide(event, ctx):
    if not event.agent_type or not event.agent_id:
        return []
    row = subagents.get(ctx.db, event.agent_id)
    if row is None or row["started"] is None:
        return []
    found = _common.awaiting_final(ctx, row)
    if found is None:
        return []
    work, cycle, role = found
    if ctx.component("readonly_check") and work["worktree"] \
            and _common.fingerprint_changed(ctx, row, Path(work["worktree"])):
        return _common.tampered_records(row, work)
    aid, number = row["id"], cycle["number"]
    tokens = report.transcript_tokens(event.raw.get("agent_transcript_path") or "")
    msg = event.raw.get("last_assistant_message") or row["report"]
    if role == "reviewer":
        v = verdicts.parse_final_verdict(msg, sha=cycle["sha"], code=cycle["code"])
        if not v.valid:
            return _invalid(row, work, tokens, "verdetto del revisore finale", v.problems)
        return [record("review_report", work=work["id"], cycle=number, source=row["type"],
                       outcome=v.outcome, findings=v.findings, rejected=v.rejected),
                record("subagent_finish", agent_id=aid, state="done", declared_status=v.outcome,
                       tokens=tokens)]
    ids = set(reviews.unjudged_ids(ctx.db, work["id"], number))
    r = verdicts.parse_verifier_results(msg, sha=cycle["sha"], code=cycle["code"], ids=ids)
    if not r.valid:
        return _invalid(row, work, tokens, "risultati del verificatore", r.problems)
    return [record("finding_verify", work=work["id"], cycle=number, results=r.results),
            record("subagent_finish", agent_id=aid, state="done", tokens=tokens)]
