"""SubagentStop (spec 6.2 punto 3, 18.3; decisioni 4, 5 e 7 di P3c): report dei giri di audit.

Possiede la chiusura degli agenti del giro aperto (`spec-adversary`, `spec-auditor`,
`plan-adversary`): `subagent_stop` li salta (`_common.awaiting_audit`), perché i `record` si
applicano anche dopo un veto. Legge la riga JSON finale (`auditrules.parse_round_json`); se è
valida emette `subagent_finish` e poi `audit_report`, che scrive il report, chiude il giro e apre
i blocchi dei tetti. Una riga non valida ha al più due veti, poi `needs_you` e il giro resta
aperto (`audit prepare` lo ristampa con lo stesso codice). Ogni ramo emette `subagent_finish`."""
from __future__ import annotations

from pathlib import Path

from tollgate_analysis import auditrules, report, specdoc
from tollgate_core import audits, git, subagents
from tollgate_hooks.model import deny, record

from . import _common

CHECK = {"api": 1, "events": ["subagent_stop"], "component": None, "order": 15}
MAX_VETOES = 2
ADV_KIND = "spec-adversarial"
UNREADABLE_SPEC = "la spec del giro non si legge: le sezioni del pitch non sono state controllate"


def _mechanical(ctx, work, rnd) -> list[str]:
    """I rilievi meccanici (decisione 8): con `spec_pitch` acceso, una riga per ogni sezione
    della spec che manca. Si legge il blob del giro, non il file del worktree; se il blob non si
    legge il controllo non può dire che la spec è a posto: un rilievo solo."""
    if rnd["kind"] != ADV_KIND or not ctx.component("spec_pitch"):
        return []
    wt = Path(work["worktree"]) if work["worktree"] else None
    text = git.blob_text(wt, rnd["sha"]) if wt is not None and wt.is_dir() else None
    return specdoc.pitch_problems(text) if text is not None else [UNREADABLE_SPEC]


def decide(event, ctx):
    if not event.agent_type or not event.agent_id:
        return []
    row = subagents.get(ctx.db, event.agent_id)
    if row is None or row["started"] is None:
        return []
    rnd = _common.awaiting_audit(ctx, row)
    if rnd is None:
        return []
    aid, kind = row["id"], rnd["kind"]
    tokens = report.transcript_tokens(event.raw.get("agent_transcript_path") or "")
    if not ctx.component(audits.COMPONENTS[kind]):
        return [record("subagent_finish", agent_id=aid, state="done", tokens=tokens)]
    work = ctx.db.execute("SELECT * FROM work_items WHERE id = ?", (rnd["work"],)).fetchone()
    if ctx.component("readonly_check") and work["worktree"] \
            and _common.fingerprint_changed(ctx, row, Path(work["worktree"])):
        return _common.tampered_records(row, work)
    msg = event.raw.get("last_assistant_message") or row["report"]
    parsed = auditrules.parse_round_json(
        msg, kind=kind, number=rnd["number"], code=rnd["code"], spec_sha=rnd["spec_sha"],
        plan_sha=rnd["sha"] if kind == auditrules.PLAN_KIND else None,
        viewpoint=rnd["viewpoint"])
    if not parsed.valid:
        why = "; ".join(parsed.problems)
        if row["vetoes"] >= MAX_VETOES:
            return [record("subagent_finish", agent_id=aid, state="done", tokens=tokens),
                    record("block", work=work["id"], type="needs_you",
                           reason=f"report del giro non valido: {why}"[:500])]
        return [record("subagent_veto", agent_id=aid),
                deny(f"report del giro non valido: {why}. Chiudi con la riga JSON del brief, con "
                     f"kind, number, code e SHA del giro alla lettera (veto "
                     f"{row['vetoes'] + 1} di {MAX_VETOES})", rule="audit_round")]
    extra = _mechanical(ctx, work, rnd)
    counts = dict(parsed.counts)
    counts["major"] += len(extra)
    return [record("subagent_finish", agent_id=aid, state="done",
                   declared_status=auditrules.outcome(counts), tokens=tokens),
            record("audit_report", work=work["id"], kind=kind, number=rnd["number"],
                   counts=counts, body=msg, extra=extra)]
