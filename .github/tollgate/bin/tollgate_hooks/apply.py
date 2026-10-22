"""Operazioni `record` dei controlli (decisione 6): ognuna scrive con tollgate_core."""
from __future__ import annotations

import getpass
import os

from pathlib import Path

from tollgate_analysis import approvals, auditrules, brief, profiles as prof
from tollgate_core import (acts, audits, effects, events, git, phases, reviews, scope, sessions,
                           subagents, tasks, violations)

REPORT_MAX_CHARS = 60000


def _actor() -> str | None:
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        return None


def _bind(conn, state, ctx, d):
    phases.bind_session(conn, d["work"], ctx.event.session, now=ctx.now)
    sessions.mark_bound(state, ctx.event.session)


def _act(conn, state, ctx, d):
    acts.record_act(conn, type_=d["type"], object_=d.get("object"), target=d.get("target"),
                    args=d.get("args"), typed_text=d.get("typed_text", ""), actor=_actor(),
                    session=ctx.event.session, work=d.get("work"), head_sha=d.get("head_sha"),
                    now=ctx.now, ttl_minutes=ctx.cfg("acts.ttl_minutes"))


def _subagent_start(conn, state, ctx, d):
    task = d.get("task")
    if d.get("take_pending") and d.get("work") is not None:
        # Una ripresa sa già di quale task è: cerca solo quello (più task dello stesso tipo).
        resume = bool(d.get("resume"))
        task = tasks.take_pending(conn, d["work"], agent_type=d["type"], resume=resume,
                                  number=task if resume else None) or task
    subagents.start(conn, agent_id=d["agent_id"], type_=d["type"], session=ctx.event.session,
                    work=d.get("work"), task=task, base_sha=d.get("base_sha"),
                    fingerprint=d.get("fingerprint"), now=ctx.now,
                    refresh_fingerprint=bool(d.get("refresh_fingerprint")))


def _commit(conn, state, ctx, d):
    events.record_event(conn, "commit", {"sha": d["sha"]}, now=ctx.now,
                        session=ctx.event.session, work=d["work"])
    acts.invalidate_finish(conn, d["work"], d.get("head") or d["sha"], now=ctx.now,
                           session=ctx.event.session)


def _invalidate_finish(conn, state, ctx, d):
    acts.invalidate_finish(conn, d["work"], d["head"], now=ctx.now, session=ctx.event.session)


def _effect_execute(conn, state, ctx, d):
    act = acts.find_usable(conn, type_="approve", object_="effect",
                           target=effects.effect_id(d["key"]), work=d.get("work"),
                           session=ctx.event.session, now=ctx.now)
    if act is None:
        raise acts.ActError("atto approve effect non più valido")
    acts.consume(conn, act["act_id"], type_="approve", object_="effect",
                 target=effects.effect_id(d["key"]), now=ctx.now, work=d.get("work"),
                 session=ctx.event.session)
    effects.mark_executed(conn, key=d["key"], act_id=act["act_id"], now=ctx.now,
                          session=ctx.event.session)


def _final_rules(ctx, work, sha: str) -> tuple[set[str], set[str]]:
    """Regole `[blocca]` e note dei profili attivi sul diff del ciclo (decisione 8). Se il diff
    non si legge, nessun profilo è attivo: ogni `R-…` blocca (fail-closed)."""
    wt = Path(work["worktree"]) if work["worktree"] else None
    names: list[str] = []
    if wt is not None and wt.is_dir():
        try:
            names = violations.active_profile_names(ctx.config, wt, work, head=sha)
        except git.GitError:
            names = []
    profs = ctx.config.profiles
    return prof.blocking_rules(names, profs), prof.known_rules(names, profs)


def _review_report(conn, state, ctx, d):
    """Riporto di un revisore finale. Un riporto non più accettabile (ciclo non in stadio
    review, fonte non attesa o già riportata: una corsa) non si applica, mai un'eccezione: lascia
    l'evento `veto` con il motivo."""
    wid, n = d["work"], d["cycle"]
    work = phases.get_work(conn, wid)
    cycle = conn.execute("SELECT sha FROM review_cycles WHERE work = ? AND number = ?",
                         (wid, n)).fetchone()
    if cycle is None:
        return
    blocking, known = _final_rules(ctx, work, cycle["sha"])
    try:
        stage = reviews.add_report(conn, wid, n, source=d["source"], outcome=d["outcome"],
                                   findings=d["findings"], rejected=d["rejected"],
                                   blocking_rules=blocking, known_rules=known, now=ctx.now)
    except ValueError as e:
        events.record_event(conn, "veto", {"event": "subagent_stop", "rule": "final_review",
                                           "reason": str(e)}, now=ctx.now,
                            session=ctx.event.session or None, work=wid)
        return
    if stage == "verify" and not reviews.unjudged_ids(conn, wid, n):
        reviews.close_cycle(conn, state, wid, n, now=ctx.now, session=ctx.event.session)


def _finding_verify(conn, state, ctx, d):
    """Esiti del verificatore. A zero rilievi senza esito chiude il ciclo; altrimenti conta il
    riporto incompleto (dal secondo, `needs_you`)."""
    wid, n = d["work"], d["cycle"]
    cycle = conn.execute("SELECT stage FROM review_cycles WHERE work = ? AND number = ?",
                         (wid, n)).fetchone()
    if cycle is None or cycle["stage"] != "verify":
        return
    left = reviews.apply_verification(conn, wid, n, d["results"], now=ctx.now)
    if left == 0:
        reviews.close_cycle(conn, state, wid, n, now=ctx.now, session=ctx.event.session)
    else:
        reviews.verifier_incomplete(conn, state, wid, n, now=ctx.now, session=ctx.event.session)


def _write_atomic(path: Path, text: str) -> None:
    """Scrive `path` con un file temporaneo accanto e `os.replace`; `OSError` o `ValueError` (testo
    non codificabile) se non riesce, e in ogni caso il temporaneo non resta."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except (OSError, ValueError):
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _report_body(title: str, msg: str, extra: list[str]) -> str:
    """Corpo del report: i rilievi meccanici e il messaggio dell'agente (testo non fidato, in
    un recinto, troncato a `REPORT_MAX_CHARS`)."""
    cut = len(msg) - REPORT_MAX_CHARS
    if cut > 0:
        msg = msg[:REPORT_MAX_CHARS]
    out = [f"# {title}", ""]
    out += [f"rilievo meccanico: {line}" for line in extra]
    out += ["", brief.DATA_NOTE, "", brief.fence(msg), msg, brief.fence(msg)]
    if cut > 0:
        out += ["", f"(messaggio troncato: {cut} caratteri omessi)"]
    return "\n".join(out) + "\n"


def _audit_veto(conn, ctx, wid, reason: str) -> None:
    events.record_event(conn, "veto", {"event": "subagent_stop", "rule": "audit_round",
                                       "reason": reason}, now=ctx.now,
                        session=ctx.event.session or None, work=wid)


def _cap_block(conn, state, ctx, wid, kind: str, number: int, counts: dict) -> None:
    """Blocchi dei tetti (decisione 7), contando i giri chiusi non `superseded` del tipo. Il
    tetto dei cicli a lenti si confronta per uguaglianza: i cicli di conferma oltre il tetto
    non lo riaprono."""
    done = len(audits.rounds(conn, wid, kind))
    if kind == "spec-adversarial":
        hit = done >= ctx.cfg("spec_audit.spec_rounds") and not auditrules.is_clean(counts)
    elif kind == auditrules.PLAN_KIND:
        hit = done >= ctx.cfg("spec_audit.plan_rounds") and not auditrules.is_clean(counts)
    else:
        rows = audits.rounds(conn, wid, kind)
        closed = auditrules.lens_state([(r["viewpoint"], r["outcome"]) for r in rows]).closed
        hit = done == ctx.cfg("spec_audit.spec_audit_cycles") and not closed
    if hit:
        phases.open_block(conn, state, wid, "needs_you", audits.cap_reason(kind, number),
                          now=ctx.now, session=ctx.event.session)


def _audit_report(conn, state, ctx, d):
    """Report valido di un giro (decisione 5): scrive il file, chiude il giro, rigenera lo stato
    delle lenti, apre i blocchi dei tetti. Un giro non più aperto con quel numero (superato o
    chiuso: una corsa) si ignora; una scrittura che fallisce lascia il giro aperto. In entrambi i
    casi un evento `veto`, mai un'eccezione."""
    wid, kind, number = d["work"], d["kind"], d["number"]
    rnd = conn.execute("SELECT * FROM spec_audit WHERE work = ? AND kind = ? AND number = ? "
                       "AND stage = 'open'", (wid, kind, number)).fetchone()
    if rnd is None:
        _audit_veto(conn, ctx, wid, "giro non più aperto")
        return
    work = phases.get_work(conn, wid)
    counts = d["counts"]
    outcome = auditrules.outcome(counts)
    rel = f"{approvals.REVIEWS_DIR}/{work['issue']}/{kind}-{number}.md"
    fields = {"schema_version": 1, "kind": kind, "number": number, "viewpoint": rnd["viewpoint"],
              "spec_sha": rnd["spec_sha"]}
    if kind == auditrules.PLAN_KIND:
        fields["plan_sha"] = rnd["sha"]
    fields.update(counts=counts, outcome=outcome)
    title = f"Report {kind} {number}, lavoro #{work['issue']}"
    wt = Path(work["worktree"]) if work["worktree"] else None
    try:
        if wt is None or not wt.is_dir():
            raise FileNotFoundError("worktree assente")
        _write_atomic(wt / rel, approvals.render_report(
            fields, _report_body(title, d["body"], d.get("extra") or [])))
    except (OSError, ValueError) as e:
        _audit_veto(conn, ctx, wid, f"report non scritto: {e}")
        return
    audits.close_round(conn, wid, kind=kind, number=number, counts=counts, outcome=outcome,
                       report_path=rel, now=ctx.now)
    if kind == auditrules.LENS_KIND:
        lens = auditrules.lens_state([(r["viewpoint"], r["outcome"])
                                      for r in audits.rounds(conn, wid, kind)])
        text = auditrules.render_lens_status(
            lens, issue=work["issue"], cap=ctx.cfg("spec_audit.spec_audit_cycles"),
            suspended=kind in audits.suspended(conn, wid))
        try:
            _write_atomic(wt / approvals.REVIEWS_DIR / str(work["issue"]) / "spec-lens-stato.md",
                          text)
        except (OSError, ValueError) as e:
            _audit_veto(conn, ctx, wid, f"stato delle lenti non scritto: {e}")
    _cap_block(conn, state, ctx, wid, kind, number, counts)


_OPS = {
    "event": lambda c, s, x, d: events.record_event(c, d["type"], d.get("data"), now=x.now,
                                                    session=x.event.session, work=d.get("work")),
    "bind": _bind,
    "cli_call": lambda c, s, x, d: sessions.note_cli_call(s, x.event.session, d["cwd"],
                                                          d["argv"], now=x.now),
    "act": _act,
    "expire_acts": lambda c, s, x, d: acts.expire_stale(c, now=x.now, session=x.event.session),
    "block": lambda c, s, x, d: phases.open_block(c, s, d["work"], d["type"], d["reason"],
                                                  now=x.now, session=x.event.session),
    "level": lambda c, s, x, d: phases.set_level(c, d["work"], d["level"], now=x.now,
                                                 session=x.event.session),
    "phase": lambda c, s, x, d: phases.set_phase(c, s, d["work"], d["to"], d["cause"],
                                                 now=x.now, session=x.event.session),
    "plan": lambda c, s, x, d: scope.register_plan(
        c, s, d["work"], plan_path=d["plan_path"], plan_sha=d["plan_sha"],
        scope_paths=d["scope"], plan_tasks=[tuple(t) for t in d["tasks"]],
        advance=d["advance"], now=x.now, session=x.event.session),
    "plan_path": lambda c, s, x, d: scope.set_plan_path(c, d["work"], d["plan_path"], now=x.now),
    "subagent_start": _subagent_start,
    "subagent_name": lambda c, s, x, d: subagents.set_name(c, d["agent_id"], d["name"],
                                                           session=x.event.session,
                                                           work=d.get("work"), now=x.now),
    "subagent_report": lambda c, s, x, d: subagents.set_report(c, d["agent_id"], d["text"]),
    "subagent_veto": lambda c, s, x, d: subagents.add_veto(c, d["agent_id"]),
    "subagent_finish": lambda c, s, x, d: subagents.finish(
        c, d["agent_id"], state=d["state"], declared_status=d.get("declared_status"),
        tokens=d.get("tokens"), size_reason=d.get("size_reason"), now=x.now,
        session=x.event.session),
    "subagent_interrupt": lambda c, s, x, d: subagents.interrupt(c, d["agent_id"], now=x.now,
                                                                 session=x.event.session),
    "task": lambda c, s, x, d: tasks.task_event(c, d["work"], d["number"], d["event"],
                                                now=x.now, session=x.event.session),
    "task_reserve": lambda c, s, x, d: tasks.reserve(c, d["work"], d["number"], now=x.now),
    "task_verdict": lambda c, s, x, d: tasks.set_verdict(
        c, d["work"], d["number"], outcome=d["outcome"], findings=d["findings"], now=x.now,
        session=x.event.session, dropped=d.get("dropped", 0)),
    "task_commit": lambda c, s, x, d: tasks.add_commit(c, d["work"], d["number"], d["sha"]),
    "skill_used": lambda c, s, x, d: tasks.add_skill_used(c, d["work"], d["number"], d["skill"]),
    "commit": _commit,
    "invalidate_finish": _invalidate_finish,
    "effect_request": lambda c, s, x, d: effects.request(
        c, key=d["key"], command=d["command"], work=d.get("work"), sha=d.get("sha"), now=x.now,
        session=x.event.session),
    "effect_execute": _effect_execute,
    "review_report": _review_report,
    "finding_verify": _finding_verify,
    "audit_report": _audit_report,
}
OPS = frozenset(_OPS)


def apply(conn, state, ctx, decision) -> None:
    fn = _OPS.get(decision.op)
    if fn is None:
        raise ValueError(f"operazione record sconosciuta: {decision.op}")
    fn(conn, state, ctx, decision.data)
