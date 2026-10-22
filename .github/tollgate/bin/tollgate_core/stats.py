"""Statistiche dagli eventi (spec 3.1, criterio 43): quanto tollgate frena e quanto protegge.

Gli intervalli (OFF, tempo per fase) si costruiscono da tutti gli eventi e poi si tagliano sulla
finestra; solo i conteggi di punti si filtrano con `at >= since`.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from . import clock
from .events import export_events


def _hours(seconds: float) -> float:
    return round(seconds / 3600, 2)


def _off_intervals(evts: list[dict]):
    """Intervalli (da, a) tra `off` e `on`; `a` è None se OFF è ancora attivo."""
    off_at = None
    for e in evts:
        if e["type"] == "off" and off_at is None:
            off_at = clock.parse(e["at"])
        elif e["type"] == "on" and off_at is not None:
            yield off_at, clock.parse(e["at"])
            off_at = None
    if off_at is not None:
        yield off_at, None


def _off_seconds(evts: list[dict], start: datetime | None, end: datetime) -> float:
    return sum(_overlap(a, b or end, start, end) for a, b in _off_intervals(evts))


def off_periods(conn, start: datetime, end: datetime) -> list[dict]:
    """Periodi di OFF tagliati sulla finestra [start, end]: `{"from", "to"}`, con `to` nullo
    se OFF è ancora attivo (spec 18.1, `off_periods`)."""
    switches = [e for e in export_events(conn, 0) if e["type"] in ("off", "on")]
    out = []
    for a, b in _off_intervals(switches):
        lo = max(a, start)
        hi = None if b is None else min(b, end)
        if lo >= end or (hi is not None and hi <= lo):
            continue
        out.append({"from": clock.fmt(lo), "to": None if hi is None else clock.fmt(hi)})
    return out


def _overlap(a: datetime, b: datetime, start: datetime | None, end: datetime) -> float:
    lo = max(a, start) if start else a
    hi = min(b, end)
    return max(0.0, (hi - lo).total_seconds())


def _phase_intervals(changes: list[dict], end: datetime):
    for cur, nxt in zip(changes, changes[1:] + [None]):
        stop = clock.parse(nxt["at"]) if nxt else end
        yield cur["data"]["to"], clock.parse(cur["at"]), stop


def compute_stats(conn, *, now: datetime, work: int | None = None,
                  since: datetime | None = None) -> dict:
    """Conteggi e tempi. Il `phase_hours` globale somma i lavori paralleli: non e' tempo reale."""
    every = export_events(conn, 0)
    since_s = clock.fmt(since) if since is not None else None
    if work is not None:
        scope = [e for e in every if e["work"] == work]
        first = clock.parse(scope[0]["at"]) if scope else now
        closing = [e for e in scope if e["type"] == "phase_change" and e["data"]["to"] == "closed"]
        end = clock.parse(closing[-1]["at"]) if closing else now
        start = max(first, since) if since is not None else first
    else:
        scope = every
        start, end = since, now
    switches = [e for e in every if e["type"] in ("off", "on")]
    inside = [e for e in scope if since_s is None or e["at"] >= since_s]

    vetoes = Counter(e["data"].get("rule", "?") for e in inside if e["type"] == "veto")
    opened = [e for e in inside if e["type"] == "block_opened"]
    tokens = Counter()
    for e in inside:
        if e["type"] == "subagent_stop" and e["data"].get("tokens"):
            tokens[e["data"].get("type") or "?"] += e["data"]["tokens"]

    fix_in: dict[tuple, int] = {}
    fix_before: dict[tuple, int] = {}
    for e in scope:
        if e["type"] == "task_change":
            key = (e["work"], e["data"]["number"])
            rounds = e["data"].get("fix_rounds") or 0
            target = fix_before if since_s is not None and e["at"] < since_s else fix_in
            target[key] = max(target.get(key, 0), rounds)
    fix_rounds = sum(max(0, v - fix_before.get(k, 0)) for k, v in fix_in.items())

    by_work: dict[int, list[dict]] = defaultdict(list)
    for e in scope:
        if e["type"] == "phase_change":
            by_work[e["work"]].append(e)
    phase_secs: dict[str, float] = defaultdict(float)
    for changes in by_work.values():
        for phase, a, b in _phase_intervals(changes, now):
            if phase != "closed":
                phase_secs[phase] += _overlap(a, b, start, end)

    phase_hours = {k: _hours(v) for k, v in phase_secs.items()}
    return {
        "vetoes": {"total": sum(vetoes.values()), "by_rule": dict(vetoes)},
        "needs_you": sum(1 for e in opened if e["data"].get("type") == "needs_you"),
        "blocks": len(opened),
        "waivers": sum(1 for e in inside if e["type"] == "waiver_added"),
        "finding_overrides": sum(1 for e in inside if e["type"] == "act"
                                 and e["data"].get("type") == "approve"
                                 and e["data"].get("object") == "finding"),
        "off_hours": _hours(_off_seconds(switches, start, end)),
        "phase_hours": {k: v for k, v in phase_hours.items() if v > 0},
        "tokens": {"total": sum(tokens.values()), "by_agent": dict(tokens)},
        "fix_rounds": fix_rounds,
        "review_cycles": sum(1 for e in inside if e["type"] == "review_cycle"),
    }
