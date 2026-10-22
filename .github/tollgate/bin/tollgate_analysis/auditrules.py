"""Regole pure dell'audit della spec (spec 6.2, 18.3, decisioni 3-6 di P3c): esito di un giro dai
conteggi, riga JSON finale del giro, matrice dei punti di vista dell'audit a lenti, testo di
`spec-lens-stato.md`. Niente DB né file: le usano l'hook dei report, `audit prepare` e il gate."""
from __future__ import annotations

from dataclasses import dataclass, field

from .report import json_candidates

SEVERITIES = ("blocker", "major", "moderate", "minor")
VIEWPOINTS = ("executor", "user", "attacker", "payer", "successor", "skeptic", "edge_case",
              "integrator")
VIEWPOINT_LABELS = {
    "executor": "chi esegue",
    "user": "chi usa",
    "attacker": "chi attacca",
    "payer": "chi paga",
    "successor": "chi arriva dopo",
    "skeptic": "lo scettico",
    "edge_case": "il caso limite",
    "integrator": "chi integra",
}
EMPTY_NEEDED = 2
PLAN_KIND = "plan-adversarial"
LENS_KIND = "spec-lens"


def outcome(counts: dict) -> str:
    """`empty` se `blocker + major + moderate == 0` (ciclo vuoto), altrimenti `findings`."""
    return "empty" if counts["blocker"] + counts["major"] + counts["moderate"] == 0 else "findings"


def is_clean(counts: dict) -> bool:
    """Giro pulito: né blocker né major (6.2)."""
    return counts["blocker"] + counts["major"] == 0


@dataclass
class RoundJson:
    valid: bool
    problems: list[str] = field(default_factory=list)
    counts: dict | None = None


def _counts_ok(raw) -> bool:
    return (isinstance(raw, dict)
            and all(isinstance(raw.get(k), int) and not isinstance(raw.get(k), bool)
                    and raw[k] >= 0 for k in SEVERITIES))


def parse_round_json(text: str, *, kind: str, number: int, code: str, spec_sha: str,
                     plan_sha: str | None, viewpoint: str | None) -> RoundJson:
    """L'ultima riga JSON con `counts` del messaggio finale. Vale solo con `kind`, `number`,
    `code`, `spec_sha` (e `plan_sha` per `plan-adversarial`) e `viewpoint` del giro. L'`outcome`
    dichiarato si ignora. I problemi nominano i campi, mai i valori ricevuti (decisione 5)."""
    cands = json_candidates(text or "", "counts")
    if not cands:
        return RoundJson(False, ["manca la riga JSON del giro (18.3)"])
    data = cands[0]
    problems: list[str] = []
    if data.get("kind") != kind:
        problems.append("kind diverso da quello del giro")
    got = data.get("number")
    if isinstance(got, bool) or got != number:
        problems.append("number diverso da quello del giro")
    if data.get("code") != code:
        problems.append("code diverso da quello del giro")
    if data.get("spec_sha") != spec_sha:
        problems.append("spec_sha diverso da quello del giro")
    if kind == PLAN_KIND and data.get("plan_sha") != plan_sha:
        problems.append("plan_sha diverso da quello del giro")
    if data.get("viewpoint") != (viewpoint if kind == LENS_KIND else None):
        problems.append("viewpoint diverso da quello del giro")
    if not _counts_ok(data.get("counts")):
        problems.append("counts deve avere blocker, major, moderate e minor, interi non negativi")
    if problems:
        return RoundJson(False, problems)
    return RoundJson(True, [], {k: data["counts"][k] for k in SEVERITIES})


@dataclass
class LensState:
    cycles: dict[str, list[str]]
    streak: dict[str, int]
    closed: bool
    total: int


def lens_state(rows: list[tuple[str, str]]) -> LensState:
    """`rows`: `(punto di vista, esito)` dei cicli chiusi non `superseded`, in ordine. Il contatore
    di un punto di vista è il numero dei suoi cicli vuoti consecutivi; un ciclo con rilievi lo
    azzera (criterio 24). Chiuso quando ogni contatore è almeno 2."""
    cycles: dict[str, list[str]] = {v: [] for v in VIEWPOINTS}
    streak = {v: 0 for v in VIEWPOINTS}
    total = 0
    for vp, out in rows:
        if vp not in cycles or out == "superseded":
            continue
        cycles[vp].append(out)
        streak[vp] = streak[vp] + 1 if out == "empty" else 0
        total += 1
    closed = all(n >= EMPTY_NEEDED for n in streak.values())
    return LensState(cycles, streak, closed, total)


def next_viewpoint(state: LensState, last: str | None) -> str:
    """Ad audit aperto il primo punto di vista con contatore < 2 dopo `last`, in ordine
    circolare (`last` compreso, per ultimo); ad audit chiuso il successivo di `last` (cicli di
    conferma, decisione 3). Senza `last` si parte da `executor`."""
    start = VIEWPOINTS.index(last) + 1 if last in VIEWPOINTS else 0
    order = [VIEWPOINTS[(start + i) % len(VIEWPOINTS)] for i in range(len(VIEWPOINTS))]
    if state.closed:
        return order[0]
    return next(v for v in order if state.streak[v] < EMPTY_NEEDED)


def render_lens_status(state: LensState, *, issue: int, cap: int, suspended: bool) -> str:
    """Testo di `spec-lens-stato.md` (6.2): la tabella dei punti di vista e lo stato."""
    status = "sospeso" if suspended else ("chiuso" if state.closed else "aperto")
    lines = [f"# Audit a lenti della spec, issue #{issue}", "",
             "| Punto di vista | Cicli | Vuoti di fila | Ultimo esito |",
             "|---|---|---|---|"]
    for v in VIEWPOINTS:
        done = state.cycles[v]
        lines.append(f"| {v} ({VIEWPOINT_LABELS[v]}) | {len(done)} | {state.streak[v]} | "
                     f"{done[-1] if done else '-'} |")
    lines += ["", f"stato: {status}", f"cicli fatti: {state.total} (tetto {cap})", ""]
    return "\n".join(lines)
