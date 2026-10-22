"""Verdetti dei revisori (spec 18.5, 8.6, decisioni 8 e 10): revisore del task, revisione
finale, verificatore.

Un verdetto del task che non rispetta il formato, o che non porta lo SHA e il codice del brief di
`review-prepare`, non è valido e non diventa mai `approved`."""
from __future__ import annotations

from dataclasses import dataclass, field

from .report import json_candidates

OUTCOMES = ("approved", "changes")
SEVERITIES = ("blocker", "major", "moderate", "minor")
BLOCKING = ("blocker", "major")
SPEC_FLAGS = ("missing", "extra")


@dataclass
class TaskVerdict:
    """`outcome` è l'esito effettivo (None se il verdetto non è valido); `declared` quello
    scritto dal revisore; `findings` sono i soli rilievi validi; `dropped` quelli scartati."""
    valid: bool
    problems: list[str] = field(default_factory=list)
    outcome: str | None = None
    declared: str | None = None
    findings: list[dict] = field(default_factory=list)
    dropped: int = 0


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _finding_ok(f) -> bool:
    """Prova obbligatoria: regola, file e riga (8.6); la gravità è una delle quattro."""
    return (isinstance(f, dict) and f.get("severity") in SEVERITIES
            and all(isinstance(f.get(k), str) and f[k].strip() for k in ("rule", "file"))
            and _is_int(f.get("line")))


def _may_block(f) -> bool:
    """Un rilievo scartato che poteva essere bloccante: gravità non dichiarata `moderate` o
    `minor` (anche illeggibile) conta come bloccante, in modo fail-closed."""
    return not (isinstance(f, dict) and f.get("severity") in ("moderate", "minor"))


def parse_task_verdict(text: str | None, *, task: int, sha: str, code: str, standard: bool,
                       blocking_rules: set[str] = frozenset(),
                       known_rules: set[str] = frozenset()) -> TaskVerdict:
    cands = json_candidates(text or "", "outcome")
    if not cands:
        return TaskVerdict(False, ["manca il blocco JSON del verdetto (18.5), o è malformato"])
    data = cands[0]      # l'ultimo del testo: un esempio citato prima non conta
    declared = data.get("outcome") if isinstance(data.get("outcome"), str) else None
    problems = []
    if declared not in OUTCOMES:
        problems.append(f"outcome sconosciuto: usa «approved» o «changes» (trovato {declared!r})")
    if not _is_int(data.get("task")) or data["task"] != task:
        problems.append(f"task diverso da {task}")
    if data.get("sha") != sha:
        problems.append("sha diverso da quello del brief di revisione")
    if data.get("code") != code:
        problems.append("code diverso da quello del brief di revisione")
    spec = data.get("spec_compliance")
    if not isinstance(spec, list) or any(x not in SPEC_FLAGS for x in spec):
        problems.append("spec_compliance deve essere una lista di «missing» o «extra» "
                        "(vuota se il codice aderisce)")
        spec = []
    raw = data.get("findings", [])
    if not isinstance(raw, list):
        problems.append("findings deve essere una lista")
        raw = []
    if problems:
        return TaskVerdict(False, problems, None, declared)
    findings = [f for f in raw if _finding_ok(f)]
    outcome = declared
    if standard:
        blocking = bool(spec) or any(
            f["severity"] in BLOCKING and is_blocking(f, blocking_rules, known_rules)
            for f in findings)
        lost = [f for f in raw if not _finding_ok(f) and _may_block(f)]
        if not blocking and lost:
            # Un rilievo bloccante senza prova non fa mai un `approved`, né da un `changes` né
            # da un `approved` dichiarato (riga 108).
            return TaskVerdict(False, ["rilievo bloccante senza file, riga o regola: "
                                       "riscrivilo"], None, declared)
        outcome = "changes" if blocking else "approved"
    return TaskVerdict(True, [], outcome, declared, findings, len(raw) - len(findings))


def is_blocking(finding: dict, blocking_rules: set[str], known_rules: set[str]) -> bool:
    """Un rilievo blocca se cita un passo del piano (regola che non comincia con `R-`), una
    regola `[blocca]` del profilo, o una regola `R-…` che nessun profilo attivo dichiara
    (fail-closed). Non blocca solo con una regola nota e non `[blocca]` (decisione 8)."""
    rule = finding.get("rule")
    if not isinstance(rule, str) or not rule.strip():
        return True
    rule = rule.strip()
    if not rule.startswith("R-") or rule in blocking_rules:
        return True
    return rule not in known_rules


FINAL_OUTCOMES = ("ok", "needs_fix", "needs_you")
VERIFICATIONS = ("confirmed", "rejected", "unverified")


@dataclass
class FinalVerdict:
    """Revisione finale (18.5): `findings` hanno la prova di 8.6; gli altri, con la gravità
    com'è, stanno in `rejected` (non si scartano in silenzio)."""
    valid: bool
    problems: list[str] = field(default_factory=list)
    outcome: str | None = None
    findings: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)


@dataclass
class VerifierResults:
    valid: bool
    problems: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)


def _sha_code_problems(data: dict, sha: str, code: str) -> list[str]:
    out = []
    if data.get("sha") != sha:
        out.append("sha diverso da quello del brief di revisione")
    if data.get("code") != code:
        out.append("code diverso da quello del brief di revisione")
    return out


def parse_final_verdict(text: str | None, *, sha: str, code: str) -> FinalVerdict:
    cands = json_candidates(text or "", "outcome")
    if not cands:
        return FinalVerdict(False, ["manca il blocco JSON del verdetto (18.5), o è malformato"])
    data = cands[0]
    outcome = data.get("outcome") if isinstance(data.get("outcome"), str) else None
    problems = _sha_code_problems(data, sha, code)
    if outcome not in FINAL_OUTCOMES:
        problems.append("outcome sconosciuto: usa «ok», «needs_fix» o «needs_you» "
                        f"(trovato {data.get('outcome')!r})")
    raw = data.get("findings", [])
    if not isinstance(raw, list):
        problems.append("findings deve essere una lista")
    if problems:
        return FinalVerdict(False, problems)
    findings = [f for f in raw if _finding_ok(f)]
    rejected = [f if isinstance(f, dict) else {"text": str(f)} for f in raw if not _finding_ok(f)]
    return FinalVerdict(True, [], outcome, findings, rejected)


def parse_verifier_results(text: str | None, *, sha: str, code: str,
                           ids: set[str]) -> VerifierResults:
    cands = json_candidates(text or "", "results")
    if not cands:
        return VerifierResults(False, ["manca il blocco JSON dei risultati (18.5), o è "
                                       "malformato"])
    data = cands[0]
    problems = _sha_code_problems(data, sha, code)
    raw = data.get("results")
    if not isinstance(raw, list):
        problems.append("results deve essere una lista")
        raw = []
    results, unknown = {}, 0
    for r in raw:
        if not isinstance(r, dict) or not isinstance(r.get("id"), str):
            if "ogni risultato ha un id" not in problems:
                problems.append("ogni risultato ha un id")
        elif r["id"] not in ids:
            unknown += 1
        elif r.get("verification") not in VERIFICATIONS:
            problems.append(f"verification sconosciuta per {r['id']}: usa «confirmed», "
                            f"«rejected» o «unverified» (trovato {r.get('verification')!r})")
        else:
            results[r["id"]] = r
    if not results and not problems:
        problems.append(f"nessun risultato per i rilievi richiesti ({unknown} id sconosciuti "
                        "ignorati)" if unknown else "nessun risultato per i rilievi richiesti")
    if problems:
        return VerifierResults(False, problems)
    return VerifierResults(True, [], list(results.values()))
