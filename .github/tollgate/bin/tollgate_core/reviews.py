"""Cicli di revisione finale e rilievi (spec 10, 8.6, 18.5; decisioni 5, 6, 8, 15 di P3b).

Un ciclo ha tre stadi: `review` (i revisori attesi riportano), `verify` (il verificatore dà un
esito ai rilievi) e `closed`. Il codice scrive solo qui in `review_cycles` e `findings`; ogni
funzione apre la sua transazione. `close_cycle` cambia la fase e apre i blocchi, perciò va
chiamata fuori da una transazione.
"""
from __future__ import annotations

import json
import sqlite3

from tollgate_analysis.verdicts import is_blocking

from . import clock, db
from .events import record_event
from .paths import State
from .phases import get_work, open_block, set_phase

SEVERITY_ORDER = ("blocker", "major", "moderate", "minor")
BLOCKING_SEVERITIES = SEVERITY_ORDER[:2]
CAP_COUNTED = 4          # cicli contati prima del tetto (+ extra_review_cycles)
MAX_CYCLES = 8           # oltre serve `approve unverified-review`
CAP_REASON = "cicli di revisione esauriti"
VERIFIER = "tollgate:finding-verifier"      # il suo contatore di riporti sta in `reported`
REPORT_OUTCOMES = ("ok", "needs_fix", "needs_you")
VERIFICATIONS = ("confirmed", "rejected", "unverified")
MAX_TEXT = 2000
NO_PROOF = "senza prova (8.6)"
BEYOND_MAX = "oltre max_findings"
SUPERSEDED_REASON = "ciclo superato"
UNVERIFIED_REVIEW_REASON = "revisione non verificata"


def latest(conn, work: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM review_cycles WHERE work = ? ORDER BY number DESC "
                        "LIMIT 1", (work,)).fetchone()


def count(conn, work: int) -> int:
    """Tutti i cicli aperti per il lavoro, contati o no."""
    return conn.execute("SELECT count(*) FROM review_cycles WHERE work = ?",
                        (work,)).fetchone()[0]


def counted(conn, work: int) -> int:
    """I cicli che pesano sul tetto: quelli chiusi con almeno un rilievo confermato."""
    return conn.execute("SELECT coalesce(sum(counted), 0) FROM review_cycles WHERE work = ?",
                        (work,)).fetchone()[0]


def _cycle(conn, work: int, cycle: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM review_cycles WHERE work = ? AND number = ?",
                       (work, cycle)).fetchone()
    if row is None:
        raise ValueError(f"ciclo {cycle} del lavoro {work} inesistente")
    return row


def _finding(conn, work: int, finding_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM findings WHERE work = ? AND id = ?",
                        (work, finding_id)).fetchone()


def _log_finding(conn, row, *, now, session=None) -> None:
    record_event(conn, "finding",
                 {"id": row["id"], "cycle": row["cycle"], "severity": row["severity"],
                  "confidence": row["confidence"], "verification": row["verification"],
                  "user_decision": row["user_decision"]},
                 now=now, session=session, work=row["work"])


def open_cycle(conn, work: int, *, sha: str, patch_id: str | None, code: str,
               reviewers: list[str], now) -> int:
    """Apre il ciclo `n+1` in stadio `review`. `counted` resta 0 fino alla chiusura."""
    with db.tx(conn):
        get_work(conn, work)
        number = conn.execute("SELECT coalesce(max(number), 0) + 1 FROM review_cycles "
                              "WHERE work = ?", (work,)).fetchone()[0]
        conn.execute(
            "INSERT INTO review_cycles (work, number, sha, patch_id, counted, code, stage, "
            "reviewers, reported, opened) VALUES (?, ?, ?, ?, 0, ?, 'review', ?, '{}', ?)",
            (work, number, sha, patch_id, code, json.dumps(list(reviewers)), clock.fmt(now)))
        return number


def mark_unverified(conn, work: int, cycle: int, reason: str, *, now) -> int:
    """Porta a `unverified` i rilievi del ciclo ancora senza esito (nessun rilievo registrato
    resta con `verification` nullo una volta chiuso o superato il ciclo). Dà quanti sono."""
    with db.tx(conn):
        ids = unjudged_ids(conn, work, cycle)
        for fid in ids:
            conn.execute("UPDATE findings SET verification = 'unverified', "
                         "verification_reason = ? WHERE work = ? AND id = ?", (reason, work, fid))
            _log_finding(conn, _finding(conn, work, fid), now=now)
        return len(ids)


def supersede(conn, work: int, cycle: int, *, now) -> None:
    """Chiude un ciclo ancora aperto perché il lavoro è andato avanti (P3b, Task 7): non pesa
    sul tetto. I suoi rilievi senza esito diventano `unverified`."""
    with db.tx(conn):
        row = _cycle(conn, work, cycle)
        if row["stage"] == "closed":
            raise ValueError(f"ciclo {cycle} già chiuso")
        mark_unverified(conn, work, cycle, SUPERSEDED_REASON, now=now)
        conn.execute("UPDATE review_cycles SET outcome = 'superseded', stage = 'closed', "
                     "counted = 0 WHERE work = ? AND number = ?", (work, cycle))
        record_event(conn, "review_cycle", {"number": cycle, "outcome": "superseded",
                                            "findings_confirmed": 0}, now=now, work=work)


def _text(v, limit: int | None = None):
    if not isinstance(v, str):
        return None
    return v[:limit] if limit else v


def _normalize(f: dict) -> dict:
    """Campi fuori forma diventano NULL: nel DB non entra mai un valore che viola un vincolo."""
    line = f.get("line")
    confidence = f.get("confidence")
    return {
        "severity": f.get("severity") if f.get("severity") in SEVERITY_ORDER else None,
        "confidence": float(confidence) if isinstance(confidence, (int, float))
        and not isinstance(confidence, bool) else None,
        "file": _text(f.get("file")),
        "line": line if isinstance(line, int) and not isinstance(line, bool) else None,
        "rule": _text(f.get("rule")),
        "text": _text(f.get("text"), MAX_TEXT),
    }


def add_report(conn, work: int, cycle: int, *, source: str, outcome: str, findings: list[dict],
               rejected: list[dict], blocking_rules: set[str], known_rules: set[str],
               now) -> str:
    """Registra il riporto di un revisore. I `findings` entrano senza esito (li giudica il
    verificatore), i `rejected` (senza prova) già scartati. Restituisce lo stadio dopo il
    riporto: `verify` quando tutti i revisori attesi hanno riportato."""
    if outcome not in REPORT_OUTCOMES:
        raise ValueError(f"esito del revisore sconosciuto: {outcome}")
    with db.tx(conn):
        row = _cycle(conn, work, cycle)
        if row["stage"] != "review":
            raise ValueError(f"ciclo {cycle} non è in stadio review ({row['stage']})")
        reviewers = json.loads(row["reviewers"])
        reported = json.loads(row["reported"])
        if source not in reviewers:
            raise ValueError(f"{source} non è tra i revisori attesi del ciclo {cycle}")
        if source in reported:
            raise ValueError(f"{source} ha già riportato nel ciclo {cycle}")
        n = conn.execute("SELECT count(*) FROM findings WHERE work = ? AND cycle = ?",
                         (work, cycle)).fetchone()[0]
        for batch, verification, reason in ((findings, None, None),
                                            (rejected, "rejected", NO_PROOF)):
            for raw in batch:
                n += 1
                f = _normalize(raw if isinstance(raw, dict) else {})
                fid = f"f-{cycle}-{n}"
                conn.execute(
                    "INSERT INTO findings (id, work, cycle, source, severity, confidence, file, "
                    "line, text, verification, verification_reason, rule, blocking) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (fid, work, cycle, source, f["severity"], f["confidence"], f["file"],
                     f["line"], f["text"], verification, reason, f["rule"],
                     int(is_blocking(f, blocking_rules, known_rules))))
                _log_finding(conn, _finding(conn, work, fid), now=now)
        reported[source] = outcome
        stage = "verify" if all(r in reported for r in reviewers) else "review"
        conn.execute("UPDATE review_cycles SET reported = ?, stage = ? "
                     "WHERE work = ? AND number = ?", (json.dumps(reported), stage, work, cycle))
        return stage


def _severity_key(row) -> int:
    sev = row["severity"]
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def to_verify(conn, work: int, cycle: int, *, max_findings: int, now) -> list[sqlite3.Row]:
    """I rilievi senza esito, in ordine di gravità (a parità, di arrivo), fino a
    `max_findings`: gli altri diventano `unverified`."""
    with db.tx(conn):
        _cycle(conn, work, cycle)
        rows = conn.execute("SELECT * FROM findings WHERE work = ? AND cycle = ? "
                            "AND verification IS NULL ORDER BY rowid", (work, cycle)).fetchall()
        rows.sort(key=_severity_key)       # stabile: l'ordine di arrivo resta a parità
        keep, rest = rows[:max(0, max_findings)], rows[max(0, max_findings):]
        for r in rest:
            conn.execute("UPDATE findings SET verification = 'unverified', "
                         "verification_reason = ? WHERE work = ? AND id = ?",
                         (BEYOND_MAX, work, r["id"]))
            _log_finding(conn, _finding(conn, work, r["id"]), now=now)
        return [_finding(conn, work, r["id"]) for r in keep]


def apply_verification(conn, work: int, cycle: int, results: list[dict], *, now) -> int:
    """Applica i risultati del verificatore ai rilievi del ciclo ancora senza esito. Un id
    sconosciuto, già giudicato o con un valore fuori elenco è ignorato. Dà quanti restano
    senza esito."""
    with db.tx(conn):
        _cycle(conn, work, cycle)
        for res in results:
            if not isinstance(res, dict) or res.get("verification") not in VERIFICATIONS:
                continue
            row = _finding(conn, work, res.get("id")) if isinstance(res.get("id"), str) else None
            if row is None or row["cycle"] != cycle or row["verification"] is not None:
                continue
            conn.execute("UPDATE findings SET verification = ?, verification_reason = ? "
                         "WHERE work = ? AND id = ?",
                         (res["verification"], _text(res.get("reason"), MAX_TEXT), work,
                          row["id"]))
            _log_finding(conn, _finding(conn, work, row["id"]), now=now)
        return conn.execute("SELECT count(*) FROM findings WHERE work = ? AND cycle = ? "
                            "AND verification IS NULL", (work, cycle)).fetchone()[0]


def unjudged_ids(conn, work: int, cycle: int) -> list[str]:
    """Gli id dei rilievi del ciclo ancora senza esito, in ordine di arrivo."""
    return [r[0] for r in conn.execute(
        "SELECT id FROM findings WHERE work = ? AND cycle = ? AND verification IS NULL "
        "ORDER BY rowid", (work, cycle))]


def verifier_incomplete(conn, state: State, work: int, cycle: int, *, now,
                        session=None) -> int:
    """Conta un riporto del verificatore che lascia rilievi senza esito (mai `unverified`
    automatico); dal secondo apre `needs_you`. Va chiamata fuori da una transazione. Dà il
    numero di riporti incompleti del ciclo."""
    if conn.in_transaction:
        raise RuntimeError("verifier_incomplete va chiamato fuori da una transazione")
    with db.tx(conn):
        row = _cycle(conn, work, cycle)
        reported = json.loads(row["reported"])
        n = reported.get(VERIFIER, 0)
        n = (n if isinstance(n, int) else 0) + 1
        reported[VERIFIER] = n
        conn.execute("UPDATE review_cycles SET reported = ? WHERE work = ? AND number = ?",
                     (json.dumps(reported), work, cycle))
        ids = unjudged_ids(conn, work, cycle)
    reason = f"verificatore senza esito su: {', '.join(ids)}"[:500]
    if n >= 2 and ids and not _has_open_block(conn, work, reason):
        open_block(conn, state, work, "needs_you", reason, now=now, session=session)
    return n


def effective_severity(row) -> str | None:
    """La gravità dopo `downgraded:<g>` (anche verso l'alto: vale la scelta dell'utente)."""
    decision = row["user_decision"]
    if decision and decision.startswith("downgraded:"):
        return decision.split(":", 1)[1]
    return row["severity"]


def blocking_open(conn, work: int, cycle: int | None = None) -> list[sqlite3.Row]:
    """Rilievi confermati, bloccanti, di gravità effettiva blocker o major, non archiviati."""
    rows = conn.execute(
        "SELECT * FROM findings WHERE work = ? AND verification = 'confirmed' AND blocking = 1 "
        "AND (user_decision IS NULL OR user_decision <> 'dismissed') "
        "AND (? IS NULL OR cycle = ?) ORDER BY rowid", (work, cycle, cycle)).fetchall()
    return [r for r in rows if effective_severity(r) in BLOCKING_SEVERITIES]


def set_decision(conn, work: int, finding_id: str, decision: str, *, now, session=None) -> None:
    """`approve finding`: `downgraded:<gravità>` o `dismissed`, solo su un rilievo confermato."""
    if decision != "dismissed" and not (decision.startswith("downgraded:")
                                        and decision.split(":", 1)[1] in SEVERITY_ORDER):
        raise ValueError(f"decisione non valida: {decision}")
    with db.tx(conn):
        row = _finding(conn, work, finding_id)
        if row is None:
            raise ValueError(f"rilievo {finding_id} inesistente")
        if row["verification"] != "confirmed":
            raise ValueError(f"il rilievo {finding_id} non è confermato: "
                             f"{row['verification'] or 'senza esito'}")
        conn.execute("UPDATE findings SET user_decision = ? WHERE work = ? AND id = ?",
                     (decision, work, finding_id))
        _log_finding(conn, _finding(conn, work, finding_id), now=now, session=session)


def recompute_outcome(conn, work: int, cycle: int, *, now) -> str:
    """Ricalcola l'esito di un ciclo già chiuso dopo `approve finding` (Task 10, M2): `ok` se non
    resta un rilievo bloccante aperto, altrimenti `needs_fix`; aggiorna `outcome` e
    `findings_confirmed`. Non cambia fase né blocchi (a quelli pensa `actapply`) e non
    richiama `close_cycle`. Un ciclo `needs_you`, `superseded` o ancora aperto non si
    ricalcola: `needs_you` resta com'è, gli altri sono `ValueError`."""
    with db.tx(conn):
        row = _cycle(conn, work, cycle)
        if row["stage"] != "closed":
            raise ValueError(f"ciclo {cycle} non ancora chiuso")
        if row["outcome"] == "needs_you":
            return "needs_you"
        if row["outcome"] not in ("ok", "needs_fix"):
            raise ValueError(f"ciclo {cycle}: esito {row['outcome']} non ricalcolabile")
        outcome = "needs_fix" if blocking_open(conn, work, cycle) else "ok"
        confirmed = conn.execute("SELECT count(*) FROM findings WHERE work = ? AND cycle = ? "
                                 "AND verification = 'confirmed' AND (user_decision IS NULL "
                                 "OR user_decision <> 'dismissed')", (work, cycle)).fetchone()[0]
        if (outcome, confirmed) != (row["outcome"], row["findings_confirmed"]):
            conn.execute("UPDATE review_cycles SET outcome = ?, findings_confirmed = ? "
                         "WHERE work = ? AND number = ?", (outcome, confirmed, work, cycle))
            record_event(conn, "review_cycle", {"number": cycle, "outcome": outcome,
                                                "findings_confirmed": confirmed},
                         now=now, work=work)
        return outcome


def _has_open_block(conn, work: int, reason: str) -> bool:
    return conn.execute("SELECT 1 FROM blocks WHERE work = ? AND closed IS NULL AND reason = ?",
                        (work, reason)).fetchone() is not None


def close_cycle(conn, state: State, work: int, cycle: int, *, now, session=None) -> str:
    """Chiude il ciclo (decisione 6) e ne applica le conseguenze. Esiti: `needs_you` se un
    revisore l'ha dichiarato; `needs_fix` con un rilievo bloccante confermato (fase
    `review` -> `execution`, e al tetto un blocco `needs_you`); altrimenti `ok`.
    Ripetibile: su un ciclo già chiuso riprende i passi rimasti a metà."""
    if conn.in_transaction:
        raise RuntimeError("close_cycle va chiamato fuori da una transazione")
    with db.tx(conn):
        row = _cycle(conn, work, cycle)
        if row["stage"] == "closed":
            outcome = row["outcome"]
            if outcome not in ("ok", "needs_fix", "needs_you"):
                raise ValueError(f"ciclo {cycle} già chiuso ({outcome})")
        else:
            confirmed = conn.execute("SELECT count(*) FROM findings WHERE work = ? AND cycle = ? "
                                     "AND verification = 'confirmed'", (work, cycle)).fetchone()[0]
            if "needs_you" in json.loads(row["reported"]).values():
                outcome = "needs_you"
            elif blocking_open(conn, work, cycle):
                outcome = "needs_fix"
            else:
                outcome = "ok"
            conn.execute("UPDATE review_cycles SET outcome = ?, stage = 'closed', "
                         "findings_confirmed = ?, counted = ? WHERE work = ? AND number = ?",
                         (outcome, confirmed, 1 if confirmed else 0, work, cycle))
            record_event(conn, "review_cycle", {"number": cycle, "outcome": outcome,
                                                "findings_confirmed": confirmed},
                         now=now, session=session, work=work)
    if outcome == "needs_you":
        reason = f"il revisore finale chiede una decisione (ciclo {cycle})"
        if not _has_open_block(conn, work, reason):
            open_block(conn, state, work, "needs_you", reason, now=now, session=session)
    elif outcome == "needs_fix":
        if get_work(conn, work)["phase"] == "review":
            set_phase(conn, state, work, "execution", "needs_fix", now=now, session=session)
        cap = CAP_COUNTED + get_work(conn, work)["extra_review_cycles"]
        if counted(conn, work) >= cap and not _has_open_block(conn, work, CAP_REASON):
            open_block(conn, state, work, "needs_you", CAP_REASON, now=now, session=session)
    return outcome
