"""Giri di audit di spec e piano (spec 6.2, 12.2): righe di `spec_audit`, sospensioni dei tetti
e motivi dei blocchi. Solo accesso ai dati: le regole (esiti, tetti, punti di vista) stanno in
`tollgate_analysis.audit` e nel flusso che le usa."""
from __future__ import annotations

import json
import sqlite3

from . import clock, db, phases
from .events import record_event

KINDS = ("spec-adversarial", "spec-lens", "plan-adversarial")
AGENTS = {"spec-adversarial": "tollgate:spec-adversary", "spec-lens": "tollgate:spec-auditor",
          "plan-adversarial": "tollgate:plan-adversary"}
COMPONENTS = {"spec-adversarial": "spec_adversary", "spec-lens": "spec_audit",
              "plan-adversarial": "plan_adversary"}
# Prefissi dei motivi dei blocchi dei tetti (decisione 7): `cap_reason` li completa, `cap_kind`
# li riconosce.
CAP_REASONS = {"spec-adversarial": "giri avversariali della spec esauriti",
               "spec-lens": "audit a lenti: tetto di cicli raggiunto",
               "plan-adversarial": "giri avversariali del piano esauriti"}
DECLINE_REASON = "audit a lenti rifiutato dall'utente"
SUSPENDED_LABELS = {"spec-adversarial": "avversariale sospeso",
                    "spec-lens": "audit a lenti sospeso",
                    "plan-adversarial": "avversario del piano sospeso"}


def _check_kind(kind: str) -> None:
    if kind not in KINDS:
        raise ValueError(f"tipo di giro sconosciuto: {kind}")


def open_round(conn, work: int, *, kind: str, sha: str, spec_sha: str, viewpoint: str | None,
               code: str, now, min_number: int = 1) -> int:
    """Apre un giro e ne dà il numero: per tipo, da 1, senza riusare quello di un giro superato;
    `min_number` lo alza (i report già nel ramo dopo un DB perso: il numero è il più alto tra
    quello del DB e `min_number`). Un solo giro aperto per lavoro."""
    _check_kind(kind)
    with db.tx(conn):
        phases.get_work(conn, work)
        if open_round_row(conn, work) is not None:
            raise ValueError("c'è già un giro di audit aperto")
        number = max(conn.execute("SELECT coalesce(max(number), 0) + 1 FROM spec_audit "
                                  "WHERE work = ? AND kind = ?", (work, kind)).fetchone()[0],
                     min_number)
        conn.execute("INSERT INTO spec_audit (work, kind, number, viewpoint, sha, spec_sha, "
                     "code, stage, opened) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)",
                     (work, kind, number, viewpoint, sha, spec_sha, code, clock.fmt(now)))
        return number


def open_round_row(conn, work: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM spec_audit WHERE work = ? AND stage = 'open' "
                        "ORDER BY id LIMIT 1", (work,)).fetchone()


def supersede(conn, work: int, number_kind: tuple[str, int], *, now) -> None:
    """Chiude `superseded` il giro aperto `(tipo, numero)`: il documento è cambiato, il giro non
    conta nei tetti né nella matrice. Un giro già chiuso resta com'è."""
    kind, number = number_kind
    with db.tx(conn):
        conn.execute("UPDATE spec_audit SET outcome = 'superseded', stage = 'closed' "
                     "WHERE work = ? AND kind = ? AND number = ? AND stage = 'open'",
                     (work, kind, number))


def close_round(conn, work: int, *, kind: str, number: int, counts: dict, outcome: str,
                report_path: str, now) -> None:
    with db.tx(conn):
        row = conn.execute("SELECT * FROM spec_audit WHERE work = ? AND kind = ? AND number = ? "
                           "AND stage = 'open'", (work, kind, number)).fetchone()
        if row is None:
            raise ValueError(f"nessun giro aperto {kind} {number}")
        conn.execute("UPDATE spec_audit SET counts = ?, outcome = ?, report_path = ?, "
                     "stage = 'closed' WHERE id = ?",
                     (json.dumps(counts, sort_keys=True), outcome, report_path, row["id"]))
        record_event(conn, "spec_audit_round",
                     {"kind": kind, "number": number, "viewpoint": row["viewpoint"],
                      "outcome": outcome}, now=now, work=work)


def rounds(conn, work: int, kind: str) -> list[sqlite3.Row]:
    """I giri chiusi del tipo, mai i `superseded`, in ordine: sono quelli che contano."""
    return conn.execute("SELECT * FROM spec_audit WHERE work = ? AND kind = ? AND "
                        "stage = 'closed' AND coalesce(outcome, '') <> 'superseded' "
                        "ORDER BY id", (work, kind)).fetchall()


def any_rows(conn, work: int, kind: str) -> bool:
    """Esiste una riga del tipo, anche superata o aperta (conferma del costo, decisione 6)."""
    return conn.execute("SELECT 1 FROM spec_audit WHERE work = ? AND kind = ? LIMIT 1",
                        (work, kind)).fetchone() is not None


def last_closed(conn, work: int, kinds: tuple[str, ...]) -> sqlite3.Row | None:
    """L'ultimo giro chiuso tra i tipi dati; mai una riga `superseded`."""
    if not kinds:
        return None
    marks = ",".join("?" * len(kinds))
    return conn.execute(
        f"SELECT * FROM spec_audit WHERE work = ? AND kind IN ({marks}) AND stage = 'closed' "
        "AND coalesce(outcome, '') <> 'superseded' ORDER BY id DESC LIMIT 1",
        (work, *kinds)).fetchone()


def suspend(conn, work: int, kind: str, number: int, *, now) -> None:
    """Scioglie il tetto del tipo, annotando il numero del giro (0 per il rifiuto del costo)."""
    _check_kind(kind)
    with db.tx(conn):
        data = suspended(conn, work)
        data[kind] = number
        conn.execute("UPDATE work_items SET audit_suspended = ?, updated = ? WHERE id = ?",
                     (json.dumps(data, sort_keys=True), clock.fmt(now), work))


def suspended(conn, work: int) -> dict[str, int]:
    """`{tipo: numero del giro}` dei tetti sciolti. Il numero può essere 0 (rifiuto del costo):
    si legge con `kind in suspended(...)`, mai con la veridicità del valore."""
    return dict(json.loads(phases.get_work(conn, work)["audit_suspended"]))


def cap_reason(kind: str, number: int) -> str:
    """Motivo del blocco di un tetto: il prefisso del tipo, più « (giro <n>)» per i giri
    avversariali (l'audit a lenti ha un testo fisso)."""
    _check_kind(kind)
    prefix = CAP_REASONS[kind]
    return prefix if kind == "spec-lens" else f"{prefix} (giro {number})"


def cap_kind(reason: str) -> str | None:
    """Il tipo di giro del motivo di un blocco (inverso di `cap_reason`), `None` se non è un
    blocco dell'audit. Anche il rifiuto del costo vale `spec-lens`."""
    if reason == DECLINE_REASON:
        return "spec-lens"
    for kind, prefix in CAP_REASONS.items():
        if reason.startswith(prefix):
            return kind
    return None
