"""Must-have contro i test eseguiti (spec 7.5, 8.7): il piano dice quali test li dimostrano, il
report JUnit dice quali sono girati e quali sono falliti."""
from __future__ import annotations

from dataclasses import dataclass, field

from .plan import MustHave

MANUAL = "manuale"


@dataclass
class MustHaveResult:
    """`missing` e `failed`: voci `Mn: <identificativo>`. `manual`: gli id dei must-have con
    `— test: manuale`, che non rendono falso il risultato."""
    ok: bool
    missing: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)


def check(must_haves: list[MustHave], ids_run: set[str], ids_failed: set[str]) -> MustHaveResult:
    """Un identificativo assente da `ids_run` e `ids_failed`, o presente in `ids_failed`, rende
    falso il risultato. `ids_run` conta anche i test falliti, se il chiamante li include."""
    seen = set(ids_run) | set(ids_failed)
    missing: list[str] = []
    failed: list[str] = []
    manual: list[str] = []
    for mh in must_haves:
        for test in mh.tests:
            if test == MANUAL:
                if mh.id not in manual:
                    manual.append(mh.id)
            elif test in ids_failed:
                failed.append(f"{mh.id}: {test}")
            elif test not in seen:
                missing.append(f"{mh.id}: {test}")
    return MustHaveResult(not missing and not failed, missing, failed, manual)
