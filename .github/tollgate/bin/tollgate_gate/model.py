"""Ingressi e uscita del calcolo del gate (spec 9.2, decisione 3). Dati e nient'altro: li
riempiono `gate evaluate` su GitHub e `finish check` in locale, li legge `evaluate.evaluate`."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from tollgate_analysis.junit import Junit
from tollgate_core.config import Config

from . import attention

GITHUB = "github"
LOCAL = "local"
# Da dove vengono gli identificativi della base (`GateInputs.base_ids_source`).
BASE_FROM_CACHE = "cache"
BASE_FROM_RUN = "run"


@dataclass(frozen=True)
class CommandResult:
    """L'esito di un comando sulla testa (una voce di `results.json` o una ricevuta locale).
    `state` è green, red, empty, uncounted o unverified; `exit` e `junit` sono `None` se il
    comando non è girato."""
    name: str
    state: str
    exit: int | None
    tests_run: int | None
    junit: Junit | None


@dataclass(frozen=True)
class PrFacts:
    number: int
    head_sha: str
    head_ref: str
    base_ref: str
    default_branch: str
    body: str
    cross_repo: bool


@dataclass(frozen=True)
class IssueFacts:
    """`is_pr`: il numero è quello di una PR, non di un'issue (l'API delle issue risponde anche
    per le PR)."""
    number: int
    state: str
    labels: tuple[str, ...]
    is_pr: bool = False


@dataclass(frozen=True)
class GateInputs:
    """Tutto ciò che il calcolo legge, già raccolto da chi lo chiama.

    `cfg` è la configurazione del ramo predefinito (nel gate mai quella della PR). `base_sha`
    è la base del diff (nel gate il merge-base, in locale la base del lavoro). `block` è il
    blocco 18.1 dichiarato, `None` se manca o non è valido. `commands` e `base_ids` valgono
    `None` quando non sono disponibili: su GitHub è un errore, in locale la famiglia si salta.
    `base_ids` ha gli identificativi della base per nome di comando. `waiver_text` è il testo di
    `.tollgate/waivers/<N>.toml` in testa, se c'è. `sentinel_open` sono i numeri delle issue di
    sentinel aperte."""
    where: str
    repo: Path
    cfg: Config
    base_sha: str
    head_sha: str
    pr: PrFacts | None
    block: dict | None
    issue: IssueFacts | None
    commands: list[CommandResult] | None
    base_ids: dict[str, set[str]] | None
    base_ids_source: str | None
    waiver_text: str | None
    sentinel_open: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class Item:
    """Una voce del giudizio. `text` lo scrive tollgate; `data` è testo non fidato (nomi di
    file, identificativi di test, diff) e va solo nel commento, in un recinto."""
    key: str
    family: str
    text: str
    data: str = ""


@dataclass
class Evaluation:
    red: list[Item] = field(default_factory=list)
    attention: list[Item] = field(default_factory=list)
    watch: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def verdict_state(self) -> str:
        """Lo stato di `tollgate/verdict`."""
        if self.errors:
            return "error"
        return "failure" if self.red else "success"

    @property
    def attention_state(self) -> str:
        """Lo stato di `tollgate/attention` (decisione 7): rosso solo con una voce «da leggere»."""
        read = any(attention.group(i.key) == attention.READ for i in self.attention)
        return "failure" if read else "success"
