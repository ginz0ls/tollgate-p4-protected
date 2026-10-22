"""Cartella di stato, variabili di test e chiave del repo (spec 0 e 3.1)."""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

STATE_ENV = "TOLLGATE_STATE"
SENTINEL = ".tollgate-test"
TEST_ENVS = ("TOLLGATE_STATE", "TOLLGATE_GH", "TOLLGATE_TEST_CONFIG", "TOLLGATE_GH_RETRY_DELAYS")


def program_command(bin_path) -> str:
    """Il comando che il modello lancia per il programma: `python3` seguito dal percorso quotato.
    Un percorso con spazi come nome del comando è rifiutato da Claude Code in un worktree."""
    return f"python3 {shlex.quote(str(bin_path))}"


@dataclass(frozen=True)
class State:
    root: Path
    test_mode: bool

    @property
    def db_path(self) -> Path:
        return self.root / "tollgate.db"

    @property
    def backup_dir(self) -> Path:
        return self.root / "backup"

    @property
    def broken_dir(self) -> Path:
        return self.root / "broken"


def default_state_root() -> Path:
    return Path.home() / ".local" / "state" / "tollgate"


def resolve_state(env: Mapping[str, str] | None = None) -> State:
    """`TOLLGATE_STATE` vale solo con la sentinella: senza, un agente potrebbe dirottare il DB."""
    env = os.environ if env is None else env
    candidate = env.get(STATE_ENV)
    if candidate and (Path(candidate) / SENTINEL).is_file():
        return State(Path(candidate), True)
    return State(default_state_root(), False)


def test_env(state: State, name: str, env: Mapping[str, str] | None = None) -> str | None:
    if name not in TEST_ENVS:
        raise ValueError(f"variabile di test sconosciuta: {name}")
    env = os.environ if env is None else env
    return env.get(name) if state.test_mode else None


def ensure_dirs(state: State) -> None:
    for d in (state.root, state.backup_dir):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)


_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def repo_key(url: str) -> str:
    """URL di origin normalizzato: senza protocollo, utente, porta e `.git`, in minuscolo."""
    u = url.strip()
    scheme = _SCHEME.match(u)
    u = _SCHEME.sub("", u)
    if "@" in u.split("/")[0]:
        u = u.split("@", 1)[1]
    host, _, path = u.partition("/")
    if ":" in host:
        h, _, after = host.partition(":")
        if scheme and after.isdigit():
            host = h
        else:
            host, path = h, after + ("/" + path if path else "")
    key = f"{host}/{path}".rstrip("/").lower()
    return key[:-4] if key.endswith(".git") else key
