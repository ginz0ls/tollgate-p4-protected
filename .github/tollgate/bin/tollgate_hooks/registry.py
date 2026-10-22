"""Caricamento dei moduli del registro (spec 3.2): ordine, api, componenti."""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass

from .model import INPUT_EVENTS

API = 1


@dataclass(frozen=True)
class Loaded:
    name: str
    module: object
    check: dict


@dataclass(frozen=True)
class Broken:
    name: str
    events: tuple | None      # None: eventi ignoti, vale per ogni evento di controllo
    reason: str


def _validate(check) -> str | None:
    if not isinstance(check, dict):
        return "CHECK mancante o non è un dizionario"
    if check.get("api") != API:
        return f"api {check.get('api')!r}, questa versione di tollgate carica api {API}"
    events = check.get("events")
    if not isinstance(events, list) or not events or not all(isinstance(e, str) for e in events) \
            or not set(events) <= set(INPUT_EVENTS):
        return f"eventi non validi: {events!r}"
    if not isinstance(check.get("order"), int):
        return "order mancante"
    comp = check.get("component")
    if comp is not None and not isinstance(comp, str):
        return "component non valido"
    return None


def load(package: str = "tollgate_checks"):
    pkg = importlib.import_module(package)
    loaded, broken = [], []
    for info in pkgutil.iter_modules(pkg.__path__):
        if info.name.startswith("_"):
            continue
        name = f"{package}.{info.name}"
        try:
            mod = importlib.import_module(name)
        except Exception as e:  # un controllo che manca non deve passare in silenzio
            broken.append(Broken(info.name, None, f"import fallito: {e}"))
            continue
        check = getattr(mod, "CHECK", None)
        reason = _validate(check)
        if reason is None and not callable(getattr(mod, "decide", None)):
            reason = "decide mancante"
        if reason is not None:
            events = tuple(check["events"]) if isinstance(check, dict) and isinstance(
                check.get("events"), list) else None
            broken.append(Broken(info.name, events, reason))
            continue
        loaded.append(Loaded(info.name, mod, check))
    loaded.sort(key=lambda m: (m.check["order"], m.name))
    return loaded, broken
