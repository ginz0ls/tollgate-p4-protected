"""I file del gate da installare nel repo del progetto (spec 9.1, decisione 17): i cinque
workflow, la copia del CLI in `.github/tollgate/bin/`, `VERSION` e `FINGERPRINT`."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from tollgate_core import VERSION

WORKFLOWS_DIR = "gate/workflows"
WORKFLOW_NAMES = ("guard", "run", "verdict", "base", "sentinel")
INSTALL_DIR = ".github/tollgate"
BRANCH_PLACEHOLDER = "__DEFAULT_BRANCH__"
SERVICES_MARKER = "# __SERVICES__"

# i valori finiscono nello YAML tra virgolette singole (così `true` o `123` restano stringhe): le
# regex escludono `'` e ogni carattere di controllo
_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]*")
_SERVICE_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*")
# workflow con un segnaposto dei servizi per ogni job che esegue la suite del progetto (I-1)
SERVICES_WORKFLOWS = {"run": 2, "base": 1}


def _sources(bin_root: Path) -> list[Path]:
    """I file di `bin_root` senza cache di Python, in ordine stabile."""
    return sorted(p for p in Path(bin_root).rglob("*")
                  if p.is_file() and "__pycache__" not in p.relative_to(bin_root).parts
                  and p.suffix != ".pyc")


def fingerprint(bin_root: Path) -> str:
    """`sha256` del contenuto di `bin_root` (percorsi relativi e byte), senza `__pycache__`."""
    digest = hashlib.sha256()
    for path in _sources(bin_root):
        rel = path.relative_to(bin_root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(rel).to_bytes(8, "big") + rel + len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def validate_services(services: dict[str, str], ports: dict[str, int] | None = None) -> None:
    """La sola regola dei servizi (nome, immagine, porta): `ValueError` col motivo. La usa anche
    `init` per rifiutare prima di scrivere qualunque cosa."""
    ports = ports or {}
    unknown = sorted(set(ports) - set(services))
    if unknown:
        raise ValueError(f"porta per un servizio non dichiarato: {unknown[0]!r}")
    for name, image in services.items():
        if not _SERVICE_NAME.fullmatch(name):
            raise ValueError(f"nome di servizio non valido: {name!r} (solo a-z, 0-9 e -)")
        if not _IMAGE.fullmatch(image) or image.endswith(":"):
            raise ValueError(f"immagine del servizio {name!r} non valida: {image!r}")
        if name in ports:
            port = ports[name]
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError(f"porta del servizio {name!r} non valida: {port!r}")


def _services_block(services: dict[str, str], ports: dict[str, int]) -> str:
    validate_services(services, ports)
    lines = ["    services:"]
    for name, image in services.items():
        lines += [f"      '{name}':", f"        image: '{image}'"]
        if name in ports:
            # i servizi girano in container sull'host del job: senza `ports` il job non li raggiunge
            lines += ["        ports:", f'          - "{ports[name]}:{ports[name]}"']
    return "\n".join(lines)


def _render(name: str, text: str, default_branch: str, services: dict[str, str],
            ports: dict[str, int]) -> str:
    text = text.replace(BRANCH_PLACEHOLDER, default_branch)
    expected = SERVICES_WORKFLOWS.get(name, 0)
    marker = "    " + SERVICES_MARKER + "\n"
    if text.count(marker) != expected:
        raise ValueError(f"tollgate-{name}.yml: segnaposto dei servizi attesi {expected}, "
                         f"trovati {text.count(marker)}")
    return text.replace(marker, _services_block(services, ports) + "\n" if services else "")


def files(plugin_root: Path, *, default_branch: str, services: dict[str, str],
          ports: dict[str, int] | None = None) -> dict[str, bytes]:
    """Percorso nel repo del progetto → contenuto. Il ramo predefinito sostituisce
    `__DEFAULT_BRANCH__` nei workflow dei `push`. I servizi entrano in ogni job che esegue la
    suite del progetto (`head` e `base` di `tollgate-run`, `ids` di `tollgate-base`); `ports`
    (nome del servizio → porta) li rende raggiungibili dal job con `ports: ["P:P"]` (9.6)."""
    if not _BRANCH.fullmatch(default_branch):
        raise ValueError(f"nome del ramo predefinito non valido: {default_branch!r}")
    root = Path(plugin_root)
    out: dict[str, bytes] = {}
    for name in WORKFLOW_NAMES:
        text = (root / WORKFLOWS_DIR / f"tollgate-{name}.yml").read_text(encoding="utf-8")
        out[f".github/workflows/tollgate-{name}.yml"] = _render(
            name, text, default_branch, services, ports or {}).encode("utf-8")
    out[f"{INSTALL_DIR}/VERSION"] = f"{VERSION}\n".encode()
    out[f"{INSTALL_DIR}/FINGERPRINT"] = f"{fingerprint(root / 'bin')}\n".encode()
    for path in _sources(root / "bin"):
        out[f"{INSTALL_DIR}/bin/{path.relative_to(root / 'bin').as_posix()}"] = path.read_bytes()
    return out
