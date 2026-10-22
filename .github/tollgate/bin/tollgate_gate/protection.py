"""Protezione del ramo predefinito e modalità del gate (spec 9.3, decisioni 18 e 19).

`classify` decide dalla risposta della GET di protezione (fatta con `gh api --include`, forma V2),
`missing` elenca ciò che manca a una protezione presente, `protection_body` è il corpo della PUT.
La GET richiede l'amministrazione in lettura: con il token dell'agente la risposta è «non
determinata» e non si deduce mai `protected` per esclusione."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from tollgate_core import ghcli
from tollgate_core.ghcli import REQUIRED_CONTEXTS, GhError

DETECT, PROTECTED, PROTECTED_UNSET, UNDETERMINED = (
    "detect", "protected", "protected_unset", "undetermined")
APP_ID_PLACEHOLDER = "__APP_ID__"
# Il job di `gate/workflows/tollgate-base.yml`: il suo check-run (nome esatto, unico tra i cinque
# workflow, V6) porta l'`app.id` che `protect.sh` fissa come sorgente dei controlli.
BASE_JOB = "tollgate-base"
BASE_APP_SLUG = "github-actions"

_DETECT_MESSAGE = "Upgrade to GitHub Pro or make this repository public"
_UNSET_MESSAGE = "Branch not protected"
# il ramo finisce in un percorso dell'API: stessa forma ammessa da `install.files`
_BRANCH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/-]*$")

# Campo della risposta di GitHub → cosa manca quando non è come serve.
REQUIRED_FIELDS = {
    "required_pull_request_reviews": "pull request obbligatoria",
    "required_status_checks.strict": "ramo aggiornato obbligatorio (strict)",
    "enforce_admins": "regole valide anche per gli amministratori (enforce_admins)",
    "allow_force_pushes": "push forzato consentito",
    "allow_deletions": "cancellazione del ramo consentita",
}


def classify(status: int | None, message: str) -> str:
    """Modalità dalla risposta della GET di protezione. `status` è `None` senza risposta (rete,
    `gh` assente)."""
    if status == 200:
        return PROTECTED
    if status == 403 and _DETECT_MESSAGE in message:
        return DETECT
    if status == 404 and _UNSET_MESSAGE in message:
        return PROTECTED_UNSET
    return UNDETERMINED


def _enabled(data: dict, key: str) -> bool:
    value = data.get(key)
    return isinstance(value, dict) and value.get("enabled") is True


def _checks(data: dict) -> dict[str, object]:
    """Contesto → `app_id` dei controlli obbligatori. I contesti elencati solo in `contexts` (la
    forma vecchia) non hanno una sorgente: `None`."""
    checks = data.get("required_status_checks")
    if not isinstance(checks, dict):
        return {}
    found: dict[str, object] = {c: None for c in checks.get("contexts") or []
                                if isinstance(c, str)}
    for item in checks.get("checks") or []:
        if isinstance(item, dict) and isinstance(item.get("context"), str):
            found[item["context"]] = item.get("app_id")
    return found


def missing(data: dict, *, contexts=REQUIRED_CONTEXTS) -> list[str]:
    """Ciò che manca a una protezione presente: PR obbligatoria, i controlli con la sorgente
    fissata (`app_id` positivo: `-1` è «qualunque sorgente»), `strict`, `enforce_admins`, niente
    push forzato né cancellazione. Un valore che non si legge conta come mancante."""
    out = []
    if not isinstance(data.get("required_pull_request_reviews"), dict):
        out.append(REQUIRED_FIELDS["required_pull_request_reviews"])
    present = _checks(data)
    for context in contexts:
        if context not in present:
            out.append(f"controllo obbligatorio {context}")
            continue
        app_id = present[context]
        if not isinstance(app_id, int) or isinstance(app_id, bool) or app_id < 1:
            out.append(f"controllo {context} senza la sorgente fissata (app_id {app_id})")
    status_checks = data.get("required_status_checks")
    if not isinstance(status_checks, dict) or status_checks.get("strict") is not True:
        out.append(REQUIRED_FIELDS["required_status_checks.strict"])
    if not _enabled(data, "enforce_admins"):
        out.append(REQUIRED_FIELDS["enforce_admins"])
    if _enabled(data, "allow_force_pushes"):
        out.append(REQUIRED_FIELDS["allow_force_pushes"])
    if _enabled(data, "allow_deletions"):
        out.append(REQUIRED_FIELDS["allow_deletions"])
    return out


def _body(app_id) -> dict:
    return {
        "required_status_checks": {
            "strict": True,
            "checks": [{"context": c, "app_id": app_id} for c in REQUIRED_CONTEXTS]},
        "enforce_admins": True,
        "required_pull_request_reviews": {"required_approving_review_count": 0},
        "restrictions": None,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }


def protection_body(app_id: int) -> dict:
    """Corpo della PUT `branches/<ramo>/protection`. `app_id` è quello letto dal check-run di
    `tollgate-base`: mai `-1`, che vorrebbe dire «qualunque sorgente»."""
    if not isinstance(app_id, int) or isinstance(app_id, bool) or app_id < 1:
        raise ValueError(f"app_id non valido: {app_id!r} (serve un intero positivo, mai -1)")
    return _body(app_id)


def body_template() -> str:
    """Il corpo della PUT con `"__APP_ID__"` al posto di `app_id`: `protect.sh` lo sostituisce
    col valore che legge dal check-run, dopo averne controllato la forma."""
    return json.dumps(_body(APP_ID_PLACEHOLDER), indent=2) + "\n"


@dataclass(frozen=True)
class ProtectionRead:
    kind: str
    missing: list[str] = field(default_factory=list)
    note: str = ""


def _message(result: ghcli.ApiResult) -> str:
    if isinstance(result.data, dict) and isinstance(result.data.get("message"), str):
        return result.data["message"]
    return result.stderr.strip()


def read(state, cwd, branch: str) -> ProtectionRead:
    """Legge la protezione di `branch` con le credenziali di `gh`. Mai un'eccezione: un errore di
    `gh` o una risposta che non si capisce è `undetermined`, con la nota che lo spiega."""
    if not _BRANCH.match(branch or ""):
        return ProtectionRead(UNDETERMINED, [], f"nome del ramo non valido: {branch!r}")
    try:
        result = ghcli.api(state, cwd, f"repos/{{owner}}/{{repo}}/branches/{branch}/protection",
                           include=True)
    except GhError as e:
        return ProtectionRead(UNDETERMINED, [], str(e))
    message = _message(result)
    kind = classify(result.status, message)
    if kind == PROTECTED:
        if not isinstance(result.data, dict):
            return ProtectionRead(UNDETERMINED, [], "risposta di protezione non leggibile")
        return ProtectionRead(PROTECTED, missing(result.data), "")
    note = message or (f"HTTP {result.status}" if result.status else "")
    return ProtectionRead(kind, [], note)


def actions_enabled(state, cwd) -> bool | None:
    """`enabled` di `GET actions/permissions` (V9); `None` se la risposta non si legge."""
    try:
        data = ghcli.api(state, cwd, "repos/{owner}/{repo}/actions/permissions").data
    except GhError:
        return None
    enabled = data.get("enabled") if isinstance(data, dict) else None
    return enabled if isinstance(enabled, bool) else None
