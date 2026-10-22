"""Violazioni di test-guard e scope su un intero diff (spec 7.4, 8.2): fonte unica per gli hook
(commit) e per `finish check`. Nessuna dipendenza da `Ctx`."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from tollgate_analysis import approvals, profiles as prof, waivers
from tollgate_analysis.approvals import REVIEWS_DIR
from tollgate_analysis.testguard import Violation

from . import diffcheck, git, scope as scope_mod
from .config import Config
# `guard_config` e `is_docs_md` stanno in `diffcheck`; da qui li importano hook e contesto.
from .diffcheck import guard_config, is_docs_md, scope_exempt_rel  # noqa: F401

# Ordine delle fasi di un lavoro (phases.SEQUENCES): la spec si scrive in spec_audit e il
# piano in plan. Oltre quelle fasi la spec e il piano sono bloccati (6.2).
_ORDER = ("spec_audit", "plan", "approval", "execution", "review", "pr_open", "closed")


def _rank(phase: str | None) -> int:
    return _ORDER.index(phase) if phase in _ORDER else len(_ORDER)


def _approval_files(wt: Path) -> dict[str, str]:
    """`{percorso relativo: testo}` dei `spec-approval.md` presenti sul disco del worktree, anche
    di altre issue (fette successive, decisione 19). Illeggibili e collegamenti simbolici no."""
    out: dict[str, str] = {}
    folder = wt / REVIEWS_DIR
    try:
        found = sorted(folder.glob("*/spec-approval.md"))
    except OSError:
        return out
    for p in found:
        try:
            if p.is_symlink() or not p.is_file():
                continue
            out[p.relative_to(wt).as_posix()] = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return out


def locked_docs(work) -> set[str]:
    """Spec bloccata dopo approve spec, piano bloccato dopo la registrazione dello scope (6.2).
    Un lavoro in blocco vale la fase precedente al blocco. Un ritorno con reopen riporta la
    fase alla spec o al piano, e quei file tornano modificabili (l'approvazione resta storica).
    """
    phase = work["phase_before_block"] if work["phase"] == "blocked" else work["phase"]
    out = set()
    if work["plan_sha"] and work["plan_path"] and _rank(phase) > _rank("plan"):
        out.add(work["plan_path"])
    if work["spec_path"] and work["worktree"] and _rank(phase) > _rank("spec_audit") \
            and approvals.locate_spec_approval(
                _approval_files(Path(work["worktree"])), issue=work["issue"],
                spec_path=work["spec_path"], spec_blob=None) is not None:
        out.add(work["spec_path"])
    return out


def active_profile_names(cfg: Config, wt: Path, work, *, head: str | None = None) -> list[str]:
    """I profili attivi sul diff del lavoro (dalla base del lavoro, o da `default_ref` se manca,
    fino a `head` o alla punta del worktree), senza i file cancellati. Sta qui perché la usano
    sia `review prepare` sia l'applicazione dei riporti degli hook. Senza base né
    `default_ref`, o senza nessun commit (`head` nullo): nessun profilo, perché `changes` senza
    `head` includerebbe working tree e file non tracciati. Un diff illeggibile solleva
    `git.GitError`."""
    base = work["work_base_sha"] or git.default_ref(wt)
    tip = head or git.head(wt)
    if base is None or tip is None:
        return []
    files = [c.path for c in git.changes(wt, base, head=tip) if c.status != "D"]
    return prof.active_profiles(files, cfg.profiles, cfg.get("profiles.active"))


def scope_exempt(cfg: Config, work, rel: str, scope: set[str], *,
                 locked: set[str] | None = None) -> bool:
    """`diffcheck.scope_exempt_rel` per un lavoro. `locked` sono i documenti bloccati
    (`locked_docs`): chi esamina molti file lo calcola una volta sola e lo passa."""
    return scope_exempt_rel(cfg, issue=work["issue"], rel=rel, scope=scope,
                            locked=locked_docs(work) if locked is None else locked)


def is_registered_plan(work, wt: Path, path: str, head_ref: str | None) -> bool:
    """Il piano registrato, tale e quale (stesso blob di `plan_sha`): è bloccato, ma committarlo
    non lo modifica (lo fa il coordinatore dopo la registrazione)."""
    if path != work["plan_path"] or not work["plan_sha"] or (wt / path).is_symlink():
        return False
    try:
        sha = git.blob_sha(wt, path) if head_ref is None \
            else git.run(wt, "rev-parse", f"{head_ref}:{path}").strip()
    except git.GitError:
        return False
    return sha == work["plan_sha"]


def waiver_file(work) -> waivers.WaiverFile | None:
    if work is None or not work["worktree"]:
        return None
    p = Path(work["worktree"]) / waivers.path_for(work["issue"])
    try:
        return waivers.parse(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def diff_violations(cfg: Config, conn, work, wt: Path, base_ref: str, head_ref: str | None,
                    changes, *, components: Mapping[str, bool],
                    approved_spec: tuple[str, str] | None = None) -> list[Violation]:
    """Violazioni di test-guard e scope su `changes` (da `base_ref` a `head_ref`; `None` è il
    working tree): `diffcheck.diff_findings` con i dati del lavoro. Lo scope viene dal DB (nessun
    controllo in L0 o senza `plan_sha`). `approved_spec` (percorso, sha dell'approvazione) lo
    calcola chi sa leggere l'albero (`finish check`); gli hook passano `None`."""
    scope = (scope_mod.paths(conn, work["id"])
             if work["level"] != "L0" and work["plan_sha"] else None)
    plan_path = work["plan_path"]
    registered = (plan_path, work["plan_sha"]) if (
        plan_path and work["plan_sha"] and not (wt / plan_path).is_symlink()) else None
    return diffcheck.diff_findings(
        cfg, repo=wt, issue=work["issue"], level=work["level"], base_ref=base_ref,
        head_ref=head_ref, changes=changes, scope=scope,
        locked=locked_docs(work) if scope is not None else set(), registered_plan=registered,
        approved_spec=approved_spec, waiver_file=waiver_file(work), components=components)
