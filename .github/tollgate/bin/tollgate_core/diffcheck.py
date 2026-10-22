"""Violazioni di test-guard e scope su un diff (spec 7.4, 8.2), senza stato: nessun DB né
lavoro. Lo scope, i documenti bloccati, il piano registrato e la spec approvata arrivano come
dati: in locale li ricava `violations.diff_violations`, nel gate `tollgate_gate`.

Il piano registrato è esente solo con il blob di `plan_sha`: quel blob non è un collegamento
simbolico, quindi qui il controllo che fa `violations.is_registered_plan` non serve."""
from __future__ import annotations

import posixpath
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from tollgate_analysis import globs, profiles as prof, testguard, waivers
from tollgate_analysis.approvals import REVIEWS_DIR
from tollgate_analysis.testguard import DEFAULT_TEST_GLOBS, GuardConfig, Violation

from . import git
from .config import Config, output_excludes


@dataclass
class DiffCheck:
    violations: list[Violation] = field(default_factory=list)
    watched: list[str] = field(default_factory=list)


def guard_config(cfg: Config, files) -> GuardConfig:
    tg = cfg.get("test_guard")
    profs = cfg.profiles
    active = prof.active_profiles(files, profs, cfg.get("profiles.active"))
    extra = lambda k: [x for n in active for x in profs[n].get(k, [])]  # noqa: E731
    commands = " ".join(str(v) for v in cfg.get("commands").values())
    return GuardConfig(
        test_globs=list(DEFAULT_TEST_GLOBS) + tg["test_globs"] + extra("test_globs"),
        fixture_globs=tg["fixture_globs"], ci_globs=tg["ci_globs"],
        verification_globs=tg["verification_globs"],
        verification_watch=tg["verification_watch"],
        skip_markers=tg["skip_markers"] + extra("skip_markers"),
        assert_markers=tg["assert_markers"] + extra("assert_markers"),
        js_form="jest" if "jest" in commands else "vitest")


def is_docs_md(rel: str | None) -> bool:
    return bool(rel) and rel.startswith("docs/superpowers/") and rel.endswith(".md")


def scope_exempt_rel(cfg: Config, *, issue: int, rel: str, scope: set[str],
                     locked: set[str]) -> bool:
    """Esenzioni dallo scope (7.4); quella di `docs/superpowers/reviews/<N>/` (report e
    approvazioni del lavoro) vale a ogni livello, non solo in L2. I percorsi di `scope` sono nomi
    letterali (possono contenere `[ ]`): si confrontano per uguaglianza, mai come pattern. Solo
    `[scope] always` è fatto di pattern. `locked` sono i documenti bloccati."""
    if rel.startswith(".superpowers/") or rel == f".tollgate/waivers/{issue}.toml":
        return True
    # I report e le approvazioni del lavoro li scrivono solo la CLI e gli hook e il
    # coordinatore li committa con spec e piano (decisione 26).
    if rel.startswith(f"{REVIEWS_DIR}/{issue}/"):
        return True
    if git.excluded(rel, output_excludes(cfg)):
        return True
    if is_docs_md(rel) and not rel.startswith(f"{REVIEWS_DIR}/") and rel not in locked:
        return True
    if globs.match_any(cfg.get("scope.always"), rel):
        return True
    manifest = cfg.get("scope.lockfiles").get(posixpath.basename(rel))
    return bool(manifest and posixpath.join(posixpath.dirname(rel), manifest) in scope)


def _blob_at_head(repo, head_ref: str | None, path: str) -> str | None:
    """Il blob di `path` in `head_ref`, o nel working tree se `head_ref` è `None`."""
    try:
        if head_ref is None:
            return git.blob_sha(repo, path) if (Path(repo) / path).is_file() else None
        return git.blob_at(repo, head_ref, path)
    except git.GitError:
        return None


def diff_check(cfg: Config, *, repo: Path, issue: int, level: str, base_ref: str,
               head_ref: str | None, changes, scope: set[str] | None, locked: set[str],
               registered_plan: tuple[str, str] | None,
               approved_spec: tuple[str, str] | None, waiver_file: waivers.WaiverFile | None,
               components: Mapping[str, bool],
               plan_change_is_attention: bool = False) -> DiffCheck:
    """Violazioni di test-guard e scope su `changes` (da `base_ref` a `head_ref`; `None` è il
    working tree), senza le cartelle di output e `.tollgate-run/`, e i file osservati da
    `verification_watch`. Restano solo le violazioni non coperte da una deroga, anche in attesa
    (decisione 9). Un componente assente è acceso.

    `scope` è `None` senza controllo di scope. `registered_plan = (percorso, blob)` è esente solo
    se il blob in testa è quello; con `plan_change_is_attention` il piano registrato cambiato non
    è una violazione (lo segnala il gate come `plan_changed`). `approved_spec = (percorso, sha
    dell'approvazione)` è esente solo se il blob in testa coincide."""
    skip = output_excludes(cfg)
    changes = [c for c in changes if not git.excluded(c.path, skip)]
    out: list[Violation] = []
    watched: list[str] = []
    if components.get("test_guard", True):
        tg = []
        for c in changes:
            base_text = None if c.status == "A" else git.text_at(repo, base_ref,
                                                                 c.old_path or c.path)
            if c.status == "D":
                head_text = None
            elif head_ref is None:
                head_text = git.worktree_text(repo, c.path)
            else:
                head_text = git.text_at(repo, head_ref, c.path)
            tg.append(testguard.Change(c.status, c.path, c.old_path, base_text, head_text,
                                       c.binary))
        result = testguard.check(tg, guard_config(cfg, [c.path for c in changes]))
        out += result.violations
        watched = result.watched
    if components.get("scope_check", True) and level != "L0" and scope is not None:
        for c in changes:
            if c.path in scope or scope_exempt_rel(cfg, issue=issue, rel=c.path, scope=scope,
                                                   locked=locked):
                continue
            if registered_plan and c.path == registered_plan[0] and (
                    plan_change_is_attention
                    or _blob_at_head(repo, head_ref, c.path) == registered_plan[1]):
                continue
            if approved_spec and c.path == approved_spec[0] \
                    and _blob_at_head(repo, head_ref, c.path) == approved_spec[1]:
                continue
            out.append(Violation("out_of_scope", c.path, "file fuori dallo scope del piano",
                                 "scope"))
    return DiffCheck(waivers.unresolved(out, waiver_file), watched)


def diff_findings(cfg: Config, *, repo: Path, issue: int, level: str, base_ref: str,
                  head_ref: str | None, changes, scope: set[str] | None, locked: set[str],
                  registered_plan: tuple[str, str] | None,
                  approved_spec: tuple[str, str] | None,
                  waiver_file: waivers.WaiverFile | None, components: Mapping[str, bool],
                  plan_change_is_attention: bool = False) -> list[Violation]:
    """Le sole violazioni di `diff_check` (stessi parametri)."""
    return diff_check(cfg, repo=repo, issue=issue, level=level, base_ref=base_ref,
                      head_ref=head_ref, changes=changes, scope=scope, locked=locked,
                      registered_plan=registered_plan, approved_spec=approved_spec,
                      waiver_file=waiver_file, components=components,
                      plan_change_is_attention=plan_change_is_attention).violations
