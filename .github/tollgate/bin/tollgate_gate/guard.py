"""`gate guard` (spec 9.2, decisione 15): gira in `pull_request_target` sul checkout del ramo
predefinito, prende gli oggetti della PR con `git fetch` e giudica solo i file di tollgate e i
workflow del progetto. Pubblica `tollgate/guard` e, se rosso, un commento che spiega perché."""
from __future__ import annotations

import json
import tempfile
from collections.abc import Mapping
from pathlib import Path

from tollgate_analysis import globs, prref, protected, workflows
from tollgate_core import git, paths

from . import comment, evaluate, github

CONTEXT = "tollgate/guard"
MAX_LISTED = 50     # file nominati per voce: oltre, una riga di riepilogo
DESC_OK = "file di tollgate e workflow del progetto in regola"
DESC_SHARED = "SHA condiviso da più PR: chiudine una"
NOT_APPLICABLE = "non applicabile: la PR non punta al ramo predefinito"


def _listed(paths_: list[str], template: str) -> list[str]:
    out = [template.format(path=p) for p in paths_[:MAX_LISTED]]
    if len(paths_) > MAX_LISTED:
        out.append(f"… altri {len(paths_) - MAX_LISTED} file")
    return out


def _is_config_exempt(path: str) -> bool:
    return protected.is_tollgate_file(path) or globs.match_any(protected.WAIVER_FILES, path)


def check(repo: Path, *, base_tip: str, head: str, head_ref: str, cross_repo: bool) -> list[str]:
    """I problemi di `head` rispetto alla punta del predefinito `base_tip` (`[]` se in regola).
    File di tollgate: uguali alla punta, salvo un ramo `tollgate-config/*` dello stesso repo che
    tocca solo file di tollgate e deroghe. Workflow del progetto nuovi o modificati: le regole di
    `workflows.problems`."""
    changes = git.changes(repo, base_tip, head=head)
    problems: list[str] = []
    exception = prref.is_config_branch(head_ref) and not cross_repo
    if exception:
        outside = sorted({p for c in changes for p in (c.path, c.old_path)
                          if p and not _is_config_exempt(p)})
        problems += _listed(outside, "il ramo tollgate-config tocca un file che non è di "
                                     "tollgate: {path}")
    else:
        problems += _listed(evaluate.tollgate_files_in_work(changes),
                            "file di tollgate diverso dal ramo predefinito: {path}")
    for c in changes:
        if c.status == "D" or not workflows.is_workflow_path(c.path) \
                or protected.is_tollgate_file(c.path):
            continue
        text = git.text_at(repo, head, c.path)
        for message in (workflows.problems(text) if text is not None else ["il file non si legge"]):
            problems.append(f"{c.path}: {message}")
    return problems


def _write(directory: str, name: str, text: str) -> Path:
    path = Path(directory) / name
    path.write_text(text, encoding="utf-8")
    return path


def _not_applicable_body(sha: str) -> str:
    return (f"{comment.GUARD_PREFIX} sha={sha} -->\n\n## tollgate: guard non applicabile\n\n"
            "La PR non punta al ramo predefinito: non applicabile.\n")


def _red_description(count: int) -> str:
    return f"{count} problemi nei file di tollgate o nei workflow: vedi il commento"


def run(event_path: Path, *, publish: bool, environ: Mapping[str, str],
        repo: Path | None = None) -> int:
    """Giudica la PR dell'evento. Senza `publish` stampa i problemi (una stringa JSON per riga) e
    risponde 1 se ce ne sono, senza toccare GitHub. Con `publish` pubblica lo stato e il commento
    e risponde 0: il segnale è lo stato. Una PR verso un altro ramo non riceve nessuno stato (gli
    stati sono per SHA: un `success` sulla stessa testa renderebbe unibile una PR verso il
    predefinito), solo il commento «non applicabile»; uno SHA che è la testa di più PR aperte
    verso il predefinito riceve `error`."""
    repo = Path.cwd() if repo is None else repo
    pr = github.pr_from_event(github.read_event(event_path))
    if pr is None:
        raise ValueError("evento senza pull_request")
    slug = github.repo_slug(environ) if publish else ""
    state = paths.resolve_state(environ)
    applicable = pr.base_ref == pr.default_branch
    if publish and not applicable:
        with tempfile.TemporaryDirectory(prefix="tollgate-guard-") as tmp:
            body = _write(tmp, "comment.md", _not_applicable_body(pr.head_sha))
            github.upsert_comment(state, repo, slug, pr.number, prefix=comment.GUARD_PREFIX,
                                  body_file=body)
        return 0
    if not applicable:
        print(f"guard: {NOT_APPLICABLE}")
        return 0
    tip = git.resolve_ref(repo, f"origin/{pr.default_branch}")
    if tip is None:
        raise git.GitError(f"origin/{pr.default_branch} non trovato: serve un checkout con il "
                           "ramo predefinito")
    git.fetch_ref(repo, f"refs/pull/{pr.number}/head", token=environ.get("GH_TOKEN"))
    head = git.resolve_ref(repo, pr.head_sha)
    if head is None:
        raise git.GitError("la testa della PR non è più quella dell'evento: la PR è cambiata")
    if git.resolve_ref(repo, "FETCH_HEAD") != head:
        print("guard: la PR è avanzata dopo l'evento, nessuna scrittura (la rigiudica l'evento "
              "nuovo)")
        return 0
    if publish:
        shared = github.shared_sha_prs(state, repo, slug, head, pr.default_branch)
        if len(shared) > 1:
            github.set_status(state, repo, slug, head, context=CONTEXT, status="error",
                              description=DESC_SHARED)
            return 0
    problems = check(repo, base_tip=tip, head=head, head_ref=pr.head_ref,
                     cross_repo=pr.cross_repo)
    if not publish:
        for p in problems:
            print(json.dumps(p, ensure_ascii=False))     # una riga, mai un comando del runner
        print(f"guard: {'rosso' if problems else 'verde'} ({len(problems)} problemi)")
        return 1 if problems else 0
    if not problems:
        github.set_status(state, repo, slug, head, context=CONTEXT, status="success",
                          description=DESC_OK)
        return 0
    with tempfile.TemporaryDirectory(prefix="tollgate-guard-") as tmp:
        body = _write(tmp, "comment.md", comment.render_guard(head, problems))
        github.upsert_comment(state, repo, slug, pr.number, prefix=comment.GUARD_PREFIX,
                              body_file=body)
    github.set_status(state, repo, slug, head, context=CONTEXT, status="failure",
                      description=_red_description(len(problems)))
    return 0
