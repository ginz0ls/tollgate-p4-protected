"""`gate sentinel` (spec 9.3, decisione 16): dopo un push sul ramo predefinito controlla che ogni
commit arrivato venga da una PR unita la cui testa aveva `tollgate/guard` e `tollgate/verdict`
verdi, scritti dal bot di GitHub Actions. Se no, stato `tollgate/sentinel` rosso sul commit e un
commento sull'unica issue di sentinel (creata se manca). Nel testo di issue e commenti entrano
solo SHA, numeri di PR e motivi di tollgate: niente titoli né corpi."""
from __future__ import annotations

import json
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from tollgate_core import ghcli, git, paths
from tollgate_core.config import load_config_at

from . import github

WORKFLOW = ".github/workflows/tollgate-sentinel.yml"
CONTEXT = "tollgate/sentinel"
REQUIRED = ("tollgate/guard", "tollgate/verdict")
ATTEMPTS = 3        # `commits/<sha>/pulls` può restare vuoto per qualche secondo dopo il merge (V5)
WAIT_S = 5.0
_ZEROS = "0" * 40
NO_PR = "nessuna PR unita nel ramo predefinito contiene il commit"


FORCED = "push forzato: intervallo non calcolabile"


def _commits(repo: Path, before: str, after: str) -> tuple[list[str], bool]:
    """I commit nuovi del push, dal più vecchio, e se il push è forzato. Con `before` tutto zeri
    (ramo nuovo) solo `after`. Un `before` che non si risolve o non è antenato di `after` (storia
    riscritta, ramo tornato indietro) è un push forzato: l'intervallo, se si calcola, vale
    comunque, ma `after` è non verificato."""
    if before == _ZEROS:
        return [after], False
    if git.resolve_ref(repo, before) is None:
        return [after], True
    forced = not git.ok(repo, "merge-base", "--is-ancestor", before, after)
    return git.rev_list(repo, before, after), forced


def _introduces_workflow(repo: Path, sha: str) -> bool:
    parent = git.resolve_ref(repo, f"{sha}^")
    return git.exists_at(repo, sha, WORKFLOW) and not (
        parent is not None and git.exists_at(repo, parent, WORKFLOW))


def _first_install(repo: Path, commits: list[str]) -> set[str]:
    """I commit che introducono il workflow di sentinel e i loro antenati nel push: il primo push
    che lo installa non apre l'issue (criterio 34)."""
    introducers = [c for c in commits if _introduces_workflow(repo, c)]
    return {c for c in commits
            if any(git.ok(repo, "merge-base", "--is-ancestor", c, i) for i in introducers)}


def _pr_problem(pr: dict, statuses: Callable[[str], list[dict]]) -> str | None:
    """Perché la testa della PR unita non basta (`None` se è verificata). Per ogni contesto conta
    solo lo stato più recente, e solo se scritto da `github-actions[bot]`."""
    number = pr.get("number") if isinstance(pr.get("number"), int) else "?"
    try:
        rows = statuses((pr.get("head") or {}).get("sha"))
    except ValueError:
        return f"PR #{number}: testa non valida"
    latest: dict[str, dict] = {}
    for row in rows:                    # dal più recente
        context = row.get("context")
        if context in REQUIRED and context not in latest:
            latest[context] = row
    problems = []
    for context in REQUIRED:
        row = latest.get(context)
        if row is None:
            problems.append(f"{context} assente")
        elif row.get("state") != "success":
            problems.append(f"{context} {row.get('state')}")
        elif (row.get("creator") or {}).get("login") != ghcli.STATUS_BOT:
            problems.append(f"{context} non scritto da github-actions[bot]")
    return f"PR #{number}: {', '.join(problems)}" if problems else None


def _commit_problem(sha: str, default: str, prs_for_commit: Callable[[str], list[dict]],
                    statuses: Callable[[str], list[dict]], attempts: int, wait: float,
                    sleep: Callable[[float], object]) -> str | None:
    merged: list[dict] = []
    for attempt in range(attempts):
        merged = [p for p in prs_for_commit(sha)
                  if p.get("merged_at") and (p.get("base") or {}).get("ref") == default]
        if merged or attempt == attempts - 1:
            break
        sleep(wait)
    if not merged:
        return NO_PR
    problems = []
    for pr in merged:
        problem = _pr_problem(pr, statuses)
        if problem is None:             # basta una PR unita e verificata
            return None
        problems.append(problem)
    return "; ".join(problems)


def unverified(repo: Path, *, before: str, after: str,
               prs_for_commit: Callable[[str], list[dict]],
               statuses: Callable[[str], list[dict]], default_branch: str | None = None,
               attempts: int = ATTEMPTS, wait: float = WAIT_S,
               sleep: Callable[[float], object] = time.sleep) -> list[tuple[str, str]]:
    """I commit del push non verificati, con il motivo. Le funzioni di lettura sono parametri
    (nei test sono finte); `default_branch` è quello di `git.default_branch` se manca. Un elenco
    di PR vuoto si rilegge `attempts` volte, con `wait` secondi tra una e l'altra."""
    default = default_branch or git.default_branch(repo)
    if not default:
        raise git.GitError("ramo predefinito non determinabile")
    commits, forced = _commits(repo, before, after)
    skip = _first_install(repo, commits)
    found: dict[str, str] = {}
    for sha in commits:
        if sha in skip:
            continue
        reason = _commit_problem(sha, default, prs_for_commit, statuses, attempts, wait, sleep)
        if reason is not None:
            found[sha] = reason
    if forced:
        found[after] = "; ".join([FORCED, *([found[after]] if after in found else [])])
    return list(found.items())


def _body(found: list[tuple[str, str]]) -> str:
    lines = [f"- `{sha}`: {reason}" for sha, reason in found]
    return ("## tollgate: merge non verificato\n\nCommit arrivati sul ramo predefinito senza una "
            "PR unita con `tollgate/guard` e `tollgate/verdict` verdi:\n\n" + "\n".join(lines)
            + "\n\nChiudi l'issue su GitHub dopo averla letta.\n")


def run(event_path: Path, *, publish: bool, environ: Mapping[str, str], repo: Path | None = None,
        sleep: Callable[[float], object] = time.sleep, attempts: int = ATTEMPTS,
        wait: float = WAIT_S) -> int:
    """Controlla il push dell'evento. Senza `publish` stampa i commit non verificati (una stringa
    JSON per riga) e risponde 1 se ce ne sono, senza scrivere su GitHub. Con `publish` scrive lo
    stato rosso sui commit e segnala sull'issue di sentinel, poi risponde 0: il segnale sono lo
    stato e l'issue. Con `sentinel = false` nel `tollgate.toml` della punta esce subito."""
    repo = Path.cwd() if repo is None else repo
    event = github.read_event(event_path)
    ref, before, after = github.push_from_event(event)
    default = github.event_repo(event)[1]
    if ref != f"refs/heads/{default}" or after == _ZEROS:
        print(f"sentinel: il push non è su {default} (o cancella il ramo): niente da controllare")
        return 0
    if not load_config_at(repo, after).get("components.sentinel"):
        print("sentinel: componente disattivato (components.sentinel = false)")
        return 0
    state = paths.resolve_state(environ)
    # GITHUB_REPOSITORY serve solo a `--publish`; da leggere, il repository è quello dell'evento
    slug = github.repo_slug(
        environ if publish else {"GITHUB_REPOSITORY": github.event_repo(event)[0]})
    found = unverified(
        repo, before=before, after=after, default_branch=default,
        prs_for_commit=lambda sha: github.prs_for_commit(state, repo, slug, sha),
        statuses=lambda sha: github.statuses(state, repo, slug, sha),
        attempts=attempts, wait=wait, sleep=sleep)
    if not found:
        print("sentinel: tutti i commit del push vengono da una PR verificata")
        return 0
    if not publish:
        for sha, reason in found:
            print(json.dumps(f"{sha}: {reason}", ensure_ascii=False))
        print(f"sentinel: {len(found)} commit non verificati")
        return 1
    for sha, reason in found:           # prima gli stati, che sono il segnale; poi l'issue
        github.set_status(state, repo, slug, sha, context=CONTEXT, status="failure",
                          description=f"merge non verificato: {reason}")
    with tempfile.TemporaryDirectory(prefix="tollgate-sentinel-") as tmp:
        body = Path(tmp) / "body.md"
        body.write_text(_body(found), encoding="utf-8")
        github.report_sentinel(state, repo, slug, body_file=body)
    return 0
