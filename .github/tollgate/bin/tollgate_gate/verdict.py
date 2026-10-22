"""`gate evaluate` (spec 9.1 e 9.2, decisioni 4, 5 e 14): gira in `workflow_run` dopo `tollgate-run`
sul checkout del ramo predefinito. Fa i controlli preliminari, legge gli artefatti come dati,
calcola con `evaluate.evaluate` (puro) e pubblica `tollgate/verdict`, `tollgate/attention` e il
commento. L'I/O sta qui; `evaluate.py` resta puro. Un job `workflow_run` ha la cache in sola
lettura: `verdict` non salva mai nulla in cache."""
from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from tollgate_analysis import prblock
from tollgate_core import git, paths
from tollgate_core.config import ConfigError, load_config_at
from tollgate_core.ghcli import GhError

from . import attention, baseids, comment, evaluate, github
from .artifacts import read_results
from .guard import DESC_SHARED, NOT_APPLICABLE
from .model import BASE_FROM_CACHE, BASE_FROM_RUN, GITHUB, Evaluation, GateInputs

RUN_WORKFLOW_PATH = ".github/workflows/tollgate-run.yml"
RUN_EVENT = "pull_request"
NA_PREFIX = "<!-- tollgate-na"      # non è un verdetto: `task start --from-gate` non lo legge
ARTIFACT_PREFIX = "artefatti del run: "
VERDICT = "tollgate/verdict"
ATTENTION = "tollgate/attention"
DESC_ARTIFACTS = "artefatti del run mancanti o non validi: vedi il commento"
DESC_ERROR = "errore nel calcolo del gate"
DESC_OK = "nessuna voce rossa"
DESC_ATTENTION_OK = "nessuna voce da leggere"
DESC_ATTENTION_ERROR = "non calcolato: vedi tollgate/verdict"
MAX_IDS_FILE = baseids.MAX_IDS_FILE


def _event_problem(event: dict) -> str | None:
    run = event.get("workflow_run")
    if not isinstance(run, dict):
        return "evento senza workflow_run"
    if run.get("path") != RUN_WORKFLOW_PATH:
        return f"il run non è {RUN_WORKFLOW_PATH}"
    if run.get("event") != RUN_EVENT:
        return f"il run non è partito da un evento {RUN_EVENT}"
    return None


def prechecks(event: dict, pr: dict | None, *, default_branch: str,
              open_prs_for_sha: list[dict]) -> tuple[str, str]:
    """I controlli preliminari di 9.1 (decisione 5): `("ok" | "error" | "not_applicable",
    motivo)`. `pr` è la risposta di `GET pulls/<n>`, `open_prs_for_sha` le PR aperte verso il
    predefinito con questa testa (`github.shared_sha_prs`). Una PR verso un altro ramo non è un
    errore: non riceve nessuno stato."""
    if (problem := _event_problem(event)) is not None:
        return "error", problem
    if pr is None:
        return "error", "nessuna PR aperta con questa testa"
    if (pr.get("base") or {}).get("ref") != default_branch:
        return "not_applicable", NOT_APPLICABLE
    if (pr.get("head") or {}).get("sha") != event["workflow_run"].get("head_sha"):
        return "error", "SHA superato: la PR ha una testa nuova"
    if len(open_prs_for_sha) > 1:
        return "error", DESC_SHARED
    return "ok", ""


def _base_ids(repo: Path, base_sha: str, cache: Path | None, artifact: Path | None
              ) -> tuple[dict[str, set[str]] | None, str | None]:
    """Gli identificativi della base, nell'ordine della decisione 12: la cache dell'albero di
    `merge-base`, poi l'artefatto di `tollgate-run` (voce `base_ids_from_run`). Un file
    illeggibile, di un altro albero o collegamento simbolico vale come assente."""
    tree = git.run(repo, "rev-parse", f"{base_sha}^{{tree}}").strip()
    if cache is not None and Path(cache).is_file():
        if (ids := baseids.load(Path(cache), tree=tree)) is not None:
            return ids, BASE_FROM_CACHE
    if artifact is not None:
        path = Path(artifact) / "ids.json"
        try:
            usable = path.is_file() and not path.is_symlink() \
                and path.stat().st_size <= MAX_IDS_FILE
        except OSError:
            usable = False
        if usable and (ids := baseids.load(path, tree=tree)) is not None:
            return ids, BASE_FROM_RUN
    return None, None


def inputs_from_github(repo: Path, event: dict, pr: dict, *, artifacts: Path,
                       base_ids_cache: Path | None, base_ids_artifact: Path | None, state,
                       environ: Mapping[str, str]) -> tuple[GateInputs | None, list[str]]:
    """Gli ingressi di `evaluate` per la PR `pr` (risposta di `GET pulls/<n>`) o i motivi per cui
    non si possono raccogliere (decisione 4): configurazione dalla punta del predefinito, mai dal
    working tree; diff `merge-base..testa`; artefatti come dati, controllati sullo SHA giudicato e
    sulla punta; blocco, issue e deroghe della testa. I problemi sono `error`, mai eccezioni."""
    full_name, default = github.event_repo(event)
    facts = github.pr_from_rest(pr, repo_full_name=full_name, default_branch=default)
    sha, slug = facts.head_sha, github.repo_slug(environ)
    try:
        tip = git.resolve_ref(repo, f"origin/{default}")
        if tip is None:
            return None, [f"origin/{default} non trovato: serve un checkout del ramo predefinito"]
        cfg = load_config_at(repo, tip)
        git.fetch_ref(repo, f"refs/pull/{facts.number}/head", token=environ.get("GH_TOKEN"))
        head = git.resolve_ref(repo, sha)
        if head is None or git.resolve_ref(repo, "FETCH_HEAD") != head:
            return None, ["la testa della PR non è quella giudicata: la PR è cambiata"]
        base_sha = git.run(repo, "merge-base", tip, head).strip()
        base_ids, source = _base_ids(repo, base_sha, base_ids_cache, base_ids_artifact)
        n = evaluate.pr_issue_number(facts)
        waiver_text = git.text_at(repo, head, f".tollgate/waivers/{n}.toml") if n else None
    except (git.GitError, ConfigError) as e:
        return None, [str(e)]
    meta: dict = {}
    results, applicable, problems = read_results(artifacts, meta=meta)
    if problems:
        return None, [f"{ARTIFACT_PREFIX}{p}" for p in problems]
    mismatch = []
    if meta.get("sha") != head:
        mismatch.append(f"{ARTIFACT_PREFIX}results.json non è dello SHA giudicato")
    if meta.get("config_sha") != tip:
        mismatch.append("configurazione del gate cambiata dopo il run: rilancia i controlli")
    if not applicable:
        mismatch.append(f"{ARTIFACT_PREFIX}results.json dichiara la PR non applicabile")
    if mismatch:
        return None, mismatch
    try:
        issue = github.issue(state, repo, slug, n) if n else None
        sentinel_open = [r["number"] for r in github.open_sentinel_issues(state, repo, slug)]
    except GhError as e:
        return None, [f"lettura da GitHub non riuscita: {e}"]
    return GateInputs(
        where=GITHUB, repo=repo, cfg=cfg, base_sha=base_sha, head_sha=head, pr=facts,
        block=prblock.parse(facts.body), issue=issue, commands=results, base_ids=base_ids,
        base_ids_source=source, waiver_text=waiver_text, sentinel_open=sentinel_open), []


def _error_description(errors: list[str]) -> str:
    first = errors[0]
    return (DESC_ARTIFACTS if first.startswith(ARTIFACT_PREFIX)
            else f"{DESC_ERROR}: {first}")


def _descriptions(ev: Evaluation) -> tuple[str, str]:
    """Le descrizioni di `verdict` e `attention` (scritte da tollgate, al più 140 caratteri)."""
    if ev.errors:
        return _error_description(ev.errors), DESC_ATTENTION_ERROR
    read = sum(1 for i in ev.attention if attention.group(i.key) == attention.READ)
    return (f"{len(ev.red)} voci da correggere: vedi il commento" if ev.red else DESC_OK,
            f"{read} voci da leggere: vedi il commento" if ev.attention_state == "failure"
            else DESC_ATTENTION_OK)


def _write(directory: str, name: str, text: str) -> Path:
    path = Path(directory) / name
    path.write_text(text, encoding="utf-8")
    return path


def _na_body(sha: str) -> str:
    return (f"{NA_PREFIX} sha={sha} -->\n\n## tollgate: verdetto non applicabile\n\n"
            "La PR non punta al ramo predefinito: non applicabile.\n")


def _statuses(state, repo, slug, sha, ev: Evaluation) -> None:
    verdict_desc, attention_desc = _descriptions(ev)
    github.set_status(state, repo, slug, sha, context=VERDICT, status=ev.verdict_state,
                      description=verdict_desc)
    github.set_status(state, repo, slug, sha, context=ATTENTION,
                      status="error" if ev.errors else ev.attention_state,
                      description=attention_desc)


def _error(reason: str) -> Evaluation:
    return Evaluation(errors=[reason])


def main(event_path: Path, *, artifacts: Path, base_ids_cache: Path | None,
         base_ids_artifact: Path | None, publish: bool, environ: Mapping[str, str],
         repo: Path | None = None) -> int:
    """Il verdetto sulla PR del run. Senza `publish` stampa l'esito (una stringa JSON per voce) e
    risponde 1 se non è verde, senza scrivere su GitHub. Con `publish` scrive `tollgate/verdict`,
    `tollgate/attention` e il commento e risponde 0: il segnale sono gli stati. Una PR verso un
    altro ramo non riceve nessuno stato, solo il commento «non applicabile». Subito prima di
    scrivere ricontrolla che lo SHA sia ancora la testa della PR (decisione 14): se non lo è non
    scrive nulla di quello SHA. Noto lo SHA, ogni altro guasto (GitHub, forma della PR, calcolo)
    è un `error` esplicito sullo SHA (decisione 5): l'uscita è 1 solo se nemmeno questo si
    scrive."""
    repo = Path.cwd() if repo is None else repo
    event = github.read_event(event_path)
    state = paths.resolve_state(environ)
    slug = github.repo_slug(environ)
    sha = github.run_sha(event)
    try:
        return _judge(event, repo, state, slug, sha, artifacts=artifacts,
                      base_ids_cache=base_ids_cache, base_ids_artifact=base_ids_artifact,
                      publish=publish, environ=environ)
    except Exception as e:      # confine: dopo questo punto ogni esito è uno stato esplicito
        reason = f"{type(e).__name__}: {e}"
        sys.stderr.write(f"gate evaluate: {reason}\n")
        if not publish:
            return 1
        try:
            _statuses(state, repo, slug, sha, _error(reason))
        except Exception as write_error:
            sys.stderr.write(f"gate evaluate: stato non scritto: {write_error}\n")
            return 1
        return 0


def _head_is(state, repo, slug, number: int, sha: str) -> bool:
    """Lo SHA è ancora la testa della PR (`GET pulls/<n>`); una risposta malformata vale no."""
    head = github.pull(state, repo, slug, number).get("head")
    return isinstance(head, dict) and head.get("sha") == sha


def _judge(event: dict, repo: Path, state, slug: str, sha: str, *, artifacts: Path,
           base_ids_cache: Path | None, base_ids_artifact: Path | None, publish: bool,
           environ: Mapping[str, str]) -> int:
    run = event.get("workflow_run")
    default = github.event_repo(event)[1]

    def finish(ev: Evaluation, number: int | None = None) -> int:
        """Scrive (o stampa) l'esito `ev` per `sha`; con `number` anche il commento."""
        if not publish:
            return _print(ev)
        if number is not None:
            if not _head_is(state, repo, slug, number, sha):
                print("verdict: la PR è avanzata dopo l'evento, nessuna scrittura (la "
                      "rigiudica l'evento nuovo)")
                return 0
            with tempfile.TemporaryDirectory(prefix="tollgate-verdict-") as tmp:
                body = _write(tmp, "comment.md", comment.render(sha, ev))
                github.upsert_comment(state, repo, slug, number, prefix=comment.marker(sha),
                                      body_file=body)
        _statuses(state, repo, slug, sha, ev)
        return 0

    if (problem := _event_problem(event)) is not None:
        return finish(_error(problem))
    shared = github.shared_sha_prs(state, repo, slug, sha, default)
    numbers = [p["number"] for p in run.get("pull_requests") or []
               if isinstance(p, dict) and isinstance(p.get("number"), int)]
    if not numbers:
        numbers = [p["number"] for p in github.prs_for_commit(state, repo, slug, sha)
                   if p.get("state") == "open" and (p.get("head") or {}).get("sha") == sha]
    pulls = [p for p in (github.pull(state, repo, slug, n) for n in dict.fromkeys(numbers))
             if p.get("state", "open") == "open"]
    here = [p for p in pulls if (p.get("base") or {}).get("ref") == default]
    for other in pulls:
        if other not in here and (other.get("head") or {}).get("sha") == sha:
            # nessuno stato: sono per SHA e vincerebbe l'ultimo scritto
            _not_applicable(state, repo, slug, other["number"], sha, publish)
    if not here:
        return 0 if pulls else finish(_error(prechecks(event, None, default_branch=default,
                                                       open_prs_for_sha=shared)[1]))
    pr = next((p for p in here if (p.get("head") or {}).get("sha") == sha), here[0])
    outcome, reason = prechecks(event, pr, default_branch=default, open_prs_for_sha=shared)
    if outcome == "error":
        return finish(_error(reason))
    inputs, problems = inputs_from_github(
        repo, event, pr, artifacts=artifacts, base_ids_cache=base_ids_cache,
        base_ids_artifact=base_ids_artifact, state=state, environ=environ)
    ev = Evaluation(errors=problems) if inputs is None else evaluate.evaluate(inputs)
    return finish(ev, pr["number"])


def _not_applicable(state, repo, slug, number: int, sha: str, publish: bool) -> None:
    if not publish:
        print(f"verdict: PR #{number}: {NOT_APPLICABLE}")
        return
    if not _head_is(state, repo, slug, number, sha):
        return
    with tempfile.TemporaryDirectory(prefix="tollgate-verdict-") as tmp:
        body = _write(tmp, "comment.md", _na_body(sha))
        github.upsert_comment(state, repo, slug, number, prefix=NA_PREFIX, body_file=body)


def _print(ev: Evaluation) -> int:
    for item in [*ev.errors, *(i.text for i in ev.red), *(i.text for i in ev.attention)]:
        print(json.dumps(item, ensure_ascii=False))     # una riga, mai un comando del runner
    print(f"verdict: {ev.verdict_state}, attention: "
          f"{'error' if ev.errors else ev.attention_state}")
    return 0 if ev.verdict_state == "success" else 1
