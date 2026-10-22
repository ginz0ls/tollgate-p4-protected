"""`gh` per il flusso (spec 3.1). Nei test `TOLLGATE_GH` indica il finto `tests/fakegh.py`.

Nessun testo dell'issue entra mai in un argomento: si passano solo numeri, SHA e prefissi
costruiti da numeri."""
from __future__ import annotations

from dataclasses import dataclass

from tollgate_core.ghcli import (GH_ENV, GH_TIMEOUT_S, REQUIRED_CONTEXTS, SENTINEL_TITLE,  # noqa: F401
                                 GhError, decode_json_values, gh_cmd, run as _run, run_json,
                                 run_json_lines)
from tollgate_gate import github


@dataclass(frozen=True)
class Issue:
    number: int
    title: str
    body: str
    state: str
    labels: tuple[str, ...]
    author_association: str


def _run_checked(state, repo, args) -> None:
    r = _run(state, repo, args)
    if r.returncode != 0:
        raise GhError(f"gh {' '.join(args[:2])}: {r.stderr.strip() or 'uscita ' + str(r.returncode)}")


def auth_ok(state, repo) -> bool:
    try:
        return _run(state, repo, ["auth", "status"]).returncode == 0
    except GhError:
        return False


def _label_names(raw) -> tuple[str, ...]:
    out = []
    for item in raw if isinstance(raw, list) else []:
        name = item.get("name") if isinstance(item, dict) else item
        if isinstance(name, str) and name:
            out.append(name)
    return tuple(out)


def issue(state, repo, n: int) -> Issue:
    """L'issue dall'API REST: `gh issue view --json` non ha `authorAssociation` (gh 2.46)."""
    data = run_json(state, repo, ["api", f"repos/{{owner}}/{{repo}}/issues/{int(n)}"])
    if not isinstance(data, dict):
        raise GhError(f"issue #{n}: risposta inattesa")

    def text(key):
        v = data.get(key)
        return v if isinstance(v, str) else ""

    return Issue(number=int(data.get("number") or n), title=text("title"), body=text("body"),
                 state=text("state").upper(), labels=_label_names(data.get("labels")),
                 author_association=text("author_association").upper())


# L'API REST dà `state` in minuscolo e il merge solo in `merged_at`: si porta alla forma di
# `gh pr list` (OPEN, CLOSED, MERGED), che si aspettano `start` e i task successivi.
PR_JQ = (".[] | {number, headRefName: .head.ref, state: (if .merged_at then \"MERGED\" else "
         "(.state | ascii_upcase) end), url: .html_url}")


def prs_for_branch_prefix(state, repo, prefix: str) -> list[dict]:
    """Tutte le PR (aperte e chiuse) i cui rami cominciano per `prefix`: `api --paginate`, una
    riga JSON per PR (G5)."""
    data = run_json_lines(state, repo, ["api", "--paginate",
                                        "repos/{owner}/{repo}/pulls?state=all&per_page=100",
                                        "--jq", PR_JQ])
    return [p for p in data if str(p.get("headRefName", "")).startswith(prefix)]


def pr_for_branch(state, repo, branch: str) -> dict | None:
    """La PR con il numero più alto per il ramo, in qualunque stato (G4), escluse quelle da fork:
    `--head` filtra per nome e non per proprietario, e il nome del ramo è prevedibile. Un errore
    di `gh` è un `GhError`, mai «nessuna PR»."""
    data = run_json(state, repo, ["pr", "list", "--head", branch, "--state", "all", "--limit",
                                  "100", "--json",
                                  "number,state,url,headRefOid,mergedAt,isCrossRepository"])
    if not isinstance(data, list):
        raise GhError("pr list: risposta inattesa")
    found = [p for p in data if isinstance(p, dict) and isinstance(p.get("number"), int)
             and p.get("isCrossRepository") is not True]
    return max(found, key=lambda p: p["number"]) if found else None


def pr_view(state, repo, number: int) -> dict:
    data = run_json(state, repo, ["pr", "view", str(int(number)), "--json",
                                  "number,state,url,mergedAt"])
    if not isinstance(data, dict):
        raise GhError(f"pr view {number}: risposta inattesa")
    return data


def pr_create(state, repo, *, branch: str, base: str, title: str, body_file) -> None:
    """Il titolo viene dal nome del ramo (solo `[a-z0-9-]`), il corpo da un file: nessun testo
    non fidato in un argomento. L'URL non si legge da stdout (G2): si rilegge con
    `pr_for_branch`."""
    _run_checked(state, repo, ["pr", "create", "--head", branch, "--base", base, "--title",
                               title, "--body-file", str(body_file)])


def pr_edit(state, repo, number: int, *, body_file) -> None:
    _run_checked(state, repo, ["pr", "edit", str(int(number)), "--body-file", str(body_file)])


def pr_body(state, repo, number: int) -> str:
    """Il corpo della PR (dato non fidato: `adopt` ne legge solo il blocco JSON)."""
    data = run_json(state, repo, ["pr", "view", str(int(number)), "--json", "body"])
    body = data.get("body") if isinstance(data, dict) else None
    if not isinstance(body, str):
        raise GhError(f"pr view {number}: risposta inattesa")
    return body


def pr_comments(state, repo, number: int) -> list[dict]:
    data = run_json(state, repo, ["pr", "view", str(int(number)), "--json", "comments"])
    comments = data.get("comments") if isinstance(data, dict) else None
    if not isinstance(comments, list):
        raise GhError(f"pr view {number}: risposta inattesa")
    return [c for c in comments if isinstance(c, dict)]


def commit_state(state, repo, sha: str) -> dict[str, str]:
    """Stato dei soli contesti obbligatori (`REQUIRED_CONTEXTS`) presenti sul commit."""
    data = run_json(state, repo, ["api", f"repos/{{owner}}/{{repo}}/commits/{sha}/status"])
    found = {}
    for item in data.get("statuses", []) if isinstance(data, dict) else []:
        if isinstance(item, dict) and item.get("context") in REQUIRED_CONTEXTS:
            found[item["context"]] = str(item.get("state", ""))
    return found


def sentinel_issues(state, repo) -> list[dict]:
    """Le issue aperte di sentinel, paginate (decisione 16): `{owner}/{repo}` lo risolve `gh`."""
    return github.open_sentinel_issues(state, repo, "{owner}/{repo}")
