"""Git in scrittura per il flusso (spec 6.1). La lettura sta in `tollgate_core.git`."""
from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path

from tollgate_core import git

FETCH_TIMEOUT_S = 120
LS_REMOTE_TIMEOUT_S = 60
WRITE_TIMEOUT_S = 60
PUSH_TIMEOUT_S = 120


class GitWriteError(Exception):
    pass


def _run(repo, *args, timeout=WRITE_TIMEOUT_S) -> subprocess.CompletedProcess:
    cmd = ["git", "-c", "core.fsmonitor=false", "-C", str(repo), *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL,
                              env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except FileNotFoundError as e:
        raise GitWriteError("git non disponibile") from e
    except subprocess.TimeoutExpired as e:
        raise GitWriteError(f"git {' '.join(args)}: timeout dopo {timeout} s") from e


def _checked(repo, *args, timeout=WRITE_TIMEOUT_S) -> str:
    r = _run(repo, *args, timeout=timeout)
    if r.returncode != 0:
        raise GitWriteError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def fetch(repo) -> bool:
    """`git fetch origin`. Falso senza rete (o per qualunque errore): mai un'eccezione."""
    try:
        return _run(repo, "fetch", "origin", timeout=FETCH_TIMEOUT_S).returncode == 0
    except GitWriteError:
        return False


def worktree_add(repo, path, *, branch: str, start_point: str | None, new_branch: bool,
                 force: bool = False) -> None:
    """Nuovo ramo da `start_point` (senza ramo a monte, C18) o ramo esistente. `force` solo per
    un percorso già registrato ma sparito (crash): non tocca le registrazioni degli altri."""
    extra = ["--force"] if force else []
    if new_branch:
        if not start_point:
            raise GitWriteError("serve il punto di partenza per un ramo nuovo")
        _checked(repo, "worktree", "add", *extra, "--no-track", "-b", branch, str(path),
                 start_point)
    else:
        _checked(repo, "worktree", "add", *extra, str(path), branch)


def worktree_remove(repo, path) -> None:
    """`git worktree remove <percorso>`, mai con `--force`: un worktree con modifiche o file
    nuovi non si toglie e git rifiuta (`GitWriteError`)."""
    _checked(repo, "worktree", "remove", str(path))


def rebase_in_progress(wt) -> bool:
    """Un rebase interrotto (`sync`) lascia `rebase-merge` o `rebase-apply` nella cartella git
    privata del worktree."""
    gitdir = Path(git.run(wt, "rev-parse", "--absolute-git-dir").strip())
    return (gitdir / "rebase-merge").exists() or (gitdir / "rebase-apply").exists()


def is_dirty(wt, exclude=()) -> bool:
    """Modifiche non committate (o file nuovi) fuori da `exclude`."""
    return not git.is_clean(wt, exclude)


def create_branch(repo, branch: str, sha: str) -> bool:
    """Crea `branch` a `sha` in modo atomico: il vecchio valore vuoto di `update-ref` vuol dire
    «il ref non deve esistere». Falso se esiste già (di un altro: non si tocca) o se git fallisce.
    Non imposta un ramo a monte."""
    try:
        return _run(repo, "update-ref", f"refs/heads/{branch}", sha, "").returncode == 0
    except GitWriteError:
        return False


def delete_branch(repo, branch: str, expected_sha: str) -> bool:
    """Toglie `branch` solo se punta ancora a `expected_sha` (atomico: `update-ref -d` con il
    vecchio valore fallisce se il ramo punta altrove). Mai `branch -D`. Vero se tolto."""
    try:
        return _run(repo, "update-ref", "-d", f"refs/heads/{branch}",
                    expected_sha).returncode == 0
    except GitWriteError:
        return False


def add_excludes(repo, lines: list[str]) -> None:
    """Righe nuove in `info/exclude` della cartella comune, senza duplicati."""
    target = git.common_dir(repo) / "info" / "exclude"
    try:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        have = set(current.splitlines())
        new = [ln for ln in dict.fromkeys(lines) if ln not in have]
        if not new:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        prefix = "" if not current or current.endswith("\n") else "\n"
        target.write_text(current + prefix + "\n".join(new) + "\n", encoding="utf-8")
    except OSError as e:
        raise GitWriteError(f"info/exclude: {e.strerror}") from e


def set_config(repo, key: str, value: str) -> None:
    _checked(repo, "config", key, value)


def remote_branches(repo, pattern: str) -> list[str]:
    """Rami di `origin` che combaciano con il glob (`tg/7-*`). Vuoto senza rete."""
    try:
        r = _run(repo, "ls-remote", "--heads", "origin", timeout=LS_REMOTE_TIMEOUT_S)
    except GitWriteError:
        return []
    if r.returncode != 0:
        return []
    names = []
    for line in r.stdout.splitlines():
        _, _, ref = line.partition("\t")
        if ref.startswith("refs/heads/"):
            names.append(ref.removeprefix("refs/heads/"))
    return sorted(n for n in names if fnmatch.fnmatchcase(n, pattern))


def push_sha(repo, sha: str, branch: str, *, lease: str | None) -> None:
    """Spinge esattamente `sha` su `refs/heads/<branch>` di origin. Con `lease` il push è forzato
    solo se il ramo remoto punta ancora a `lease` (`--force-with-lease`); senza, un ramo remoto
    che non è antenato di `sha` fa fallire il push."""
    args = ["push"]
    if lease:
        args.append(f"--force-with-lease=refs/heads/{branch}:{lease}")
    _checked(repo, *args, "origin", f"{sha}:refs/heads/{branch}", timeout=PUSH_TIMEOUT_S)


def remote_sha(repo, branch: str) -> str | None:
    """Lo SHA di `refs/heads/<branch>` su origin, `None` se il ramo non esiste. Un errore
    (senza rete) è un `GitWriteError`, mai «non esiste»."""
    out = _checked(repo, "ls-remote", "--heads", "origin", f"refs/heads/{branch}",
                   timeout=LS_REMOTE_TIMEOUT_S)
    for line in out.splitlines():
        sha, _, ref = line.partition("\t")
        if ref == f"refs/heads/{branch}" and sha:
            return sha
    return None


def is_ancestor(repo, a: str, b: str) -> bool:
    """`a` è antenato di `b` (o uguale). Falso anche se `a` non è nel repo locale."""
    return _run(repo, "merge-base", "--is-ancestor", a, b).returncode == 0


def merge_ff_only(wt, ref: str) -> bool:
    """`git merge --ff-only <ref>`: vero se HEAD avanza (o è già lì), falso se non è un
    avanzamento rapido o git fallisce."""
    return _run(wt, "merge", "--ff-only", ref).returncode == 0


def rebase(wt, onto: str) -> bool:
    """`git rebase <onto>`. Falso con un conflitto, e il rebase resta in corso nel worktree
    (lo annulla `rebase_abort`). Un guasto senza rebase in corso (per esempio modifiche non
    committate) è un `GitWriteError`."""
    r = _run(wt, "rebase", onto)
    if r.returncode == 0:
        return True
    if rebase_in_progress(wt):
        return False
    raise GitWriteError(f"git rebase {onto}: {(r.stderr or r.stdout).strip()}")


def rebase_abort(wt) -> None:
    """`git rebase --abort`; nulla se non c'è un rebase in corso."""
    if rebase_in_progress(wt):
        _checked(wt, "rebase", "--abort")


def merge_base(repo, a: str, b: str) -> str | None:
    """Il miglior antenato comune di `a` e `b`; `None` se non c'è o se un riferimento manca."""
    r = _run(repo, "merge-base", a, b)
    out = r.stdout.strip()
    return out if r.returncode == 0 and out else None


def worktree_dir(main: Path, branch: str) -> Path:
    """`<checkout principale>/.claude/worktrees/tg-<N>-<slug>` (decisione 4)."""
    return main / ".claude" / "worktrees" / branch.replace("/", "-")
