"""Git per hook e CLI (spec 3.2): diff dalla base, file, impronte. Sola lettura, tranne `fetch_ref`."""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
GIT_TIMEOUT_S = 10
FETCH_TIMEOUT_S = 120
_HEAD_BYTES = 8000  # byte letti per riconoscere un file binario (come per i blob)
_BLOCK = 1 << 16  # blocco di lettura per contare le righe


class GitError(Exception):
    pass


@dataclass(frozen=True)
class Change:
    status: str
    path: str
    old_path: str | None
    added: int
    removed: int
    binary: bool


def _check_ref(ref: str) -> None:
    """Un riferimento che comincia con `-` sarebbe un'opzione di git: rifiutato prima di lanciare
    alcun processo."""
    if ref.startswith("-"):
        raise GitError(f"riferimento non valido: {ref!r}")


def _proc(repo, args, input_=None, timeout=GIT_TIMEOUT_S, extra_env=None):
    # Sola lettura (I1): nessun lock opzionale. Niente comandi dal repo (M2): nessun fsmonitor.
    cmd = ["git", "-c", "core.fsmonitor=false", "--no-optional-locks", "-C", str(repo), *args]
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", **(extra_env or {})}
    try:
        return subprocess.run(cmd, capture_output=True, input=input_, env=env, timeout=timeout)
    except FileNotFoundError as e:
        raise GitError("git non disponibile") from e
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git {' '.join(args)}: timeout dopo {timeout} s") from e


def run(repo, *args, check=True, env=None) -> str:
    r = _proc(repo, args, extra_env=env)
    if check and r.returncode != 0:
        raise GitError(f"git {' '.join(args)}: "
                       f"{r.stderr.decode('utf-8', 'replace').strip()}")
    return r.stdout.decode("utf-8", "surrogateescape")


def ok(repo, *args) -> bool:
    try:
        return _proc(repo, args).returncode == 0
    except GitError:
        return False


def _resolved(path) -> Path:
    """Percorso assoluto con i collegamenti risolti; la coda che non esiste ancora resta lessicale."""
    p = Path(os.path.abspath(path))
    tail = []
    while not p.exists() and p.parent != p:
        tail.insert(0, p.name)
        p = p.parent
    return p.resolve().joinpath(*tail)


def toplevel(path) -> Path | None:
    """Radice del repo di `path`. Dentro una cartella `.git` (anche se non esiste) vale il repo che la
    possiede; altrimenti la prima cartella esistente risalendo dal percorso. Un `.git` file
    (worktree collegato) da' il worktree."""
    p = _resolved(path)
    if ".git" in p.parts:
        last = len(p.parts) - 1 - p.parts[::-1].index(".git")
        p = Path(*p.parts[:last])
    while not p.is_dir():
        if p.parent == p:
            return None
        p = p.parent
    try:
        out = run(p, "rev-parse", "--show-toplevel", check=False).strip()
    except GitError:
        return None
    return Path(out).resolve() if out else None


def head(repo) -> str | None:
    out = run(repo, "rev-parse", "--verify", "-q", "HEAD", check=False).strip()
    return out or None


def branch(repo) -> str | None:
    out = run(repo, "symbolic-ref", "--short", "-q", "HEAD", check=False).strip()
    return out or None


def common_dir(repo) -> Path:
    out = run(repo, "rev-parse", "--git-common-dir").strip()
    p = Path(out)
    return (p if p.is_absolute() else Path(repo) / p).resolve()


def worktrees(repo) -> list[tuple[Path, str | None]]:
    out, path, br = [], None, None
    for line in run(repo, "worktree", "list", "--porcelain").splitlines() + [""]:
        if line.startswith("worktree "):
            path, br = Path(line[9:]).resolve(), None
        elif line.startswith("branch "):
            br = line[7:].removeprefix("refs/heads/")
        elif not line and path is not None:
            out.append((path, br))
            path = None
    return out


def main_worktree(repo) -> Path:
    return worktrees(repo)[0][0]


def local_branches(repo) -> set[str]:
    return {b for b in run(repo, "for-each-ref", "--format=%(refname:short)",
                           "refs/heads").splitlines() if b}


def resolve_ref(repo, ref: str) -> str | None:
    _check_ref(ref)
    out = run(repo, "rev-parse", "--verify", "-q", f"{ref}^{{commit}}", check=False).strip()
    return out or None


def default_branch(repo) -> str | None:
    b = run(repo, "config", "--get", "tollgate.defaultBranch", check=False).strip()
    if b:
        return b
    sym = run(repo, "symbolic-ref", "-q", "refs/remotes/origin/HEAD", check=False).strip()
    if sym:
        return sym.removeprefix("refs/remotes/origin/")
    for b in ("main", "master"):
        if resolve_ref(repo, f"origin/{b}"):
            return b
    return None


def default_ref(repo) -> str | None:
    """Ordine di 7.1: tollgate.defaultBranch, origin/HEAD, origin/main, origin/master."""
    b = run(repo, "config", "--get", "tollgate.defaultBranch", check=False).strip()
    for ref in ([f"origin/{b}"] if b else []) + ["origin/HEAD", "origin/main", "origin/master"]:
        if resolve_ref(repo, ref):
            return ref
    return None


def origin_url(repo) -> str | None:
    out = run(repo, "remote", "get-url", "origin", check=False).strip()
    return out or None


def _parse_z(numstat: str, status: str) -> list[Change]:
    st_tokens = status.split("\0")
    statuses: dict[str, tuple[str, str | None]] = {}
    i = 0
    while i < len(st_tokens) and st_tokens[i]:
        code = st_tokens[i]
        if code[0] in "RC":
            statuses[st_tokens[i + 2]] = ("R", st_tokens[i + 1])
            i += 3
        else:
            statuses[st_tokens[i + 1]] = (code[0], None)
            i += 2
    out = []
    ns = numstat.split("\0")
    i = 0
    while i < len(ns) and ns[i]:
        added, removed, path = ns[i].split("\t", 2)
        if path == "":
            path = ns[i + 2]
            i += 3
        else:
            i += 1
        binary = added == "-"
        st, old = statuses.get(path, ("M", None))
        out.append(Change("M" if st == "T" else st, path, old,
                          0 if binary else int(added), 0 if binary else int(removed), binary))
    return out


def _scan(path: Path) -> tuple[bool, int]:
    """(binario, righe) senza caricare il file in memoria: NUL nei primi 8000 byte, righe a blocchi."""
    with open(path, "rb") as f:
        head = f.read(_HEAD_BYTES)
        if b"\0" in head:
            return True, 0
        lines, last = head.count(b"\n"), head[-1:]
        while chunk := f.read(_BLOCK):
            lines += chunk.count(b"\n")
            last = chunk[-1:]
    if last and last != b"\n":
        lines += 1
    return False, lines


def _untracked(repo, exclude=()) -> list[Change]:
    out = []
    for rel in run(repo, "ls-files", "--others", "--exclude-standard", "-z").split("\0"):
        if not rel or excluded(rel, exclude):
            continue
        try:
            binary, lines = _scan(Path(repo) / rel)
        except OSError:
            continue
        out.append(Change("A", rel, None, lines, 0, binary))
    return out


@contextmanager
def _private_index(repo):
    """Copia temporanea dell'indice per i diff col working tree: `git diff` riscrive l'indice col refresh
    anche con GIT_OPTIONAL_LOCKS=0 (I1). Il vero `.git/index` non si tocca mai."""
    src = Path(run(repo, "rev-parse", "--path-format=absolute", "--git-path", "index").strip())
    with tempfile.TemporaryDirectory(prefix="tollgate-index-") as tmp:
        dst = Path(tmp) / "index"
        if src.is_file():
            shutil.copyfile(src, dst)
        yield {"GIT_INDEX_FILE": str(dst)}


def _pathspecs(exclude) -> list[str]:
    """Pathspec che tolgono dal diff le cartelle `exclude` (nomi letterali, dalla radice)."""
    return [f":(top,literal,exclude){e.rstrip('/')}" for e in exclude]


def changes(repo, base: str, *, head: str | None = None, exclude=()) -> list[Change]:
    """Differenze dalla base. `exclude`: cartelle o file (output_dirs) da lasciar fuori."""
    _check_ref(base)
    if head is not None:
        _check_ref(head)
    refs = [base] if head is None else [base, head]
    specs = _pathspecs(exclude)
    with nullcontext({}) if head is not None else _private_index(repo) as env:
        numstat = run(repo, "diff", "-M", "--no-ext-diff", "--no-textconv", "--numstat", "-z",
                      *refs, "--", *specs, env=env)
        status = run(repo, "diff", "-M", "--no-ext-diff", "--no-textconv", "--name-status", "-z",
                     *refs, "--", *specs, env=env)
    out = _parse_z(numstat, status)
    if head is None:
        out += _untracked(repo, exclude)
    return out


def range_base(repo, first_commit: str) -> str:
    """La base di un intervallo che comincia da `first_commit`: il suo genitore, o l'albero
    vuoto se è un commit radice."""
    return resolve_ref(repo, f"{first_commit}^") or EMPTY_TREE


def commit_changes(repo, sha: str) -> list[Change]:
    return changes(repo, range_base(repo, sha), head=sha)


def diff_size(repo, base: str, *, head: str | None = None, exclude=()) -> int:
    _check_ref(base)
    if head is not None:
        _check_ref(head)
    refs = [base] if head is None else [base, head]
    with nullcontext({}) if head is not None else _private_index(repo) as env:
        size = len(run(repo, "diff", "--no-color", "--no-ext-diff", "--no-textconv", *refs,
                       "--", *_pathspecs(exclude), env=env).encode("utf-8", "surrogateescape"))
    if head is None:
        for rel in run(repo, "ls-files", "--others", "--exclude-standard", "-z").split("\0"):
            if rel and not excluded(rel, exclude):
                try:
                    size += (Path(repo) / rel).stat().st_size
                except OSError:
                    pass
    return size


def show(repo, ref: str, path: str) -> bytes | None:
    _check_ref(ref)
    r = _proc(repo, ["show", f"{ref}:{path}"])
    return r.stdout if r.returncode == 0 else None


def _text(data: bytes | None) -> str | None:
    """Testo di un blob: None se binario o assente. Se non è UTF-8 si ripiega su Latin-1 (mai un crash)."""
    if data is None or b"\0" in data[:8000]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def text_at(repo, ref: str, path: str) -> str | None:
    return _text(show(repo, ref, path))


def blob_text(repo, sha: str) -> str | None:
    """Testo di un blob dal suo SHA; None se manca dal database degli oggetti o è binario."""
    _check_ref(sha)
    r = _proc(repo, ["cat-file", "blob", sha])
    return _text(r.stdout) if r.returncode == 0 else None


def worktree_text(repo, path: str) -> str | None:
    try:
        return _text((Path(repo) / path).read_bytes())
    except OSError:
        return None


def ls_files_at(repo, ref: str, prefix: str) -> list[str]:
    """I file sotto `prefix` nell'albero di `ref`, ricorsivi; `[]` se il riferimento non c'è.
    Divide su NUL: i nomi non vengono citati né spezzati da spazi o accenti."""
    _check_ref(ref)
    r = _proc(repo, ["ls-tree", "-r", "-z", "--name-only", ref, "--", prefix])
    if r.returncode != 0:
        return []
    return [p for p in r.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


def blob_at(repo, ref: str, path: str) -> str | None:
    """SHA del blob di `path` nell'albero di `ref`; `None` se manca, se è una cartella o se manca
    il riferimento."""
    _check_ref(ref)
    r = _proc(repo, ["ls-tree", "-z", ref, "--", path])
    if r.returncode != 0:
        return None
    for entry in r.stdout.decode("utf-8", "surrogateescape").split("\0"):
        meta, _, name = entry.partition("\t")
        parts = meta.split()
        if name == path and len(parts) == 3 and parts[1] == "blob":
            return parts[2]
    return None


def exists_at(repo, ref: str, path: str) -> bool:
    _check_ref(ref)
    return ok(repo, "cat-file", "-e", f"{ref}:{path}")


def object_in_history(repo, obj: str, ref: str) -> bool:
    """`obj` (un blob) compare nella storia di `ref`: un commit che lo aggiunge o lo toglie.
    Un oggetto presente nel database ma mai committato lungo `ref` non conta."""
    _check_ref(obj)
    _check_ref(ref)
    r = _proc(repo, ["log", "-n", "1", "--format=%H", f"--find-object={obj}", ref, "--"],
              timeout=30)
    return r.returncode == 0 and bool(r.stdout.strip())


def blob_sha(repo, path: str) -> str:
    return run(repo, "hash-object", "--", path).strip()


def rev_list(repo, base: str, head: str) -> list[str]:
    _check_ref(base)
    _check_ref(head)
    return [s for s in run(repo, "rev-list", "--reverse", f"{base}..{head}").split() if s]


def excluded(rel: str, exclude) -> bool:
    return any(rel == e.rstrip("/") or rel.startswith(e.rstrip("/") + "/") for e in exclude)


CACHE_DIRS = ("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache")


def fingerprint(repo, exclude) -> str:
    """Impronta dei file tracciati e non tracciati non ignorati (7.3), esclusi output_dirs e le
    cartelle di cache a qualunque profondità (decisione 22)."""
    h = hashlib.sha256()
    files = run(repo, "ls-files", "-co", "--exclude-standard", "-z").split("\0")
    for rel in sorted({f for f in files if f}):
        if excluded(rel, exclude) or any(seg in CACHE_DIRS for seg in rel.split("/")):
            continue
        try:
            digest = hashlib.sha1((Path(repo) / rel).read_bytes()).hexdigest()
        except FileNotFoundError:
            digest = "cancellato"
        except IsADirectoryError:
            digest = "cartella"
        except OSError:
            digest = "illeggibile"
        h.update(f"{rel}\0{digest}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()


def is_clean(repo, exclude) -> bool:
    out = run(repo, "status", "--porcelain", "-z", "--untracked-files=all")
    entries = [e for e in out.split("\0") if e]
    paths, skip = [], False
    for e in entries:
        if skip:
            skip = False
            continue
        code, rel = e[:2], e[3:]
        paths.append(rel)
        if code[0] in "RC":
            skip = True
    return all(excluded(p, exclude) for p in paths)


def patch_id(repo, base: str, head: str) -> str | None:
    """Identità del contenuto di `base..head` (`git patch-id --stable`): non cambia con un
    rebase senza conflitti su una base avanzata. `None` con il diff vuoto. Niente driver di
    diff né textconv del repo (M2)."""
    _check_ref(base)
    _check_ref(head)
    diff = _proc(repo, ["diff", "--binary", "--no-ext-diff", "--no-textconv", base, head],
                 timeout=30)
    if diff.returncode != 0:
        raise GitError(f"git diff {base} {head}: {diff.stderr.decode('utf-8', 'replace').strip()}")
    if not diff.stdout.strip():
        return None
    out = _proc(repo, ["patch-id", "--stable"], input_=diff.stdout, timeout=30)
    if out.returncode != 0:
        raise GitError(f"git patch-id: {out.stderr.decode('utf-8', 'replace').strip()}")
    first = out.stdout.decode("ascii", "replace").split()
    return first[0] if first else None


def fetch_ref(repo, ref: str, *, token: str | None = None) -> None:
    """`git fetch origin <ref>` (nel gate: `refs/pull/<n>/head`, che un checkout con
    `persist-credentials: false` non può leggere su un repo privato). Il token, se c'è, passa
    come intestazione HTTP nelle variabili d'ambiente del processo figlio: mai negli argomenti né
    in `.git/config`."""
    _check_ref(ref)
    env = {"GIT_TERMINAL_PROMPT": "0"}     # senza credenziali non si attende mai un prompt
    if token:
        auth = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
        env |= {"GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {auth}"}
    r = _proc(repo, ["fetch", "--no-tags", "origin", ref], timeout=FETCH_TIMEOUT_S,
              extra_env=env)
    if r.returncode != 0:
        raise GitError(f"git fetch origin {ref}: {r.stderr.decode('utf-8', 'replace').strip()}")
