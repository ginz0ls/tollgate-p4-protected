"""PreToolUse Bash (spec 7.4, ambito 6.6). Best effort: il resto lo prende PostToolUse Bash.

I bersagli di scrittura seguono la logica di `writes.py`: la protezione si valuta su ogni
radice pertinente, una sessione legata non scrive nel worktree di un altro lavoro, se i
worktree non si possono elencare si nega con un messaggio, i percorsi fuori dai repo passano."""
from __future__ import annotations

import glob
import itertools
import os
import re
from pathlib import Path

from tollgate_analysis import bash
from tollgate_analysis.protected import REPO_PROTECTED
from tollgate_core import git
from tollgate_hooks.model import deny

from ._common import (_inside, governing_work, in_main_checkout, is_docs_md, is_protected_path,
                      orphan_next, orphan_tg, output_excludes, path_forms, repo_key_of)

CHECK = {"api": 1, "events": ["pre_bash"], "component": None, "order": 20}
_SUBST = "_TG_SUBST_"
# `TOLLGATE_X=1; cmd`: l'assegnazione da sola non lascia traccia nei comandi letti.
_TOLLGATE_ASSIGN = re.compile(r"(?:^|[\s;&|(])TOLLGATE_\w*=")


# Un percorso concreto per ogni pattern protetto: serve a vedere se una cartella ne contiene.
_PROBES = [pat.replace("**", "x").replace("*", "x").lstrip("/") for pat in REPO_PROTECTED]


def _abs(c: bash.Cmd, target: str) -> Path | None:
    """Percorso assoluto e normalizzato di un bersaglio, con i collegamenti NON risolti: la
    protezione per nome li valuta tutti (`path_forms`). None per il segnaposto delle
    sostituzioni."""
    if _SUBST in target:
        return None
    return Path(os.path.normpath(os.path.join(c.cwd, os.path.expanduser(target))))


_GLOB_CHARS = "*?["
_GLOB_CAP = 5000
_BRACE_CAP = 1000


def _braces(t: str) -> list[str]:
    """`{a,b}` -> due bersagli (annidate comprese). Senza virgola o sbilanciate restano come sono."""
    i = t.find("{")
    while i >= 0:
        depth, parts, start, end = 0, [], i + 1, -1
        for j in range(i, len(t)):
            ch = t[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    parts.append(t[start:j])
                    end = j
                    break
            elif ch == "," and depth == 1:
                parts.append(t[start:j])
                start = j + 1
        if end < 0:
            return [t]
        if len(parts) > 1:
            out = [x for part in parts for x in _braces(t[:i] + part + t[end + 1:])]
            return out[:_BRACE_CAP]
        i = t.find("{", i + 1)
    return [t]


def _expand(c: bash.Cmd, raw: str) -> tuple[list[Path], list[Path]]:
    """Percorsi che un bersaglio può toccare: il testo stesso, le graffe e i glob espansi (anche
    i file nascosti). In più la cartella che precede il primo carattere glob: serve quando il
    glob non trova nulla o i file nascono dopo."""
    paths, ancestors = [], []
    for t in _braces(raw):
        p = _abs(c, t)
        if p is None:
            continue
        paths.append(p)
        if not any(ch in t for ch in _GLOB_CHARS):
            continue
        pattern = os.path.join(glob.escape(c.cwd), os.path.expanduser(t))
        found = glob.iglob(pattern, recursive=True, include_hidden=True)
        paths += [Path(os.path.normpath(m)) for m in itertools.islice(found, _GLOB_CAP)]
        first = min(i for i, ch in enumerate(t) if ch in _GLOB_CHARS)
        ancestors.append(_abs(c, t[:first][:t[:first].rfind("/") + 1] or "."))
    return paths, ancestors


def _write_paths(c: bash.Cmd, edir: Path, repo: Path | None) -> list[tuple[str, Path]]:
    """Ciò che il comando scrive: redirect e comandi di file, e il file di `git config`."""
    out = [(t, p) for t in bash.write_targets(c) for p in _expand(c, t)[0]]
    cfg = bash.git_config_write(c)
    if cfg == "local" and repo is not None:
        try:
            out.append(("git config", git.common_dir(repo) / "config"))
        except git.GitError:
            out.append(("git config", repo / ".git" / "config"))
    elif cfg and cfg != "local" and (p := _abs(c, cfg)) is not None:
        out.append((cfg, p))
    return out


def _removes_protected(ctx, p: Path) -> bool:
    """`p` (tolto con rm, rmdir, mv...) è, o contiene, un file protetto o la radice del lavoro,
    in una qualunque delle sue forme (collegamenti compresi)."""
    return any(_removes_protected_form(ctx, f, git.toplevel(f), governing_work(ctx, f))
               for f in path_forms(p))


def _removes_protected_form(ctx, p: Path, repo: Path | None, work) -> bool:
    if is_protected_path(ctx, p, repo, work):
        return True
    wt = Path(work["worktree"]).resolve() if work is not None and work["worktree"] else None
    roots = [r for r in (wt, Path(ctx.repo).resolve() if ctx.repo is not None else None) if r]
    if any(_inside(r, p) for r in roots):
        return True
    if repo is not None:
        roots.append(Path(repo).resolve())
    return any(_inside(r / probe, p) for r in roots for probe in _PROBES) or any(
        _inside(ar, p) for r in roots + [None] for ar in ctx.protected_roots(r))


def _active_branches(ctx, repo) -> dict[str, object]:
    key = repo_key_of(repo)
    return {r["branch"]: r for r in ctx.db.execute(
        "SELECT * FROM work_items WHERE repo_key = ? AND phase <> 'closed' "
        "AND branch IS NOT NULL", (key,))}


def _repo_is_active(ctx, repo: Path) -> bool:
    """Repo del contesto, o con `tollgate.toml` sul riferimento predefinito (7.1)."""
    try:
        if ctx.repo is not None and git.common_dir(repo) == git.common_dir(ctx.repo):
            return True
        ref = git.default_ref(repo)
        return bool(ref) and git.exists_at(repo, ref, "tollgate.toml")
    except git.GitError:
        return False


def _forbidden(c: bash.Cmd, raw: str) -> tuple[str, str] | None:
    text = " ".join(c.argv + c.redirects + [f"{k}={v}" for k, v in c.env.items()])
    if bash.is_claude(c):
        return "forbidden", ("claude e i suoi alias sono negati: una sessione nuova sfuggirebbe "
                             "ai guardrail")
    if "TOLLGATE_" in text or _TOLLGATE_ASSIGN.search(raw):
        return "forbidden", "le variabili TOLLGATE_ sono negate nei comandi (3.1)"
    if bash.is_tollgate_hook(c):
        return "forbidden", "tollgate hook lo lancia solo hooks/run"
    if bash.hooks_path_override(c):
        return "forbidden", ("core.hooksPath è negato: aggira .git/hooks, che è protetto, "
                             "come --no-verify (7.4)")
    d = bash.destructive(c)
    if d:
        return "destructive", f"{d} è negato (7.4)"
    return None


def _rm_rf(ctx, c: bash.Cmd, repo: Path | None, work) -> tuple[str, str] | None:
    roots = []
    for r in (repo, ctx.repo, Path(work["worktree"]) if work is not None and work["worktree"]
              else None):
        r = Path(r).resolve() if r is not None else None
        if r is not None and r not in roots:
            roots.append(r)
    for t in bash.rm_rf_targets(c):
        p = Path(t).resolve()
        if not any(_inside(p, r) for r in roots):
            return "destructive", (f"rm -rf fuori dal repo e dal worktree: {t}; usa un percorso dentro il "
                                    "worktree, oppure chiedi all'utente di eseguirlo")
        if p in roots:
            return "destructive", f"rm -rf della radice del repo o del worktree: {t}"
    return None


def _repo_rules(ctx, c: bash.Cmd, edir: Path, repo: Path) -> tuple[str, str] | None:
    sub, args, _ = bash.git_call(c)
    default = git.default_branch(repo)
    works = _active_branches(ctx, repo)
    if bash.is_push(c):
        if bash.push_is_force(c):
            return "push", "push forzato negato: lo fanno solo open-pr e sync (6.5)"
        current = git.branch(edir)
        targets = [current if t == "HEAD" and current else t for t in bash.push_targets(c)]
        if not targets and current:
            targets = [current]
        if default and (default in targets or "--all" in args):
            return "push", (f"push verso {default} negato: l'hotfix passa da un ramo e da una "
                            f"PR (9.4)")
    if default and git.branch(edir) == default and any(
            a.removeprefix("origin/").startswith("tg/") or a in works
            for a in bash.merge_args(c)):
        return "merge", f"merge di un ramo tg/* verso {default} negato"
    if any(b in works for b in bash.branch_deletes(c)):
        return "branch", "cancellazione del ramo di un lavoro attivo negata"
    op = bash.worktree_op(c)
    if op:
        existing = git.worktrees(repo)
        if op[0] == "remove" and any(Path(op[1]).resolve() == Path(w["worktree"]).resolve()
                                     for w in works.values() if w["worktree"]):
            return "worktree", "rimozione del worktree di un lavoro attivo negata"
        if op[0] == "add" and (any(Path(op[1]).resolve() == p for p, _ in existing)
                               or (op[2] and any(op[2] == b for _, b in existing))):
            return "worktree", "git worktree add doppio negato"
    return None


def _work_rules(ctx, event, c: bash.Cmd, edir: Path, work,
                paths: list[tuple[str, Path]]) -> tuple[str, str] | None:
    if bash.is_push(c):
        return "push", "il push del ramo lo fa /tollgate:finish (open-pr), non Bash (6.6)"
    if bash.is_gh_pr_create(c):
        return "push", "la PR la apre /tollgate:finish (open-pr), non gh pr create (6.6)"
    if not work["worktree"]:
        return None
    wt = Path(work["worktree"]).resolve()
    in_wt = _inside(edir, wt)
    if in_wt:
        bc = bash.branch_change(c)
        if bc:
            return "branch", f"{bc} nel worktree negato: il ramo del lavoro non cambia (6.6)"
        args = bash.checkout_args(c)
        if args:
            branches = git.local_branches(wt)
            if any(a in branches or a == "-" for a in args):
                return "branch", "git checkout di un altro ramo nel worktree negato (6.6)"
    elif bash.git_mutating(c) and in_main_checkout(edir, wt):
        return "main_checkout", (f"comandi che scrivono nel checkout principale negati durante "
                                 f"il lavoro #{work['issue']}: si lavora in {wt} (6.6)")
    for raw, p in paths:
        rel = ctx.rel(p, wt)
        if rel is None:
            if in_main_checkout(p, wt):
                return "main_checkout", (f"scrittura nel checkout principale negata durante il "
                                         f"lavoro #{work['issue']}: {raw} (6.6)")
            continue
        if (event.agent_id is None and work["level"] in ("L1", "L2") and not is_docs_md(rel)
                and not bash.restores_from_index(c)
                and not rel.startswith(".superpowers/")
                and not git.excluded(rel, output_excludes(ctx))):
            return "coordinator", (f"in {work['level']} il codice lo scrivono gli "
                                   f"implementatori, anche con redirect o sed -i: {raw}")
    return None


def _orphan_rule(ctx, c: bash.Cmd, repo: Path | None,
                 paths: list[tuple[str, Path]]) -> tuple[str, str] | None:
    """Ramo tg/N-* senza lavoro nel DB (12.4): scritture negate tranne i .md di docs/superpowers."""
    hit, where = (orphan_tg(ctx, repo), repo) if bash.git_mutating(c) else (None, None)
    if hit is None:
        for _, p in paths:
            r = git.toplevel(p)
            n = orphan_tg(ctx, r)
            if n is not None and not is_docs_md(ctx.rel(p, r)):
                hit, where = n, r
                break
    if hit is None:
        return None
    why, command = orphan_next(ctx, where, hit)
    return "adopt", (f"ramo tg/{hit}-* {why}: comandi che scrivono negati, tranne "
                     f"i .md sotto docs/superpowers/. L'utente deve lanciare {command} "
                     f"(12.4)")


def _check(event, ctx, c: bash.Cmd, raw: str) -> tuple[str, str] | None:
    hit = _forbidden(c, raw)
    if hit:
        return hit
    edir = Path(bash.effective_dir(c)).resolve()
    repo = git.toplevel(edir)
    work = governing_work(ctx, edir)
    paths = _write_paths(c, edir, repo)
    for raw_target, p in paths:
        if is_protected_path(ctx, p, git.toplevel(p), governing_work(ctx, p)):
            return "protected", (f"{raw_target}: {p} è un file protetto: lo scrivono solo la CLI "
                                 f"e gli hook di tollgate (7.4)")
    paths = [(r, p.resolve()) for r, p in paths]
    for raw_target in bash.removal_targets(c):
        found, ancestors = _expand(c, raw_target)
        candidates = found + (ancestors if bash.removal_recursive(c) else [])
        if any(_removes_protected(ctx, p) for p in candidates):
            return "protected", (f"{raw_target} è, o contiene, un file protetto o la radice del "
                                 f"lavoro: lo tolgono solo la CLI e gli hook di tollgate (7.4)")
    if ctx.bound and ctx.work is not None:
        touched = [p for _, p in paths] + ([edir] if bash.git_mutating(c) else [])
        for p in touched:
            other = ctx.work_for_path(p)
            if other is not None and other["id"] != ctx.work["id"]:
                return "other_work", (f"{p} sta nel worktree del lavoro #{other['issue']}, ma "
                                      f"questa sessione è legata al lavoro #{ctx.work['issue']}: "
                                      f"le regole valgono in qualunque directory (6.6)")
    hit = _rm_rf(ctx, c, repo, work)
    if hit:
        return hit
    if repo is not None and _repo_is_active(ctx, repo):
        hit = _repo_rules(ctx, c, edir, repo)
        if hit:
            return hit
    if work is not None:
        return _work_rules(ctx, event, c, edir, work, paths)
    return _orphan_rule(ctx, c, repo, paths) if bash.writes(c) else None


def decide(event, ctx):
    command = str(event.tool_input.get("command") or "")
    try:
        cmds = bash.parse(command, str(event.cwd))
    except bash.BashParseError:
        label = bash.text_danger(command)
        if label:
            return [deny(f"comando non leggibile che contiene «{label}»: riscrivilo in forma "
                         f"semplice", rule="unparsable")]
        return []
    for c in cmds:
        if not c.argv and not c.redirects:
            continue
        try:
            hit = _check(event, ctx, c, command)
        except git.GitError as e:
            hit = ("worktrees", f"non è stato possibile verificare i worktree ({e}): comando "
                                f"negato per prudenza (6.6)")
        if hit:
            return [deny(hit[1], rule=hit[0])]
    return []
