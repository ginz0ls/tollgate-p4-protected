"""Lettura dei comandi Bash e classificazione per le regole di 7.4 e gli effetti di 8.5.
Best effort: ciò che sfugge lo prende PostToolUse Bash (spec 7.2)."""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass, field


class BashParseError(ValueError):
    pass


@dataclass
class Cmd:
    argv: list[str]
    cwd: str
    env: dict[str, str] = field(default_factory=dict)
    redirects: list[str] = field(default_factory=list)
    nested: bool = False


_OPS = {";", "&&", "||", "|", "&", "|&", ";;", "(", ")"}
_REDIR_OUT = {">", ">>", ">|", "&>", "&>>"}
_REDIR_SKIP = {"<", "<<<", "<&", ">&", "<>"}
_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "{", "!"}
_WRAPPERS = {"sudo", "nohup", "time", "command", "exec", "nice", "env", "xargs", "timeout",
             "stdbuf", "builtin"}
# Opzioni che prendono un argomento separato, per ciascun wrapper (`sudo -u bob git ...`).
_WRAP_ARGS = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group",
             "--chdir", "--host", "--prompt", "--role", "--type", "--other-user"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-k", "-s", "--kill-after", "--signal"},
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args", "--max-procs",
              "--delimiter", "--arg-file", "--max-lines"},
    "stdbuf": {"-i", "-o", "-e"},
    "time": {"-f", "-o"},
    "exec": {"-a"},
}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# `<<` di heredoc, non `<<<` (here-string).
_HEREDOC_AT = re.compile(r"(?<!<)<<(?!<)-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_SHELL_LINE = re.compile(r"(?:^|[\s;&|(])(?:bash|sh|zsh|dash|ksh)(?=[\s;&|)]|$)")


# Segnaposto per `$(...)` e backtick: niente spazi, così `X=$(cmd)` resta un'assegnazione.
SUBST_TOKEN = "_TG_SUBST_"


def _skip_heredoc_bodies(text: str, start: int, pending: list[tuple[str, bool]],
                         inners: list[str]) -> int:
    """Indice dopo i corpi degli heredoc in attesa, a partire da `start`. Il corpo di un
    heredoc non quotato esegue `$(...)` e i backtick: quelle sostituzioni vanno in `inners`."""
    i = start
    for delim, quoted in pending:
        body_start = i
        while True:
            nl = text.find("\n", i)
            end = nl if nl >= 0 else len(text)
            if text[i:end].strip() == delim:
                body = text[body_start:i]
                i = end + 1
                break
            i = end + 1
            if nl < 0:
                raise BashParseError(f"heredoc senza delimitatore '{delim}'")
        if not quoted:
            _collect_subst(body, inners)
    return i


def _collect_subst(s: str, inners: list[str]) -> None:
    """Sostituzioni eseguite da un testo non quotato (corpo di heredoc)."""
    i = 0
    while i < len(s):
        if s[i] == "\\":
            i += 2
        elif s[i] == "`":
            j = s.find("`", i + 1)
            if j < 0:
                raise BashParseError("backtick non chiuso")
            inners.append(s[i + 1:j])
            i = j + 1
        elif s.startswith("$(", i):
            _, _, end = _scan(s, i + 2, True)
            inners.append(s[i + 2:end - 1])
            i = end
        else:
            i += 1


def _scan(text: str, i: int, nested: bool) -> tuple[str, list[str], int]:
    """Scansione unica del testo di shell, al livello esterno (`nested=False`) o dentro un
    `$(...)` (`nested=True`, si ferma alla `)` che lo chiude e ne ritorna l'indice dopo).
    Ritorna (testo esterno con SEGNAPOSTO al posto delle sostituzioni e senza corpi di
    heredoc, sostituzioni da analizzare a parte, indice finale)."""
    out: list[str] = []
    inners: list[str] = []
    pending: list[tuple[str, bool]] = []
    in_dq = False
    depth = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            out.append(text[i:i + 2])
            i += 2
            continue
        if c == "'" and not in_dq:
            j = text.find("'", i + 1)
            if j < 0:
                raise BashParseError("virgolette non chiuse")
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if c == '"':
            in_dq = not in_dq
            out.append(c)
            i += 1
            continue
        if c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                raise BashParseError("backtick non chiuso")
            inners.append(text[i + 1:j])
            out.append(SUBST_TOKEN)
            i = j + 1
            continue
        if text.startswith("$(", i):
            _, _, end = _scan(text, i + 2, True)
            inners.append(text[i + 2:end - 1])
            out.append(SUBST_TOKEN)
            i = end
            continue
        if not in_dq:
            if nested and c == ")" and depth == 0:
                return "".join(out), inners, i + 1
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
        if c == "<" and not in_dq and not text.startswith("<<<", i):
            m = _HEREDOC_AT.match(text, i)
            if m:
                line_start = text.rfind("\n", 0, i) + 1
                line_end = text.find("\n", i)
                line = text[line_start:line_end if line_end >= 0 else n]
                if _SHELL_LINE.search(line):
                    raise BashParseError("heredoc verso una shell: il corpo non si legge")
                pending.append((m.group(2), m.group(1) != ""))
                out.append(m.group(0))
                i = m.end()
                continue
        if c == "\n":
            out.append("\n")
            i = _skip_heredoc_bodies(text, i + 1, pending, inners) if pending else i + 1
            pending = []
            continue
        out.append(c)
        i += 1
    if nested:
        raise BashParseError("sostituzione $(...) non chiusa")
    if in_dq:
        raise BashParseError("virgolette non chiuse")
    return "".join(out), inners, n


def _norm(cwd: str, path: str) -> str:
    return os.path.normpath(os.path.join(cwd, os.path.expanduser(path)))


def _unwrap(argv: list[str], env: dict) -> list[str]:
    while argv and os.path.basename(argv[0]) in _WRAPPERS:
        name = os.path.basename(argv[0])
        takes = _WRAP_ARGS.get(name, set())
        argv = argv[1:]
        while argv:
            x = argv[0]
            if x == "--":
                argv = argv[1:]
                break
            if _ASSIGN.match(x):
                k, _, v = x.partition("=")
                env[k] = v
                argv = argv[1:]
                continue
            if x.startswith("-") and len(x) > 1:
                argv = argv[1:]
                if x in takes and argv:
                    argv = argv[1:]
                continue
            if name == "timeout" and x.replace(".", "", 1).isdigit():
                argv = argv[1:]
                continue
            break
    return argv


def _shell_command(argv: list[str]) -> str | None:
    """Stringa passata a `-c` di una shell, anche nei flag combinati (`bash -lc`, `sh -ec`).
    None se la shell esegue uno script o legge da stdin."""
    i = 1
    while i < len(argv):
        x = argv[i]
        if x == "--" or not x.startswith(("-", "+")) or x.startswith("--"):
            return None
        if x in ("-o", "+o"):
            i += 2
            continue
        if x.startswith("-") and "c" in x[1:]:
            return argv[i + 1] if i + 1 < len(argv) else None
        i += 1
    return None


_PUNCT_RE = re.compile(r"<<<|<<|<>|&>>|&>|>>|>\||>&|<&|[<>]|&&|\|\||\|&|;;|[;&|()]")


def _ops(tokens):
    """shlex fonde la punteggiatura (`);`, `)&&`, `;>`): la spezza negli operatori e nelle
    redirezioni noti. Ogni redirezione resta un token a sé, seguito dal suo bersaglio."""
    for t in tokens:
        if t and set(t) <= set(";&|()<>"):
            yield from _PUNCT_RE.findall(t)
        else:
            yield t


def parse(command: str, cwd: str) -> list[Cmd]:
    outer, inners, _ = _scan(command.replace("\\\n", " "), 0, False)
    extra: list[Cmd] = []
    for inner in inners:
        for c in parse(inner, cwd):
            c.nested = True
            extra.append(c)
    lex = shlex.shlex(outer.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        tokens = list(_ops(lex))
    except ValueError as e:
        raise BashParseError(str(e)) from e
    out: list[Cmd] = []
    seg: list[str] = []

    def flush():
        nonlocal cwd, seg
        if not seg:
            return
        env: dict[str, str] = {}
        redirects: list[str] = []
        argv: list[str] = []
        i = 0
        while i < len(seg):
            t = seg[i]
            # Descrittore numerato (`2>&1`, `1>x`): shlex lo lascia come parola a sé.
            if t.isdigit() and i + 1 < len(seg) and seg[i + 1][:1] in ("<", ">"):
                i += 1
                continue
            if t in _REDIR_OUT:
                if i + 1 < len(seg):
                    redirects.append(seg[i + 1])
                i += 2
                continue
            if t in _REDIR_SKIP or t == "<<":
                i += 2
                continue
            if not argv and _ASSIGN.match(t):
                k, _, v = t.partition("=")
                env[k] = v
            else:
                argv.append(t)
            i += 1
        while argv and argv[0] in _KEYWORDS:
            argv = argv[1:]
        argv = _unwrap(argv, env)
        seg = []
        if not argv and not redirects:
            return
        cmd = Cmd(argv, cwd, env, redirects)
        out.append(cmd)
        if argv and argv[0] in ("cd", "pushd"):
            cwd = _norm(cwd, argv[1] if len(argv) > 1 else "~")
        elif argv and os.path.basename(argv[0]) in _SHELLS:
            inner = _shell_command(argv)
            if inner is not None:
                for c in parse(inner, cmd.cwd):
                    c.nested = True
                    out.append(c)
        elif argv and (alias_shell := shell_alias_command(cmd)) is not None:
            for c in parse(alias_shell, cmd.cwd):
                c.nested = True
                out.append(c)
        elif argv and argv[0] == "eval" and len(argv) > 1:
            for c in parse(" ".join(argv[1:]), cmd.cwd):
                c.nested = True
                out.append(c)

    for t in tokens:
        if t in _OPS:
            flush()
        else:
            seg.append(t)
    flush()
    return out + extra


# --- git -------------------------------------------------------------------------------------

_GIT_OPT_ARG = {"-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
_GIT_MUTATING = {"add", "commit", "checkout", "switch", "reset", "restore", "rm", "mv", "merge",
                 "rebase", "cherry-pick", "revert", "am", "stash", "apply", "pull", "clean",
                 "tag", "branch", "worktree", "push", "update-ref", "remote", "filter-branch",
                 "symbolic-ref", "submodule", "gc"}
# Git ignora un alias che ha il nome di un comando integrato: non si espande mai.
_GIT_BUILTIN = _GIT_MUTATING | {"status", "log", "diff", "show", "config", "rev-parse",
                                          "ls-files"}
_CONFIG_WRITE = {"--unset", "--unset-all", "--add", "--replace-all", "--rename-section",
                 "--remove-section"}
_CONFIG_READ = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l",
                "--show-origin", "--show-scope", "--name-only"}


# Opzioni lunghe che le regole di 7.4 cercano. Git accetta il prefisso univoco di un'opzione lunga
# (`--no-verif`, `--har`, `--force-w`): da 3 caratteri in su un prefisso vale l'opzione intera.
# Un prefisso ambiguo per git è un errore: negarlo non costa nulla.
_DANGEROUS_LONG = ("force", "force-with-lease", "mirror", "no-verify", "hard")
_MIN_ABBREV = 3


def _canonical_long(arg: str) -> str:
    if not arg.startswith("--"):
        return arg
    name, eq, value = arg[2:].partition("=")
    if len(name) < _MIN_ABBREV:
        return arg
    for opt in _DANGEROUS_LONG:
        if opt.startswith(name):
            return f"--{opt}{eq}{value}"
    return arg


def _canonical_args(args: list[str]) -> list[str]:
    """Le opzioni lunghe abbreviate nella forma intera; dopo `--` si tratta di percorsi."""
    out = []
    for i, x in enumerate(args):
        if x == "--":
            return out + args[i:]
        out.append(_canonical_long(x))
    return out


def _git_split(a: list[str]):
    """argv di git -> (sottocomando, argomenti, directory di -C, alias definiti con -c)."""
    i, c_dir, aliases = 1, None, {}

    def note(kv: str):
        key, _, value = kv.partition("=")
        if key.lower().startswith("alias.") and key[6:].lower() not in _GIT_BUILTIN:
            aliases[key[6:].lower()] = value

    while i < len(a) and a[i].startswith("-"):
        if a[i] == "-C" and i + 1 < len(a):
            # git compone i -C: ognuno e' relativo al precedente, un assoluto azzera la base.
            c_dir = os.path.normpath(os.path.join(c_dir, a[i + 1])) if c_dir else a[i + 1]
            i += 2
        elif a[i] == "-c" and i + 1 < len(a):
            note(a[i + 1])
            i += 2
        elif a[i].startswith("-c") and not a[i].startswith("--") and len(a[i]) > 2:
            note(a[i][2:])
            i += 1
        elif a[i] in _GIT_OPT_ARG:
            i += 2
        else:
            i += 1
    return (a[i] if i < len(a) else None), a[i + 1:], c_dir, aliases


def git_call(cmd: Cmd):
    """(sottocomando, argomenti, directory di -C). Gli alias di `-c alias.<x>=<valore>` si
    sostituiscono col loro contenuto (un alias di shell, `!...`, dà il sottocomando `!`: lo legge
    `shell_alias_command`), le opzioni lunghe pericolose abbreviate si completano."""
    a = cmd.argv
    if not a or os.path.basename(a[0]) != "git":
        return None, [], None
    sub, args, c_dir, aliases = _git_split(a)
    seen = set()
    while sub is not None and sub.lower() in aliases and sub.lower() not in seen:
        seen.add(sub.lower())
        value = aliases[sub.lower()]
        if value.startswith("!"):
            return "!", _canonical_args(args), c_dir
        try:
            toks = shlex.split(value)
        except ValueError:
            toks = value.split()
        if not toks:
            break
        sub, args = toks[0], toks[1:] + args
    return sub, _canonical_args(args), c_dir


def shell_alias_command(cmd: Cmd) -> str | None:
    """Testo shell eseguito da un alias `-c alias.<x>=!<comando>` richiamato da `git <x> ...`."""
    a = cmd.argv
    if not a or os.path.basename(a[0]) != "git":
        return None
    sub, args, _, aliases = _git_split(a)
    value = aliases.get(sub.lower()) if sub is not None else None
    if value is None or not value.startswith("!"):
        return None
    return " ".join([value[1:]] + [shlex.quote(x) for x in args])


_CONFIG_FILE_OPTS = {"--global", "--system", "--file", "-f", "--blob"}
_TAG_CHANGE = {"--delete", "--force", "--annotate", "--sign", "--local-user", "--message",
               "--file", "--create-reflog"}
_BRANCH_LISTING = {"-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose", "-l", "--list",
                   "--show-current", "--merged", "--no-merged", "--contains", "--no-contains",
                   "--sort", "--format", "--color", "--no-color", "--column", "--no-column",
                   "--points-at", "-i", "--ignore-case"}


def _read_only_git(sub: str | None, args: list[str]) -> bool:
    """Forme di sola lettura dei sottocomandi che di norma scrivono (`git branch -a`,
    `git worktree list`...): l'elenco non è una scrittura (decisione 16)."""
    first = args[0] if args else None
    listing = any(x in ("-l", "--list") for x in args)
    if sub == "worktree":
        return first == "list"
    if sub == "stash":
        return first in ("list", "show")
    if sub == "submodule":
        return first in ("status", "summary")
    if sub == "remote":
        return first in (None, "-v", "--verbose", "show", "get-url")
    if sub == "tag":
        if any(x in _TAG_CHANGE or (x.startswith("-") and not x.startswith("--")
                                    and set(x[1:]) & set("dafsumF"))
               for x in args):
            return False
        return not args or listing or any(
            x.startswith(("-n", "--contains", "--no-contains", "--merged", "--no-merged",
                          "--points-at", "--sort", "--format", "--column")) for x in args)
    if sub == "branch":
        flags_ok = all(x.split("=", 1)[0] in _BRANCH_LISTING for x in args if x.startswith("-"))
        return flags_ok and (listing or not _positional(args))
    return False


def _is_mutating(sub: str | None, args: list[str]) -> bool:
    if sub == "config":
        if any(x in _CONFIG_WRITE for x in args):
            return True
        if any(x in _CONFIG_READ for x in args):
            return False
        return len(_positional(args)) >= 2  # `git config chiave valore`
    return sub in _GIT_MUTATING and not _read_only_git(sub, args)


def hooks_path_override(cmd: Cmd) -> bool:
    """`core.hooksPath` impostato per il comando (`git -c`, `--config-env`, variabili
    `GIT_CONFIG_*`) o scritto con `git config` a qualunque livello: aggira `.git/hooks`."""
    a = cmd.argv
    if not a or os.path.basename(a[0]) != "git":
        return False
    key = "core.hookspath"
    if any(key in v.lower() for v in cmd.env.values()):
        return True
    i = 1
    while i < len(a) and a[i].startswith("-"):
        if a[i] == "-c" and i + 1 < len(a):
            if a[i + 1].split("=", 1)[0].lower() == key:
                return True
            i += 2
        elif a[i].startswith("-c") and not a[i].startswith("--") and len(a[i]) > 2:
            if a[i][2:].split("=", 1)[0].lower() == key:
                return True
            i += 1
        elif a[i].startswith("--config-env="):
            if a[i].split("=", 2)[1].lower() == key:
                return True
            i += 1
        elif a[i] in _GIT_OPT_ARG:
            i += 2
        else:
            i += 1
    sub, args, _ = git_call(cmd)
    return sub == "config" and _is_mutating(sub, args) and any(
        x.lower() == key for x in _positional(args))


def git_mutating(cmd: Cmd) -> bool:
    """Comando git che scrive nel repo (non conta i redirect del comando)."""
    sub, args, _ = git_call(cmd)
    return _is_mutating(sub, args)


def git_config_write(cmd: Cmd) -> str | None:
    """`git config` in forma di scrittura: «local» per il config del repo (`.git/config`),
    il percorso dato con `--file`, None se legge o scrive `--global` o `--system`."""
    sub, args, _ = git_call(cmd)
    if sub != "config" or not _is_mutating(sub, args):
        return None
    for i, x in enumerate(args):
        if x in ("--file", "-f") and i + 1 < len(args):
            return args[i + 1]
        if x.startswith("--file="):
            return x.split("=", 1)[1]
    return None if any(x in _CONFIG_FILE_OPTS for x in args) else "local"


def effective_dir(cmd: Cmd) -> str:
    _, _, c_dir = git_call(cmd)
    return _norm(cmd.cwd, c_dir) if c_dir else cmd.cwd


def _positional(args: list[str]) -> list[str]:
    return [x for x in args if not x.startswith("-")]


def is_push(cmd: Cmd) -> bool:
    return git_call(cmd)[0] == "push"


def push_is_force(cmd: Cmd) -> bool:
    sub, args, _ = git_call(cmd)
    if sub != "push":
        return False
    # `--force-if-includes` da solo non forza: lo fa con --force o --force-with-lease.
    if any(x == "--mirror" or x == "--force" or x.startswith("--force-with-lease")
           for x in args):
        return True
    # `-f` anche nei gruppi corti (`-fu`, `-uf`).
    if any(x.startswith("-") and not x.startswith("--") and "f" in x[1:] for x in args):
        return True
    return any(x.startswith("+") for x in _positional(args)[1:])


def push_targets(cmd: Cmd) -> list[str]:
    sub, args, _ = git_call(cmd)
    if sub != "push":
        return []
    out = []
    for spec in _positional(args)[1:]:
        dst = spec.split(":")[-1].lstrip("+")
        out.append(dst.removeprefix("refs/heads/"))
    return out


def is_commit(cmd: Cmd) -> bool:
    return git_call(cmd)[0] == "commit"


def commit_all(cmd: Cmd) -> bool:
    sub, args, _ = git_call(cmd)
    if sub != "commit":
        return False
    return any(x in ("-a", "--all") or (x.startswith("-") and not x.startswith("--")
                                         and "a" in x[1:]) for x in args)


def is_gh_pr_create(cmd: Cmd) -> bool:
    return cmd.argv[:3] == ["gh", "pr", "create"]


def checkout_args(cmd: Cmd) -> list[str]:
    sub, args, _ = git_call(cmd)
    if sub != "checkout" or "--" in args:
        return []
    return _positional(args)


def branch_change(cmd: Cmd) -> str | None:
    sub, args, _ = git_call(cmd)
    if sub == "switch":
        return "git switch"
    if sub == "checkout" and any(x in ("-b", "-B", "--orphan") for x in args):
        return "git checkout -b/-B"
    if sub == "branch" and any(x in ("-m", "-M", "--move") for x in args):
        return "git branch -m/-M"
    return None


def rm_rf_targets(cmd: Cmd) -> list[str]:
    a = cmd.argv
    if not a or os.path.basename(a[0]) != "rm":
        return []
    flags = "".join(x[1:] for x in a[1:] if x.startswith("-") and not x.startswith("--"))
    long = {x for x in a[1:] if x.startswith("--")}
    recursive = "r" in flags or "R" in flags or "--recursive" in long
    force = "f" in flags or "--force" in long
    if not (recursive and force):
        return []
    return [_norm(cmd.cwd, x) for x in _positional(a[1:])]


def destructive(cmd: Cmd) -> str | None:
    sub, args, _ = git_call(cmd)
    if sub == "reset" and "--hard" in args:
        return "git reset --hard"
    if sub is not None and "--no-verify" in args:
        return "--no-verify"
    # `git commit -n` è l'alias di --no-verify, anche nei gruppi di opzioni corti (`-nm`).
    if sub == "commit" and any(x == "-n" or (x.startswith("-") and not x.startswith("--")
                                              and "n" in x[1:]) for x in args):
        return "--no-verify"
    return None


def _inplace(args: list[str]) -> bool:
    return any(x == "--in-place" or x.startswith("--in-place=")
               or (x.startswith("-") and not x.startswith("--") and "i" in x[1:])
               for x in args)


def _inplace_files(args: list[str]) -> list[str]:
    """File modificati da sed/perl -i: le posizionali, senza il programma se non è dato con -e/-f."""
    files: list[str] = []
    code = False
    i = 0
    while i < len(args):
        x = args[i]
        if x in ("-e", "--expression", "-f", "--file"):
            code = True
            i += 2
            continue
        if x.startswith(("--expression=", "--file=")):
            code = True
            i += 1
            continue
        if x.startswith("-") and x != "-":
            i += 1
            continue
        files.append(x)
        i += 1
    if not code and files:
        files = files[1:]
    return files


def _target_dir(args: list[str]) -> str | None:
    """Directory di `cp/mv/install -t dir` (anche `-tdir` e `--target-directory=dir`)."""
    for i, x in enumerate(args):
        if x in ("-t", "--target-directory") and i + 1 < len(args):
            return args[i + 1]
        if x.startswith("--target-directory="):
            return x.split("=", 1)[1]
        if x.startswith("-t") and not x.startswith("--") and len(x) > 2:
            return x[2:]
    return None


def _is_source_option(x: str) -> bool:
    """`-s`, `-s<albero>`, `--source`, `--source=...` e i prefissi abbreviati (`--so`, `--sour=`)."""
    if x.startswith("--"):
        name = x[2:].partition("=")[0]
        return len(name) >= 2 and "source".startswith(name)
    return x.startswith("-s")


def _in_c_dir(cmd: Cmd, targets: list[str]) -> list[str]:
    """I percorsi di un comando git sono relativi alla directory di `-C`, non al `cwd`."""
    if git_call(cmd)[2] is None:
        return targets
    base = effective_dir(cmd)
    return [_norm(base, t) for t in targets]


def _git_restore_targets(cmd: Cmd) -> list[str]:
    """File che `git checkout <albero> -- <file>` e `git restore <file>` riscrivono."""
    sub, args, _ = git_call(cmd)
    if sub not in ("checkout", "restore"):
        return []
    if "--" in args:
        return _in_c_dir(cmd, args[args.index("--") + 1:])
    if sub == "checkout":
        return []
    out, i = [], 0
    while i < len(args):
        if args[i] in ("-s", "--source"):
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            out.append(args[i])
            i += 1
    return _in_c_dir(cmd, out)


def restores_from_index(cmd: Cmd) -> bool:
    """`git checkout -- <file>` e `git restore <file>` senza albero né `--source`: tornano alla
    versione dell'indice, non scrivono codice nuovo."""
    sub, args, _ = git_call(cmd)
    if sub == "checkout":
        return bool(args) and args[0] == "--"
    if sub == "restore":
        return not any(_is_source_option(x) for x in args)
    return False


def write_targets(cmd: Cmd) -> list[str]:
    a = cmd.argv
    out = list(cmd.redirects)
    if not a:
        return out
    base = os.path.basename(a[0])
    args = a[1:]
    pos = _positional(args)
    if base == "tee":
        out += pos
    elif base in ("sed", "perl") and _inplace(args):
        out += _inplace_files(args)
    elif base in ("cp", "mv", "install", "ln"):
        target = _target_dir(args)
        # `mv` toglie anche le sorgenti, e `cp --remove-source-files` pure.
        removes = base == "mv" or (base == "cp" and any(
            x.startswith("--remove-source") for x in args))
        if target is not None:
            if removes:
                srcs = list(pos)
                if target in srcs:
                    srcs.remove(target)
                out += srcs
            out.append(target)
        elif removes:
            out += pos
        elif len(pos) >= 2:
            out.append(pos[-1])
    elif base in ("rm", "touch", "mkdir", "rmdir", "truncate"):
        out += pos
    elif base in ("chmod", "chown"):
        out += pos[1:]
    elif base == "dd":
        out += [x[3:] for x in args if x.startswith("of=")]
    elif base == "git":
        out += _git_restore_targets(cmd)
    return out


_REMOVERS = {"rm", "rmdir", "unlink", "mv", "shred"}


def _find_parts(args: list[str]) -> tuple[list[str], list[str]]:
    """Radici di `find` (prima della prima espressione) e resto dell'espressione."""
    i = 0
    while i < len(args) and not (args[i].startswith("-") or args[i] in ("(", "!")):
        i += 1
    return (args[:i] or ["."]), args[i:]


def _find_removes(expr: list[str]) -> bool:
    if "-delete" in expr:
        return True
    return any(x in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(expr)
               and os.path.basename(expr[i + 1]) in _REMOVERS for i, x in enumerate(expr))


def removal_targets(cmd: Cmd) -> list[str]:
    """Ciò che `rm`, `rmdir`, `unlink`, `git rm`, `mv` (le sorgenti) e `find -delete/-exec rm`
    (la radice di `find`) tolgono dal loro posto."""
    a = cmd.argv
    if not a:
        return []
    base = os.path.basename(a[0])
    if base in ("rm", "rmdir", "unlink"):
        return _positional(a[1:])
    if base == "mv":
        pos = _positional(a[1:])
        target = _target_dir(a[1:])
        if target is None:
            return pos[:-1]
        if target in pos:
            pos.remove(target)
        return pos
    if base == "find":
        roots, expr = _find_parts(a[1:])
        return roots if _find_removes(expr) else []
    sub, args, _ = git_call(cmd)
    if sub == "rm":
        return _in_c_dir(cmd, _positional(args))
    return []


def removal_recursive(cmd: Cmd) -> bool:
    """La rimozione può portare via intere cartelle (e quindi file protetti sotto di esse)."""
    a = cmd.argv
    if not a:
        return False
    base = os.path.basename(a[0])
    flags = "".join(x[1:] for x in a[1:] if x.startswith("-") and not x.startswith("--"))
    recursive = "r" in flags or "R" in flags or "--recursive" in a
    if base == "rm":
        return recursive
    if base in ("rmdir", "find"):
        return bool(removal_targets(cmd))
    sub, args, _ = git_call(cmd)
    return sub == "rm" and (any(x == "-r" or (x.startswith("-") and not x.startswith("--")
                                              and "r" in x[1:]) for x in args))


def writes(cmd: Cmd) -> bool:
    return bool(write_targets(cmd)) or git_mutating(cmd)


def is_claude(cmd: Cmd) -> bool:
    a = cmd.argv
    if not a:
        return False
    base = os.path.basename(a[0])
    if base in ("claude", "claude-code"):
        return True
    return base in ("npx", "bunx", "pnpx", "pnpm", "yarn", "npm") and any(
        "@anthropic-ai/claude-code" in x for x in a[1:])


def is_tollgate_hook(cmd: Cmd) -> bool:
    a = cmd.argv
    for i, x in enumerate(a[:2]):
        if os.path.basename(x) == "tollgate":
            return len(a) > i + 1 and a[i + 1] == "hook"
    return False


def script_index(argv: list[str]) -> int | None:
    """Posizione dello script in `python3 [opzioni] script ...`, saltando le opzioni
    dell'interprete (`-B`, `-W error`, `-X dev`). None se non è un interprete python, se non c'è
    uno script o se il codice arriva da `-c`/`-m`."""
    if not argv or not os.path.basename(argv[0]).startswith("python"):
        return None
    i = 1
    while i < len(argv) and argv[i].startswith("-") and argv[i] != "-":
        opt = argv[i]
        if opt[:2] in ("-c", "-m"):
            return None
        i += 2 if opt in ("-W", "-X") else 1
    return i if i < len(argv) else None


def uses_tollgate_bin(cmd: Cmd, plugin_bin: str) -> bool:
    a = cmd.argv
    target = os.path.realpath(plugin_bin)
    k = script_index(a)
    cands = a[:1] + ([a[k]] if k is not None else [])
    return any(os.path.realpath(_norm(cmd.cwd, x)) == target for x in cands)


def merge_args(cmd: Cmd) -> list[str]:
    sub, args, _ = git_call(cmd)
    return _positional(args) if sub == "merge" else []


def worktree_op(cmd: Cmd):
    sub, args, _ = git_call(cmd)
    if sub != "worktree" or not args:
        return None
    op, rest = args[0], args[1:]
    branch = None
    if "-b" in rest or "-B" in rest:
        k = rest.index("-b") if "-b" in rest else rest.index("-B")
        branch = rest[k + 1] if k + 1 < len(rest) else None
        rest = rest[:k] + rest[k + 2:]
    pos = _positional(rest)
    if op == "add" and pos:
        return ("add", _norm(cmd.cwd, pos[0]), branch or (pos[1] if len(pos) > 1 else None))
    if op == "remove" and pos:
        return ("remove", _norm(cmd.cwd, pos[0]), None)
    return None


def branch_deletes(cmd: Cmd) -> list[str]:
    sub, args, _ = git_call(cmd)
    if sub != "branch" or not any(x in ("-d", "-D", "--delete") for x in args):
        return []
    return _positional(args)


# --- effetti esterni (8.5) --------------------------------------------------------------------

@dataclass(frozen=True)
class EffectsCfg:
    commands: tuple | list = ()
    project_scripts: tuple | list = ()
    allow: tuple | list = ()


_DEFAULT_EFFECTS = [("ssh",), ("scp",), ("rsync",), ("psql",), ("docker", "push"),
                    ("kubectl",), ("terraform", "apply"), ("aws",), ("gcloud",), ("az",),
                    ("vercel",), ("netlify",), ("firebase", "deploy"), ("wrangler", "deploy"),
                    ("wrangler", "publish"), ("npm", "publish"), ("pnpm", "publish"),
                    ("yarn", "publish")]
_SUPABASE_WRITE = {"db", "functions", "secrets", "link", "migration", "storage", "projects",
                   "orgs", "branches"}
_SUPABASE_READ = {"list", "diff", "dump", "ls", "download", "--help", "-h"}
_GH_WRITE = {("pr", "create"), ("pr", "edit"), ("pr", "review"), ("pr", "close"),
             ("pr", "merge"), ("workflow", "run"), ("issue", "edit"), ("issue", "close"),
             ("issue", "create")}
_GH_WRITE_ANY = {"release", "secret", "project"}
_GH_GLOBAL_ARG = {"-R", "--repo", "--hostname"}


def normalized(cmd: Cmd) -> str:
    return " ".join(cmd.argv)


def _matches(patterns, text: str) -> bool:
    # Per i comandi `*` attraversa `/` (fnmatch), come da decisione del controller.
    return any(text == p or text.startswith(p + " ") or fnmatch.fnmatchcase(text, p)
               for p in patterns)


def _curl_write(a: list[str]) -> bool:
    for i, x in enumerate(a):
        if x in ("-X", "--request") and i + 1 < len(a) and a[i + 1].upper() != "GET":
            return True
        if x.startswith("-X") and len(x) > 2 and x[2:].upper() != "GET":
            return True
        if x.startswith("--request=") and x.split("=", 1)[1].upper() != "GET":
            return True
        if x in ("-d", "-F", "-T", "--json", "--form", "--upload-file") or \
                x.startswith(("--data", "--form", "-d")):
            return True
    return False


def _wget_write(a: list[str]) -> bool:
    for x in a:
        if x.startswith(("--post-data", "--post-file", "--body-data", "--body-file")):
            return True
        if x.startswith("--method") and x.split("=", 1)[-1].upper() != "GET":
            return True
    return False


def _gh_args(a: list[str]) -> list[str]:
    """`gh` senza i flag globali (`-R o/r`, `--repo=o/r`) che precedono o seguono il sottocomando."""
    out: list[str] = []
    i = 1
    while i < len(a):
        x = a[i]
        if x in _GH_GLOBAL_ARG:
            i += 2
            continue
        if x.startswith(("--repo=", "--hostname=")) or (
                x.startswith("-R") and len(x) > 2 and not x.startswith("--")):
            i += 1
            continue
        out.append(x)
        i += 1
    return ["gh"] + out


def _gh_write(a: list[str]) -> bool:
    if len(a) < 2:
        return False
    if a[1] in _GH_WRITE_ANY:
        return True
    if len(a) >= 3 and (a[1], a[2]) in _GH_WRITE:
        return True
    if a[1] == "api":
        rest = a[2:]
        for i, x in enumerate(rest):
            if x in ("-X", "--method") and i + 1 < len(rest) and rest[i + 1].upper() != "GET":
                return True
            if x.startswith("-X") and len(x) > 2 and x[2:].upper() != "GET":
                return True
            if x.startswith("--method=") and x.split("=", 1)[1].upper() != "GET":
                return True
        graphql = "graphql" in rest
        fields = [rest[i + 1] for i, x in enumerate(rest[:-1])
                  if x in ("-f", "-F", "--field", "--raw-field")]
        if graphql:
            return any(re.search(r"\bmutation\b", f) for f in fields) or "--input" in rest
        return bool(fields) or "--input" in rest
    return False


def effect_reason(cmd: Cmd, cfg: EffectsCfg) -> str | None:
    a = cmd.argv
    if not a:
        return None
    text = normalized(cmd)
    if _matches(cfg.allow, text):
        return None
    if _matches(cfg.commands, text):
        return "comando dichiarato in [external_effects] commands"
    base = os.path.basename(a[0])
    for prefix in _DEFAULT_EFFECTS:
        if [base] + a[1:len(prefix)] == list(prefix):
            return f"effetto esterno: {' '.join(prefix)}"
    if base == "supabase" and len(a) > 1 and a[1] in _SUPABASE_WRITE \
            and not (len(a) > 2 and a[2] in _SUPABASE_READ):
        return "effetto esterno: supabase in scrittura"
    if base in ("npm", "pnpm", "yarn", "bun") and len(a) > 1:
        script = a[2] if a[1] == "run" and len(a) > 2 else a[1]
        if script in cfg.project_scripts:
            return f"script del progetto: {script}"
    if base in ("make", "just") and any(x in cfg.project_scripts for x in a[1:]):
        return "script del progetto"
    if base == "curl" and _curl_write(a[1:]):
        return "curl con metodo diverso da GET o con dati"
    if base == "wget" and _wget_write(a[1:]):
        return "wget con metodo diverso da GET o con dati"
    if base == "gh" and _gh_write(_gh_args(a)):
        return "gh in scrittura"
    return None


_INTERPRETERS = {"bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl", "deno",
                 "bun", "tsx", "ts-node", "php"}


def script_path(cmd: Cmd) -> str | None:
    a = cmd.argv
    if not a:
        return None
    if "/" in a[0] and os.path.basename(a[0]) not in _INTERPRETERS:
        return _norm(cmd.cwd, a[0])
    if os.path.basename(a[0]) in _INTERPRETERS:
        rest = a[1:]
        if any(x in ("-c", "-m", "-e") for x in rest[:1]):
            return None
        pos = [x for x in rest if not x.startswith("-")]
        if pos and ("/" in pos[0] or re.search(r"\.(sh|py|js|mjs|ts|rb|pl|php)$", pos[0])):
            return _norm(cmd.cwd, pos[0])
    return None


_TEXT_DANGER = [
    (re.compile(r"\bgit\b[^;&|]*\bpush\b"), "git push"),
    (re.compile(r"--force\b"), "--force"),
    (re.compile(r"\breset\b[^;&|]*--hard\b"), "reset --hard"),
    (re.compile(r"--no-verify\b"), "--no-verify"),
    (re.compile(r"\bcommit\b[^;&|]*\s-[a-zA-Z]*n[a-zA-Z]*\b"), "--no-verify"),
    (re.compile(r"TOLLGATE_"), "TOLLGATE_"),
    (re.compile(r"(^|[\s;&|(])claude(\s|$)"), "claude"),
    (re.compile(r"rm\s+-[a-zA-Z]*[rR]"), "rm -r"),
    (re.compile(r"hookspath", re.IGNORECASE), "core.hooksPath"),
    (re.compile(r"tollgate\.toml"), "tollgate.toml"),
    (re.compile(r"\.tollgate/"), ".tollgate/"),
    (re.compile(r"settings(\.local)?\.json"), "settings.json"),
]


def text_danger(raw: str) -> str | None:
    """Ripiego per i comandi che shlex non legge: si cerca per testo."""
    for rx, label in _TEXT_DANGER:
        if rx.search(raw):
            return label
    return None


_B = r"(?:^|[\s;&|(`'\"])"
_E = r"(?=[\s;&|)`'\"]|$)"
_TEXT_EFFECTS = [
    (re.compile(_B + r"\s+".join(re.escape(w) for w in prefix) + _E),
     "effetto esterno: " + " ".join(prefix)) for prefix in _DEFAULT_EFFECTS] + [
    (re.compile(_B + r"supabase\s+(?:db|functions|secrets|link|migration|storage|projects|orgs|"
                r"branches)\b(?!\s+(?:list|diff|dump|ls|download)\b)"),
     "effetto esterno: supabase in scrittura"),
    (re.compile(_B + r"gh\s+(?:(?:-R|--repo)\s+\S+\s+)?(?:pr\s+(?:create|edit|review|close|merge)|"
                r"workflow\s+run|issue\s+(?:edit|close|create)|release|secret|project)" + _E),
     "gh in scrittura"),
    (re.compile(_B + r"gh\s+api\b[^;&|]*(?:\s-X\s*(?!GET\b)\w|--method[ =](?!GET\b)|\s-[fF]\s|"
                r"--field|--raw-field|--input)"), "gh in scrittura"),
    (re.compile(_B + r"curl\b[^;&|]*(?:\s-X\s*(?!GET\b)\w|--request[ =](?!GET\b)|\s-d\b|"
                r"--data|\s-F\b|--form|\s-T\b|--upload-file|--json)"),
     "curl con metodo diverso da GET o con dati"),
    (re.compile(_B + r"wget\b[^;&|]*--(?:post-|body-|method[ =](?!GET\b))"),
     "wget con metodo diverso da GET o con dati"),
]


def text_effect(raw: str) -> str | None:
    """Ripiego per i comandi che shlex non legge: effetti esterni cercati per testo."""
    for rx, label in _TEXT_EFFECTS:
        if rx.search(raw):
            return label
    return None
