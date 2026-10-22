"""Il percorso di un hook (spec 7.1 dal punto 5, 3.2, 12.1)."""
from __future__ import annotations

import json
import os
import signal
import sqlite3
import traceback
from dataclasses import dataclass
from pathlib import Path

from tollgate_analysis import bash
from tollgate_core import active, clock, db, git, offlog, sessions, subagents
from tollgate_core.acts import ActError
from tollgate_core.config import ConfigError, ConfigNotFound, load_config
from tollgate_core.phases import TransitionError
from tollgate_core.tasks import TaskTransitionError
from tollgate_core.events import record_event
from tollgate_core.paths import program_command, resolve_state

from . import adapter, apply as applier, registry
from .context import Ctx, ReadDb
from .model import CONTROL_EVENTS

HOOKS_LOG = "hooks.log"
PLUGIN_ROOT = Path(__file__).resolve().parents[2]
BUDGET = {"session_start": (10, 1500), "subagent_start": (None, 2000)}
DEFAULT_BUDGET = (None, 1500)
_CONTROL_HOOKS = {"PreToolUse"}
# Eventi la cui protezione segue il bersaglio (I1): file per Edit/Write, `-C` o `cd` per Bash.
_TARGET_KINDS = {"pre_edit", "pre_bash"}


@dataclass(frozen=True)
class HookResult:
    exit: int
    stdout: str = ""
    stderr: str = ""


class _Timeout(BaseException):
    pass


class _Unverifiable(Exception):
    pass


def _footer(state_root: Path) -> str:
    return (f"Programma: {program_command(db.BIN_PATH)}. Per spegnere tollgate: /tollgate:off, "
            f"oppure dal terminale: touch {state_root / 'OFF'}")


def _fail(control: bool, msg: str, state_root: Path) -> HookResult:
    text = f"tollgate: {msg}\n{_footer(state_root)}\n"
    if control:
        return HookResult(2, "", text + "Azione negata perché il controllo non è riuscito.\n")
    return HookResult(0, "", text + "Avviso: controllo informativo saltato.\n")


def _log(state_root: Path, now, text: str) -> None:
    """Log degli hook: dove finisce ciò che Claude Code non mostrerebbe (nessuna iniezione)."""
    try:
        state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with open(state_root / HOOKS_LOG, "a", encoding="utf-8") as f:
            f.write(f"{clock.fmt(now)} {text.replace(chr(10), ' / ')}\n")
    except OSError:
        pass


def _off_active(state_root: Path, now) -> bool:
    off = state_root / "OFF"
    if not off.exists():
        return False
    try:
        for line in off.read_text().splitlines():
            if line.startswith("until="):
                return now.timestamp() < int(line[6:])
    except (OSError, ValueError):
        pass
    return True


def _budget(kind: str, text: str) -> str:
    max_lines, max_chars = BUDGET.get(kind, DEFAULT_BUDGET)
    lines = text.splitlines()
    if max_lines is not None and len(lines) > max_lines:
        text = "\n".join(lines[:max_lines - 1] + ["…"])
    if len(text) > max_chars:
        text = text[:max_chars - 1] + "…"
    return text


def _set_alarm(seconds: int) -> None:
    def handler(signum, frame):
        raise _Timeout()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(max(1, int(seconds)))


def _corrupt(e: BaseException) -> bool:
    code = getattr(e, "sqlite_errorcode", None)
    return code is not None and (code & 0xFF) in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB)


def _repo_active(repo) -> bool:
    """`tollgate.toml` sul riferimento predefinito del repo (7.1 punto 3), senza rete."""
    if repo is None:
        return False
    try:
        ref = git.default_ref(repo)
        return bool(ref) and git.exists_at(repo, ref, "tollgate.toml")
    except git.GitError:
        return False


_SUBST = "_TG_SUBST_"
_GLOB_CHARS = "*?["


def _candidate(base: str, raw: str) -> Path | None:
    """Percorso di un bersaglio: `~` espanso, relativo al `cwd` effettivo del comando; per un
    glob vale la cartella che precede il primo carattere glob."""
    if not raw or _SUBST in raw:
        return None
    first = min((i for i, ch in enumerate(raw) if ch in _GLOB_CHARS), default=None)
    if first is not None:
        raw = raw[:first][:raw[:first].rfind("/") + 1] or "."
    return Path(os.path.normpath(os.path.join(base, os.path.expanduser(raw))))


def _target(event) -> list[tuple[Path, Path]]:
    """Repo attivi (e percorso) che l'azione di controllo nomina, dove si ricava: il file di
    Edit/Write; per Bash la directory effettiva (`-C`, `cd`) di ogni comando e i suoi bersagli
    di scrittura e rimozione (redirect, `sed -i`, `rm`...). Un solo elemento per repo."""
    if event.kind == "pre_edit":
        raw = adapter.edit_path(event)
        paths = [_candidate(str(event.cwd), raw)] if raw else []
    else:
        try:
            cmds = bash.parse(str(event.tool_input.get("command") or ""), str(event.cwd))
        except bash.BashParseError:
            return []
        paths = []
        for c in cmds:
            if not c.argv and not c.redirects:
                continue
            paths.append(Path(bash.effective_dir(c)))
            paths += [_candidate(c.cwd, t) for t in
                      bash.write_targets(c) + bash.removal_targets(c)]
    # Un solo elemento per repo git (stessa cartella comune): il checkout principale e i suoi
    # worktree sono lo stesso repo. Tra i candidati dello stesso repo vale un worktree
    # collegato, se un bersaglio ci cade dentro, altrimenti il primo.
    found: dict[Path, tuple[Path, Path]] = {}
    for p in paths:
        if p is None:
            continue
        repo = git.toplevel(p)
        if repo is None or not _repo_active(repo):
            continue
        try:
            key = git.common_dir(repo)
            linked = repo != git.main_worktree(repo)
        except git.GitError as e:
            raise _Unverifiable(f"non è stato possibile verificare il repo del bersaglio "
                                f"{repo} ({e}): azione negata per prudenza") from e
        if key not in found or (linked and found[key][0] == git.main_worktree(repo)):
            found[key] = (repo, p)
    return list(found.values())


def run_hook(hook_event: str, stdin_text: str, *, env=None, now=None, plugin_root=None,
             checks=None, alarm: bool = False) -> HookResult:
    env = os.environ if env is None else env
    state = resolve_state(env)
    control = hook_event in _CONTROL_HOOKS
    now = now or clock.now()
    if alarm:
        _set_alarm(20)
    conn = None
    try:
        if _off_active(state.root, now):
            return HookResult(0)
        try:
            raw = json.loads(stdin_text)
            event = adapter.to_event(hook_event, raw)
        except (ValueError, TypeError) as e:
            return _fail(control, f"input dell'hook non valido ({e})", state.root)
        if event is None:
            return HookResult(0)
        control = event.kind in CONTROL_EVENTS
        if event.kind == "pre_edit" and adapter.edit_path(event) is None:
            return _fail(control, "modifica senza percorso: tool_input privo di file_path",
                         state.root)
        cwd_ok = event.cwd.is_dir()
        root = git.toplevel(event.cwd) if cwd_ok else None
        anchor = event.cwd if cwd_ok else None
        if event.kind in _TARGET_KINDS and not _repo_active(root):
            # Il cwd non è in un repo attivo (o non esiste): repo e configurazione vengono dal
            # bersaglio (I1, M1).
            try:
                targets = _target(event)
            except _Unverifiable as e:
                return _fail(control, str(e), state.root)
            if len(targets) > 1:
                names = ", ".join(str(r) for r, _ in targets)
                return _fail(True, f"l'azione tocca più repo attivi ({names}): dividila in "
                                   f"azioni separate, una per repo", state.root)
            if targets:
                root, anchor = targets[0]
        # Senza sessione non c'è segnalino (e `bound/` stessa non è il segnalino di nessuno).
        marked = bool(event.session) and sessions._SAFE.match(event.session) is not None \
            and (state.root / sessions.BOUND_DIR / event.session).exists()
        if root is None and not marked:
            return HookResult(0)
        if hook_event == "PreToolUse" and not marked and not _repo_active(root):
            return HookResult(0)
        conn = db.open_db(state)
        offlog.import_log(conn, state)
        if event.session:
            sessions.touch(conn, event.session, now=now)
        if event.agent_id and subagents.get(conn, event.agent_id) is not None:
            subagents.touch(conn, event.agent_id, now=now)
        bound = sessions.bound_work(conn, event.session) if event.session else None
        work = bound or (sessions.work_for_path(conn, anchor) if anchor is not None else None)
        if work is not None and work["work_base_sha"] and work["worktree"] \
                and Path(work["worktree"]).is_dir():
            cfg_repo, ref = Path(work["worktree"]), work["work_base_sha"]
        elif root is not None:
            cfg_repo, ref = root, git.default_ref(root)
        else:
            return HookResult(0)
        if ref is None:
            return HookResult(0, "", "tollgate: nessun riferimento remoto (origin/HEAD, main, "
                                     "master): repo trattato come non attivo\n")
        try:
            config = load_config(state, cfg_repo, ref, env=env)
        except ConfigNotFound:
            return HookResult(0)
        except ConfigError as e:
            return _fail(control, f"tollgate.toml non valido: {e}", state.root)
        active.register(state, root if root is not None else cfg_repo)
        if alarm:
            _set_alarm(config.get("hooks.timeout_s"))
        repo = root
        if repo is None and work is not None and work["worktree"] \
                and Path(work["worktree"]).is_dir():
            repo = Path(work["worktree"])
        ctx = Ctx(event, state, ReadDb(conn), config, repo, work,
                  bound is not None and work is not None and bound["id"] == work["id"], now,
                  Path(plugin_root) if plugin_root else PLUGIN_ROOT)
        loaded, broken = checks if checks is not None else registry.load()
        denial, rule, injects, records = None, "", [], []
        for b in broken:
            if (b.events is None and control) or (b.events and event.kind in b.events):
                msg = f"controllo «{b.name}» non caricato: {b.reason}"
                if control:
                    if denial is None:
                        denial, rule = f"{msg}\n{_footer(state.root)}", b.name
                else:
                    injects.append(f"(tollgate: {msg})")
        for m in loaded:
            if event.kind not in m.check["events"]:
                continue
            comp = m.check.get("component")
            if comp and not ctx.component(comp):
                continue
            try:
                decisions = m.module.decide(event, ctx) or []
            except (_Timeout, sqlite3.Error):
                raise
            except Exception as e:
                if control:
                    if denial is None:
                        denial, rule = (f"controllo «{m.name}» in errore: {e}\n"
                                        f"{_footer(state.root)}"), m.name
                else:
                    injects.append(f"(tollgate: controllo «{m.name}» in errore: {e})")
                continue
            for d in decisions:
                if d.kind == "deny" and denial is None:
                    denial, rule = d.text, d.rule or m.name
                elif d.kind == "inject" and d.text:
                    injects.append(d.text)
                elif d.kind == "record":
                    records.append(d)
        for d in records:
            try:
                applier.apply(conn, state, ctx, d)
            except (TransitionError, TaskTransitionError, ActError, ValueError) as e:
                # una registrazione non più possibile (fase cambiata, atto scaduto) non
                # annulla le altre né il veto: si riporta e si va avanti
                injects.append(f"(tollgate: registrazione «{d.op}» non applicata: {e})")
        if event.kind == "prompt_submit" and denial:
            # informativo: non blocca mai il prompt dell'utente (uscita sempre 0)
            _log(state.root, now, f"prompt_submit: veto ignorato ({rule}): {denial}")
            denial = None
        if denial:
            record_event(conn, "veto", {"event": event.kind, "rule": rule, "reason": denial},
                         now=now, session=event.session or None,
                         work=work["id"] if work is not None else None)
        inject_text = _budget(event.kind, "\n".join(injects)) if injects else None
        if inject_text and event.kind in adapter.NO_INJECT_KINDS:
            _log(state.root, now, f"{event.kind}: {inject_text}")
            inject_text = None
        code, out, err = adapter.render(hook_event, denial, inject_text)
        return HookResult(code, out, err)
    except _Timeout:
        return _fail(control, "controllo oltre la scadenza ([hooks] timeout_s)", state.root)
    except db.DbCorrupt as e:
        return _fail(control, str(e), state.root)
    except db.DbError as e:
        return _fail(control, str(e), state.root)
    except sqlite3.Error as e:
        if _corrupt(e) or type(e) is sqlite3.DatabaseError:
            return _fail(control, f"DB di tollgate guasto: {e}. Ripristino dal terminale: "
                                  f"{db.restore_hint()}", state.root)
        return _fail(control, f"errore del DB: {e}", state.root)
    except Exception as e:
        tb = traceback.format_exc(limit=3)
        return _fail(control, f"errore interno: {e}\n{tb}", state.root)
    finally:
        if alarm:
            signal.alarm(0)
        if conn is not None:
            conn.close()
