"""`tollgate init --propose|--update` (spec 11.2, 9.3, 9.5, 9.6, decisione 18).

Misura la modalità del gate dalla protezione del ramo predefinito e scrive in
`docs/superpowers/tollgate-init/` la proposta: `README.md` con i passi dell'utente, `files/` con
l'albero da copiare e, in `protected`, `protection.json` e `protect.sh`. Non scrive mai su GitHub
e non tocca i file di tollgate del repo: li copia l'utente. Codici: 0 fatto, 1 rifiuto."""
from __future__ import annotations

import json
import math
import re
import shlex
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from tollgate_analysis import prbody, workflows
from tollgate_core import VERSION, clock, config, db, git
from tollgate_core.paths import State, repo_key
from tollgate_gate import install, protection

from . import gitw

OK, REFUSED = 0, 1
FOLDER = "docs/superpowers/tollgate-init"
PLUGIN_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = PLUGIN_ROOT / "templates" / "tollgate.toml"
FREE_MINUTES = "2.000"                  # GitHub Free, repo privati (9.5)
RECEIPT_SOURCES = ("finish", "verify")
MODE_PLACEHOLDER = "__MODE__"

_SECTION = re.compile(r"^\s*\[([^\[\]]*)\]\s*(?:#.*)?$")
_MODE_LINE = re.compile(r'^(\s*mode\s*=\s*)"[^"\n]*"')


@dataclass
class InitResult:
    code: int
    lines: list[str]
    folder: Path | None = None


@dataclass
class _Proposal:
    mode: str
    kind: str
    missing: list[str]
    files: dict[str, bytes]
    removed: list[str] = field(default_factory=list)
    violations: list[tuple[str, str]] = field(default_factory=list)
    jest: bool = False
    jest_junit: bool = False
    seconds: float | None = None
    from_template: bool = False


def _refuse(*lines: str) -> InitResult:
    return InitResult(REFUSED, [f"tollgate: {line}" for line in lines])


def _plain(text: str) -> str:
    """Testo di un repo per l'uscita a terminale: i caratteri non stampabili diventano `?`."""
    return "".join(c if c.isprintable() else "?" for c in text)


def with_mode(text: str, mode: str) -> str:
    """`text` (un `tollgate.toml`) con `[gate] mode` uguale a `mode`: cambia solo quella riga, o
    la aggiunge alla sezione, o crea la sezione. Il resto del file resta com'è."""
    lines = text.splitlines()
    section, last_gate = None, None
    for i, line in enumerate(lines):
        m = _SECTION.match(line)
        if m:
            section = m.group(1).strip()
            if section == "gate":
                last_gate = i
            continue
        found = _MODE_LINE.match(line)
        if section == "gate" and found:
            lines[i] = f'{found.group(1)}"{mode}"' + line[found.end():]
            return "\n".join(lines) + "\n"
    if last_gate is not None:
        lines.insert(last_gate + 1, f'mode = "{mode}"')
        return "\n".join(lines) + "\n"
    return "\n".join(lines).rstrip("\n") + f'\n\n[gate]\nmode = "{mode}"\n'


def _mode_for(kind: str) -> str | None:
    return {protection.DETECT: "detect", protection.PROTECTED: "protected",
            protection.PROTECTED_UNSET: "protected"}.get(kind)


def _gate_commands(text: str) -> list[str]:
    try:
        return list(config.load_config_text(text).get("commands.gate"))
    except config.ConfigError:
        return []


def _gate_seconds(state: State, key: str, commands: list[str]) -> float | None:
    """La somma di `receipts.duration` dell'ultima ricevuta verde per ciascun comando del gate,
    sullo SHA più recente che ne ha una per **ogni** comando (con la durata scritta), prodotta
    da `finish` o `verify` per i lavori del repo `key`. Le ricevute di altri repo, quelle senza
    lavoro e quelle non verdi non contano. `None` se non c'è: non si inventa una stima."""
    if not commands or not state.db_path.exists():
        return None
    try:
        conn = db.open_db(state)
    except (db.DbError, sqlite3.Error, OSError):
        return None
    try:
        rows = conn.execute(
            f"SELECT r.sha, r.command, r.duration FROM receipts r "
            f"JOIN work_items w ON w.id = r.work WHERE w.repo_key = ? AND r.state = 'green' "
            f"AND r.command IN ({','.join('?' * len(commands))}) AND r.produced_by IN "
            f"({','.join('?' * len(RECEIPT_SOURCES))}) ORDER BY r.id DESC",
            [key, *commands, *RECEIPT_SOURCES]).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    latest: dict[str, dict[str, float | None]] = {}
    for row in rows:                       # dalla più recente: la prima di ogni comando vale
        latest.setdefault(row["sha"], {}).setdefault(row["command"], row["duration"])
    for per_command in latest.values():    # `dict` conserva l'ordine: prima lo SHA più recente
        if set(per_command) == set(commands) and all(
                isinstance(v, (int, float)) for v in per_command.values()):
            return float(sum(per_command.values()))
    return None


def _existing_violations(main, ref: str) -> list[tuple[str, str]]:
    """Decisione 15: i workflow del progetto già presenti che violano le regole di `guard`
    (quelli di tollgate non si controllano: li scrive tollgate)."""
    found = []
    for rel in git.ls_files_at(main, ref, ".github/workflows/"):
        if not workflows.is_workflow_path(rel) or PurePosixPath(rel).name.startswith("tollgate-"):
            continue
        text = git.text_at(main, ref, rel)
        problems = ["il file non si legge come testo"] if text is None \
            else workflows.problems(text)
        found += [(rel, p) for p in problems]
    return found


def _jest(main, ref: str) -> tuple[bool, bool]:
    """`(usa jest, ha già jest-junit)` da `package.json` sul predefinito."""
    text = git.text_at(main, ref, "package.json")
    try:
        data = json.loads(text) if text else None
    except ValueError:
        return False, False
    if not isinstance(data, dict):
        return False, False
    deps = {}
    for key in ("dependencies", "devDependencies"):
        if isinstance(data.get(key), dict):
            deps.update(data[key])
    return ("jest" in deps or "jest" in data), "jest-junit" in deps


def _quote(value: str) -> str:
    """Sempre tra apici singoli, anche se la shell non lo richiederebbe."""
    return "'" + value.replace("'", "'\\''") + "'"


def _protect_script(branch: str) -> str:
    """`protect.sh`: legge `app.id` dal check-run di `tollgate-base` sullo SHA dato (per difetto
    la punta di `origin/<ramo>`) e fissa con quello la sorgente dei controlli (9.3). Si ferma se
    il check-run manca, se non è finito, se ha più `app.id` diversi o se non è un intero positivo:
    mai `-1`. Nomi e valori entrano nel testo solo quotati."""
    jq = (f'.check_runs[] | select(.name == "{protection.BASE_JOB}" and '
          f'.app.slug == "{protection.BASE_APP_SLUG}") | '
          '[.status, (.conclusion // ""), (.app.id | tostring)] | @tsv')
    contexts = ", ".join(protection.REQUIRED_CONTEXTS)
    return f"""#!/usr/bin/env bash
# Attiva la protezione del ramo {branch} per tollgate (spec 9.3).
# Lo lanci tu, dalla radice del repo e con le tue credenziali di gh, dopo aver unito sul ramo
# predefinito il commit che installa i workflow e dopo che `{protection.BASE_JOB}` è finito.
# Uso: protect.sh [SHA]   (SHA: il commit su cui cercare il check-run; per difetto origin/{branch})
set -euo pipefail

BRANCH={_quote(branch)}
JOB={_quote(protection.BASE_JOB)}
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$#" -gt 1 ]; then
  echo "uso: protect.sh [SHA]" >&2
  exit 2
fi
SHA=${{1:-$(git rev-parse "origin/$BRANCH")}}
if ! [[ $SHA =~ ^[0-9a-f]{{40}}$ ]]; then
  echo "SHA non valido: serve un commit di 40 cifre esadecimali" >&2
  exit 2
fi

runs=$(gh api --paginate --jq {_quote(jq)} "repos/{{owner}}/{{repo}}/commits/$SHA/check-runs?per_page=100")
if [ -z "$runs" ]; then
  echo "check-run di $JOB non trovato sul commit $SHA: unisci prima i workflow sul ramo $BRANCH" >&2
  exit 1
fi
finished=$(printf '%s\\n' "$runs" | awk -F '\\t' '$1 == "completed" {{print $3}}' | sort -u)
if [ -z "$finished" ]; then
  echo "$JOB non è ancora finito sul commit $SHA: aspetta e rilancia" >&2
  exit 1
fi
if [ "$(printf '%s\\n' "$finished" | wc -l)" -ne 1 ]; then
  echo "il check-run di $JOB ha più app.id diversi ($finished): mi fermo" >&2
  exit 1
fi
APP_ID=$finished
if ! [[ $APP_ID =~ ^[1-9][0-9]*$ ]]; then
  echo "app.id non valido ($APP_ID): mi fermo" >&2
  exit 1
fi

body=$(mktemp)
trap 'rm -f "$body"' EXIT
sed 's/"{protection.APP_ID_PLACEHOLDER}"/'"$APP_ID"'/' "$HERE/protection.json" > "$body"
echo "Protezione di $BRANCH con app_id $APP_ID (controlli: {contexts})."
gh api --method PUT --input "$body" "repos/{{owner}}/{{repo}}/branches/$BRANCH/protection"
"""


def _estimate_lines(seconds: float | None, merges: int) -> list[str]:
    included = f"GitHub Free include {FREE_MINUTES} minuti al mese per i repo privati"
    if seconds is None:
        return ["Durata del gate non misurata: manca una ricevuta di `finish check` o `verify` "
                "per ogni comando del gate sullo stesso commit. Chiudi un lavoro con "
                "/tollgate:finish e rilancia /tollgate:init.", f"Riferimento: {included}."]
    minutes = math.ceil(seconds / 60)            # ogni job si fattura per minuti interi
    per_merge = 2 * minutes                      # base + gate
    return [f"Durata misurata del gate: {seconds:.0f} s, cioè {minutes} min fatturati per job.",
            f"Per ogni merge: base + gate = {per_merge} min (ipotesi: la suite di base dura "
            "come il gate).",
            f"Con {merges} merge al mese: {per_merge * merges} minuti al mese. {included}."]


def _readme(p: _Proposal, *, update: bool, branch: str, merges: int,
            services: dict[str, str], ports: dict[str, int], now) -> str:
    folder = FOLDER
    out = ["# Proposta di installazione di tollgate", "",
           f"Preparata il {clock.fmt(now)} da tollgate {VERSION}. I file qui sotto sono una "
           "proposta: li copi tu, tollgate non scrive mai nel repo i propri file.", "",
           "## Modalità del gate", ""]
    if p.kind == protection.DETECT:
        out.append("Repo privato con GitHub Free: la protezione del ramo non è disponibile. "
                   "Modalità `detect`: il merge non è impedito; `tollgate-sentinel` segnala a "
                   "valle i merge non verificati.")
    elif p.kind == protection.PROTECTED_UNSET:
        out.append(f"Il ramo `{branch}` non ha protezione. Modalità `protected`: "
                   "`protect.sh` la attiva (ultimo passo).")
    elif p.missing:
        out.append(f"Il ramo `{branch}` ha già una protezione, ma manca:")
        out += ["", *[f"- {m}" for m in p.missing], "",
                "`protect.sh` la porta a come serve."]
    else:
        out.append(f"Il ramo `{branch}` ha la protezione già completa: `protect.sh` non serve.")
    out += ["", "## I tuoi passi", ""]
    if update:
        out += [f"1. Crea il ramo `tollgate-config/{VERSION}` dal ramo predefinito `{branch}`.",
                f"2. Copia i file di `{folder}/files` nella radice del repo, sopra gli esistenti."]
        if p.removed:
            out.append("   Cancella i file elencati in «Da cancellare».")
        out += ["3. Fai un commit sul ramo e apri la PR: contiene solo file di tollgate, "
                "`guard` la lascia passare e `attenzione` resterà rosso, come previsto."]
        n = 4
    else:
        out += [f"1. Copia il contenuto di `{folder}/files` nella radice del repo "
                f"(per esempio `cp -R {folder}/files/. .`).",
                f"2. Fai un commit sul ramo predefinito (`{branch}`) e spingilo, prima di "
                "attivare la protezione: il commit fa partire `tollgate-base`."]
        if p.from_template:
            out.insert(len(out) - 1, "   `tollgate.toml` viene dal modello: compila `[commands]` "
                       "(`setup`, `verify`, `report`) prima del commit.")
        n = 3
    if (p.kind == protection.PROTECTED_UNSET) or p.missing:
        out.append(f"{n}. Quando `{protection.BASE_JOB}` è finito su quel commit, lancia "
                   f"`bash {folder}/protect.sh` dalla radice del repo con le tue credenziali "
                   "(non quelle dell'agente). Se il commit non è la punta di "
                   f"`origin/{branch}`, passa lo SHA come primo argomento.")
    elif p.mode == "detect":
        out.append(f"{n}. Nessuna protezione da attivare: in `detect` la verifica avviene dopo "
                   "il merge, con `tollgate-sentinel`.")
    out += ["", "## Stima dei minuti di Actions", "", *_estimate_lines(p.seconds, merges)]
    if services:
        out += ["", "## Servizi", "",
                "Messi in ogni job che esegue la suite del progetto (`head` e `base` di "
                "`tollgate-run`, `ids` di `tollgate-base`):", ""]
        for name, image in services.items():
            port = f", porta {ports[name]} esposta sull'host" if name in ports else \
                ", nessuna porta esposta"
            out.append(f"- `{name}`: `{image}`{port}")
    if p.violations:
        out += ["", "## Workflow già presenti che violano le regole di `guard`", "",
                "`guard` controlla solo i workflow nuovi o modificati: questi esistono già e "
                "restano fuori dal controllo. Valutali tu (per esempio `statuses: write` su "
                "`pull_request` esegue il codice della PR con un token di scrittura).", ""]
        out += [prbody.neutralize("\n".join(f"{rel}: {problem}"
                                            for rel, problem in p.violations))]
    if p.removed:
        out += ["", "## Da cancellare", "",
                "File di tollgate presenti sul predefinito e assenti da questa versione "
                "(da cancellare):", "", prbody.neutralize("\n".join(p.removed))]
    if p.jest:
        out += ["", "## jest-junit", "",
                "Con la configurazione predefinita due test omonimi in file diversi hanno lo "
                "stesso identificativo. Metti il file nell'identificativo:", "",
                "```json", '"jest-junit": {', '  "classNameTemplate": "{filepath}",',
                '  "titleTemplate": "{classname} {title}"', "}", "```", "",
                "(chiave di primo livello di `package.json`)."]
        if not p.jest_junit:
            out.append("`jest-junit` non risulta tra le dipendenze: `npm install --save-dev "
                       "jest-junit`.")
    out += ["", "## Token dell'agente", "",
            "Per l'agente usa un token GitHub separato dal tuo, con soli permessi su contenuti, "
            "pull request e issue: senza amministrazione e senza `project`. Con il tuo token "
            "l'agente potrebbe cambiare la protezione del ramo.", ""]
    return "\n".join(out)


def _write(top: Path, readme: str, files: dict[str, bytes], protect: tuple[str, str] | None
           ) -> Path:
    """Scrive la proposta sostituendo la precedente: `files/`, `README.md`, `protect.sh` e
    `protection.json` si rifanno, il resto della cartella non si tocca."""
    folder = top / FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    tree = folder / "files"
    if tree.is_symlink():
        tree.unlink()
    elif tree.exists():
        shutil.rmtree(tree)
    for name in ("README.md", "protect.sh", "protection.json"):
        (folder / name).unlink(missing_ok=True)
    for rel, data in files.items():
        target = tree / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (folder / "README.md").write_text(readme, encoding="utf-8")
    if protect is not None:
        script, body = protect
        (folder / "protection.json").write_text(body, encoding="utf-8")
        (folder / "protect.sh").write_text(script, encoding="utf-8")
        (folder / "protect.sh").chmod(0o755)
    return folder


def propose(state: State, cwd: Path, *, update: bool, merges_per_month: int,
            services: dict[str, str], ports: dict[str, int] | None = None, now=None
            ) -> InitResult:
    now = now or clock.now()
    ports = ports or {}
    try:
        install.validate_services(services, ports)
    except ValueError as e:
        return _refuse(str(e))
    top = git.toplevel(cwd)
    if top is None:
        return _refuse("la cartella corrente non è in un repo git")
    main = git.main_worktree(top)
    url = git.origin_url(main)
    if not url:
        return _refuse("il repo non ha il remote origin")
    notes = []
    if not gitw.fetch(main):
        notes.append("senza rete (git fetch origin non riuscito): uso l'ultimo stato noto di "
                     "origin")
    default = git.default_branch(main)
    ref = f"origin/{default}" if default else None
    if not ref or not git.resolve_ref(main, ref):
        return _refuse("origin non ha un ramo predefinito con almeno un commit")

    read = protection.read(state, main, default)
    mode = _mode_for(read.kind)
    if mode is None:
        return _refuse(
            "modalità del gate non determinata: la protezione del ramo non si legge con queste "
            f"credenziali ({read.note or 'risposta non riconosciuta'}).",
            "Rilancia /tollgate:init con le tue credenziali di `gh` (amministrazione del repo), "
            "non con il token dell'agente. Non scelgo `protected` per esclusione.")

    current = git.text_at(main, ref, "tollgate.toml")
    if update and current is None:
        return _refuse(f"manca tollgate.toml su {ref}: usa /tollgate:init --propose")
    base_text = current if current is not None else TEMPLATE.read_text(encoding="utf-8")
    toml = with_mode(base_text, mode)
    try:
        config.load_config_text(toml)
    except config.ConfigError as e:
        return _refuse(f"tollgate.toml non è valido dopo la scelta della modalità: {e}")
    try:
        tree = install.files(PLUGIN_ROOT, default_branch=default, services=services, ports=ports)
    except ValueError as e:
        return _refuse(str(e))
    tree["tollgate.toml"] = toml.encode("utf-8")

    removed: list[str] = []
    if update:
        removed = sorted(rel for rel in git.ls_files_at(main, ref, install.INSTALL_DIR + "/")
                         if rel not in tree)
        tree = {rel: data for rel, data in tree.items() if git.show(main, ref, rel) != data}
        if not tree and not removed:
            lines = [*[f"avviso: {n}" for n in notes],
                     f"nulla da aggiornare: i file di tollgate su {ref} sono quelli della "
                     f"versione {VERSION} (modalità {mode})"]
            if read.kind == protection.PROTECTED_UNSET:
                lines.append(f"il ramo {default} è senza protezione: lancia "
                             "/tollgate:init --propose per ottenere protect.sh")
            lines += [f"protezione incompleta: manca {m}" for m in read.missing]
            if read.missing:
                lines.append("lancia /tollgate:init --propose per ottenere protect.sh")
            return InitResult(OK, lines)

    jest, jest_junit = _jest(main, ref)
    proposal = _Proposal(
        mode=mode, kind=read.kind, missing=read.missing, files=tree, removed=removed,
        violations=_existing_violations(main, ref), jest=jest, jest_junit=jest_junit,
        from_template=current is None, seconds=_gate_seconds(state, repo_key(url), _gate_commands(toml)))
    protect = (_protect_script(default), protection.body_template()) \
        if mode == "protected" and (read.kind == protection.PROTECTED_UNSET or read.missing) \
        else None
    readme = _readme(proposal, update=update, branch=default, merges=merges_per_month,
                     services=services, ports=ports, now=now)
    folder = _write(Path(top), readme, tree, protect)

    shown = folder.relative_to(top).as_posix()
    lines = [f"avviso: {n}" for n in notes]
    lines.append(f"modalità del gate: {mode}"
                 + (" (ramo senza protezione: la attiva protect.sh)"
                    if read.kind == protection.PROTECTED_UNSET else ""))
    lines += [f"protezione incompleta: manca {m}" for m in read.missing]
    lines += [f"workflow esistente fuori regola: {_plain(rel)}: {_plain(problem)}"
              for rel, problem in proposal.violations]
    lines.append(f"proposta scritta in {shown}/ ({len(tree)} file)"
                 + (f"; ramo suggerito tollgate-config/{VERSION}" if update else ""))
    lines.append(f"leggi {shown}/README.md: i passi li fai tu, tollgate non scrive i suoi file "
                 "nel repo")
    return InitResult(OK, lines, folder)
