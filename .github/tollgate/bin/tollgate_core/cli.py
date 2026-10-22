"""Sottocomandi di bin/tollgate (spec 3.1): radice di composizione, importa anche il flusso."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import VERSION, clock, db, events, git, phases, stats, verify
from .paths import repo_key, resolve_state


class UsageError(Exception):
    pass


def current_repo_key(cwd: Path) -> str | None:
    r = subprocess.run(["git", "-C", str(cwd), "remote", "get-url", "origin"],
                       capture_output=True, text=True)
    url = r.stdout.strip()
    return repo_key(url) if r.returncode == 0 and url else None


def _date(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise argparse.ArgumentTypeError("data attesa nella forma AAAA-MM-GG") from e


def _issue_number(value: str) -> int:
    try:
        n = int(value.lstrip("#"))
    except ValueError as e:
        raise argparse.ArgumentTypeError("numero di issue atteso (7 oppure #7)") from e
    if n < 1:
        raise argparse.ArgumentTypeError("numero di issue atteso (7 oppure #7)")
    return n


def _positive(value: str) -> int:
    try:
        n = int(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError("numero intero atteso") from e
    if n < 1:
        raise argparse.ArgumentTypeError("serve un numero maggiore di zero")
    return n


def _service(value: str) -> tuple[str, str, int | None]:
    """`NOME=IMMAGINE` o `NOME=IMMAGINE,PORTA` (la virgola, perché i due punti sono del tag
    dell'immagine). Qui solo la forma: i caratteri ammessi li controlla `init`."""
    name, eq, rest = value.partition("=")
    image, comma, port = rest.partition(",")
    if not eq or not name or not image or (comma and not port.isascii()) \
            or (comma and not port.isdigit()):
        raise argparse.ArgumentTypeError(
            "forma attesa: NOME=IMMAGINE oppure NOME=IMMAGINE,PORTA (porta in sole cifre)")
    return name, image, int(port) if comma else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tollgate", description="CLI di tollgate",
        epilog="gate: il gate su GitHub (run, base-ids, ...), senza stato; aiuto in `gate -h`")
    p.add_argument("--version", action="version", version=f"tollgate {VERSION}")
    sub = p.add_subparsers(dest="cmd")
    st = sub.add_parser("status", help="stato dei lavori attivi (sola lettura)")
    st.add_argument("--json", action="store_true", help="uscita in JSON")
    st.add_argument("--checkpoint", action="store_true",
                    help="scrive il checkpoint nel worktree del lavoro (6.3)")
    st.add_argument("--note", metavar="TESTO", help="nota da aggiungere al checkpoint")
    sp = sub.add_parser("stats", help="statistiche dagli eventi, in JSON")
    sp.add_argument("--since", type=_date, metavar="AAAA-MM-GG")
    sp.add_argument("--work", type=int, metavar="N", help="numero dell'issue nel repo corrente")
    ep = sub.add_parser("events", help="eventi in JSONL dopo un seq")
    ep.add_argument("--after-seq", type=int, default=0, metavar="N")
    dp = sub.add_parser("db", help="manutenzione del DB")
    dsub = dp.add_subparsers(dest="db_cmd", required=True)
    dsub.add_parser("restore", help="ripristina l'ultima copia integra (solo da terminale)")
    sa = sub.add_parser("start", help="avvia o riprende il lavoro su un'issue (6.1)")
    sa.add_argument("issue", type=_issue_number, metavar="N")
    sa.add_argument("--level", choices=("L1", "L2"), help="livello scelto dall'utente")
    sa.add_argument("--spec", metavar="PERCORSO",
                    help="fetta successiva di una spec già approvata sul ramo predefinito (5)")
    sa.add_argument("--confirm", action="store_true",
                    help="conferma gli avvisi che la prima chiamata ha elencato (codice 3)")
    sa.add_argument("--reopen-execution", action="store_true",
                    help="in review o pr_open riporta la fase a execution")
    ip = sub.add_parser("init", help="misura la modalità del gate e propone i file (11.2)")
    imode = ip.add_mutually_exclusive_group(required=True)
    imode.add_argument("--propose", action="store_true",
                       help="propone l'installazione in docs/superpowers/tollgate-init/")
    imode.add_argument("--update", action="store_true",
                       help="propone solo i file che differiscono dal ramo predefinito")
    ip.add_argument("--merges-per-month", type=_positive, default=20, metavar="N",
                    help="merge al mese per la stima dei minuti (predefinito 20)")
    ip.add_argument("--service", action="append", default=[], type=_service,
                    metavar="NOME=IMMAGINE[,PORTA]",
                    help="servizio per i test in tollgate-run; con PORTA è raggiungibile "
                         "dal job sull'host (porta:porta)")
    tp = sub.add_parser("task", help="task del piano (6.3)")
    tsub = tp.add_subparsers(dest="task_cmd", required=True)
    ts = tsub.add_parser("start", help="assegna il task a un implementatore e scrive il brief")
    ts.add_argument("number", type=int, metavar="K", nargs="?")
    ts.add_argument("--from-findings", type=int, metavar="CICLO",
                    help="task di correzione dai rilievi bloccanti del ciclo")
    ts.add_argument("--from-gate", action="store_true",
                    help="task di correzione dall'ultimo commento del gate sulla PR")
    ts.add_argument("--fix", action="store_true", help="giro di correzione dopo un verdetto")
    tr = tsub.add_parser("review-prepare", help="prepara diff e brief del revisore del task")
    tr.add_argument("number", type=int, metavar="K")
    td = tsub.add_parser("done", help="chiude il task approvato dal revisore")
    td.add_argument("number", type=int, metavar="K")
    ap = sub.add_parser("act", help="atti dell'utente (8.4)")
    asub = ap.add_subparsers(dest="act_cmd", required=True)
    aa = asub.add_parser("apply", help="applica un atto registrato (resolve, approve level)")
    aa.add_argument("act_id", nargs="?", metavar="ID", help="senza id: l'ultimo atto pending")
    fp = sub.add_parser("finish", help="chiusura del lavoro (6.4)")
    fsub = fp.add_subparsers(dest="finish_cmd", required=True)
    fsub.add_parser("check", help="copia locale del gate: la DoD voce per voce; verde = review")
    fo = fsub.add_parser("open-pr", help="spinge lo SHA e apre o aggiorna la PR (6.4)")
    fo.add_argument("--update", action="store_true", help="richiede una PR già aperta")
    rp = sub.add_parser("review", help="revisione finale (6.4, 8.6)")
    rsub = rp.add_subparsers(dest="review_cmd", required=True)
    rsub.add_parser("prepare", help="apre o riprende il ciclo e scrive i brief dei revisori")
    aup = sub.add_parser("audit", help="giri di audit di spec e piano in L2 (6.2)")
    ausub = aup.add_subparsers(dest="audit_cmd", required=True)
    aprep = ausub.add_parser("prepare", help="decide il prossimo giro e scrive i brief degli agenti")
    aprep.add_argument("--confirm", action="store_true",
                       help="conferma il costo dell'audit a lenti (la prima chiamata esce con 3)")
    ausub.add_parser("decline", help="l'utente rifiuta il costo dell'audit a lenti")
    sub.add_parser("sync", help="rimette il ramo sul predefinito e aggiorna la PR (6.5)")
    ad = sub.add_parser("adopt", help="ricostruisce un lavoro dal ramo tg/<N>-* (12.4)")
    ad.add_argument("issue", type=_issue_number, metavar="N")
    ab = sub.add_parser("abandon", help="chiude un lavoro senza unirlo (12.4)")
    ab.add_argument("issue", type=_issue_number, metavar="N")
    cl = sub.add_parser("cleanup", help="toglie rami e worktree dei lavori chiusi (12.4)")
    cl.add_argument("--confirm", action="store_true",
                    help="toglie davvero; senza, elenca soltanto (codice 3)")
    cl.add_argument("--orphans", action="store_true",
                    help="include i rami tg/<N>-* senza lavoro nel DB")
    hp = sub.add_parser("hook", help="solo per hooks/run: adattatore per Claude Code")
    hp.add_argument("event", metavar="evento")
    vp = sub.add_parser("verify", help="esegue i comandi del gate e registra le ricevute (8.1)")
    vp.add_argument("--related", action="store_true",
                    help="solo i test correlati ai file cambiati")
    wp = sub.add_parser("waiver", help="deroghe (8.3)")
    wsub = wp.add_subparsers(dest="waiver_cmd", required=True)
    wa = wsub.add_parser("add", help="dichiara una deroga in .tollgate/waivers/<N>.toml")
    wa.add_argument("type", metavar="tipo")
    wa.add_argument("file", nargs="?", metavar="file")
    wa.add_argument("--pattern", metavar="GLOB")
    wa.add_argument("--test", action="append", default=[], metavar="ID")
    wa.add_argument("--choice", required=True)
    wa.add_argument("--why", required=True)
    wa.add_argument("--cost", required=True)
    bp = sub.add_parser("block", help="blocchi del lavoro (8.3)")
    bsub = bp.add_subparsers(dest="block_cmd", required=True)
    bo = bsub.add_parser("open", help="apre un blocco; lo chiude l'utente")
    bo.add_argument("type", metavar="tipo")
    bo.add_argument("--reason", required=True)
    return p


def _status(conn, key: str | None) -> list[dict]:
    from tollgate_flow import checkpoint
    sql, params = "SELECT * FROM work_items WHERE phase <> 'closed'", []
    if key:
        sql += " AND repo_key = ?"
        params.append(key)
    out = []
    for w in conn.execute(sql + " ORDER BY repo_key, issue", params).fetchall():
        blocks = [{"id": b["id"], "type": b["type"], "reason": b["reason"]}
                  for b in conn.execute("SELECT id, type, reason FROM blocks WHERE work = ? "
                                        "AND closed IS NULL ORDER BY id", (w["id"],))]
        counts = {r["state"]: r["n"] for r in conn.execute(
            "SELECT state, count(*) AS n FROM tasks WHERE work = ? GROUP BY state", (w["id"],))}
        out.append({"issue": w["issue"], "repo_key": w["repo_key"], "level": w["level"],
                    "level_cap": w["level_cap"], "phase": w["phase"],
                    "phase_before_block": w["phase_before_block"], "branch": w["branch"],
                    "blocks": blocks, "tasks": counts,
                    "stopped_by": checkpoint.stopped_by(conn, w["id"])})
    return out


def _print_status(items: list[dict]) -> None:
    if not items:
        print("nessun lavoro attivo")
        return
    for it in items:
        phase = it["phase"]
        if phase == "blocked":
            phase += f" (prima: {it['phase_before_block']})"
        print(f"#{it['issue']} {it['repo_key']}  fase {phase}  livello {it['level']}")
        if it["tasks"]:
            print("  task: " + ", ".join(f"{n} {s}" for s, n in sorted(it["tasks"].items())))
        for b in it["blocks"]:
            print(f"  blocco {b['id']} ({b['type']}): {b['reason']}")
        for s in it["stopped_by"]:
            print(f"  {s}")


def _restore(state) -> int:
    interactive = sys.stdin.isatty() and sys.stdout.isatty()

    def confirm(question: str) -> bool:
        return input(question).strip().lower() in ("s", "si", "sì", "y", "yes")

    print(db.restore(state, interactive=interactive, confirm=confirm))
    return 0


def _stats(conn, args) -> int:
    work = None
    if args.work is not None:
        key = current_repo_key(Path.cwd())
        if key is None:
            raise UsageError("--work richiede di essere in un repo con origin")
        row = phases.find_latest(conn, key, args.work)
        if row is None:
            raise UsageError(f"nessun lavoro per #{args.work} in {key}")
        work = row["id"]
    result = stats.compute_stats(conn, now=clock.now(), work=work, since=args.since)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _hook_argv(argv: list[str], cmd: str) -> list[str]:
    """Gli argomenti dal sottocomando in poi, come li registra l'hook di PreToolUse."""
    return argv[argv.index(cmd):]


def _external_errors() -> tuple[type[Exception], ...]:
    """Errori di git e di gh nei sottocomandi del flusso: un messaggio, mai un traceback."""
    from tollgate_flow import gh, gitw
    return (gh.GhError, git.GitError, gitw.GitWriteError)


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.print_help()
        return 0
    if args.cmd == "hook":
        from tollgate_hooks.runner import run_hook
        r = run_hook(args.event, sys.stdin.read(), alarm=True)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.exit
    if args.cmd == "status" and args.note is not None and not args.checkpoint:
        parser.error("--note si usa con --checkpoint")
    state = resolve_state()
    try:
        if args.cmd == "db":
            return _restore(state)
        if args.cmd == "verify":
            code, lines = verify.run_verify(state, Path.cwd(), related=args.related)
            print("\n".join(lines))
            return code
        if args.cmd == "start":
            from tollgate_flow import start as flow_start
            result = flow_start.start(state, Path.cwd(), args.issue, level=args.level,
                                      confirm=args.confirm, spec=args.spec,
                                      reopen_execution=args.reopen_execution,
                                      claude_dir=Path.home() / ".claude",
                                      argv=_hook_argv(argv, args.cmd))
            print("\n".join(result.lines))
            return result.code
        if args.cmd == "init":
            from tollgate_flow import init as flow_init
            names = [n for n, _, _ in args.service]
            if len(names) != len(set(names)):
                parser.error("--service: nome ripetuto")
            made = flow_init.propose(
                state, Path.cwd(), update=args.update,
                merges_per_month=args.merges_per_month,
                services={n: image for n, image, _ in args.service},
                ports={n: port for n, _, port in args.service if port is not None})
            print("\n".join(made.lines))
            return made.code
        if args.cmd == "sync":
            from tollgate_flow import sync as flow_sync
            synced = flow_sync.sync(state, Path.cwd(), argv=_hook_argv(argv, args.cmd))
            print("\n".join(synced.lines))
            return synced.code
        if args.cmd == "adopt":
            from tollgate_flow import adopt as flow_adopt
            adopted = flow_adopt.adopt(state, Path.cwd(), args.issue,
                                       argv=_hook_argv(argv, args.cmd))
            print("\n".join(adopted.lines))
            return adopted.code
        if args.cmd in ("abandon", "cleanup"):
            from tollgate_flow import closing
            if args.cmd == "abandon":
                code, lines = closing.abandon(state, Path.cwd(), args.issue,
                                              argv=_hook_argv(argv, args.cmd))
            else:
                code, lines = closing.cleanup(state, Path.cwd(), confirm=args.confirm,
                                              orphans=args.orphans,
                                              argv=_hook_argv(argv, args.cmd))
            print("\n".join(lines))
            return code
        if args.cmd == "task":
            from tollgate_flow import taskcmd
            try:
                if args.task_cmd == "review-prepare":
                    print(taskcmd.review_prepare(state, Path.cwd(), args.number))
                    print(f"revisore: {taskcmd.reviewer_type(state, Path.cwd(), args.number)}")
                elif args.task_cmd == "done":
                    print(taskcmd.task_done(state, Path.cwd(), args.number))
                elif args.from_findings is not None or args.from_gate:
                    from tollgate_flow import fixtask
                    if (args.number is not None or args.fix
                            or (args.from_findings is not None and args.from_gate)):
                        print("tollgate: --from-findings, --from-gate e K (con --fix) si "
                              "escludono a vicenda", file=sys.stderr)
                        return 2
                    claude_dir = Path.home() / ".claude"
                    path, summary = fixtask.from_gate(
                        state, Path.cwd(), claude_dir=claude_dir) if args.from_gate \
                        else fixtask.from_findings(state, Path.cwd(), args.from_findings,
                                                   claude_dir=claude_dir)
                    print(f"{path}\n{summary}")
                elif args.number is None:
                    print("tollgate: serve il numero del task, oppure --from-findings o "
                          "--from-gate", file=sys.stderr)
                    return 2
                else:
                    path, summary = taskcmd.task_start(state, Path.cwd(), args.number,
                                                       fix=args.fix,
                                                       claude_dir=Path.home() / ".claude")
                    print(f"{path}\n{summary}")
            except taskcmd.TaskError as e:
                print(f"tollgate: {e}", file=sys.stderr)
                return 1
            return 0
        if args.cmd == "act":
            from tollgate_flow import actapply
            try:
                print(actapply.apply_act(state, Path.cwd(), args.act_id,
                                              argv=_hook_argv(argv, args.cmd)))
            except actapply.ActApplyError as e:
                print(f"tollgate: {e}", file=sys.stderr)
                return 1
            return 0
        if args.cmd == "finish":
            if args.finish_cmd == "open-pr":
                from tollgate_flow import openpr
                opened = openpr.open_pr(state, Path.cwd(), update=args.update,
                                        argv=_hook_argv(argv, args.cmd))
                print("\n".join(opened.lines))
                return opened.code
            from tollgate_flow import finishcheck
            result = finishcheck.check(state, Path.cwd())
            print("\n".join(result.lines))
            return result.code
        if args.cmd == "review":
            from tollgate_flow import finalreview
            try:
                print("\n".join(finalreview.prepare(state, Path.cwd()).lines))
            except finalreview.ReviewError as e:
                print(f"tollgate: {e}", file=sys.stderr)
                return 1
            return 0
        if args.cmd == "audit":
            from tollgate_flow import audit
            try:
                if args.audit_cmd == "prepare":
                    prepared = audit.prepare(state, Path.cwd(), confirm=args.confirm)
                    print("\n".join(prepared.lines))
                    return prepared.code
                code, lines = audit.decline(state, Path.cwd())
            except audit.AuditError as e:
                print(f"tollgate: {e}", file=sys.stderr)
                return 1
            print("\n".join(lines))
            return code
        if args.cmd == "waiver":
            from . import waiver_cli
            print(waiver_cli.add_waiver(state, Path.cwd(), type_=args.type, file=args.file,
                                        pattern=args.pattern, tests=args.test,
                                        choice=args.choice, why=args.why, cost=args.cost))
            return 0
        if args.cmd == "block":
            from . import waiver_cli
            print(waiver_cli.open_block_cmd(state, Path.cwd(), type_=args.type,
                                            reason=args.reason))
            return 0
        if args.cmd == "status":
            if not state.db_path.exists():
                # sola lettura: senza DB non si crea nulla
                if args.checkpoint:
                    print("tollgate: nessun lavoro attivo per questa cartella: lancia il "
                          "comando dal worktree del lavoro", file=sys.stderr)
                    return 1
                print("[]" if args.json else "nessun lavoro attivo")
                return 0
            if args.checkpoint:
                from tollgate_flow import checkpoint
                try:
                    print(f"checkpoint scritto: "
                          f"{checkpoint.write_checkpoint(state, Path.cwd(), note=args.note)}")
                except checkpoint.CheckpointError as e:
                    print(f"tollgate: {e}", file=sys.stderr)
                    return 1
                return 0
        conn = db.open_db(state)
        try:
            if args.cmd == "status":
                items = _status(conn, current_repo_key(Path.cwd()))
                if args.json:
                    print(json.dumps(items, ensure_ascii=False, indent=2))
                else:
                    _print_status(items)
                return 0
            if args.cmd == "stats":
                return _stats(conn, args)
            if args.cmd == "events":
                try:
                    sys.stdout.write(
                        events.to_jsonl(events.export_events(conn, args.after_seq)))
                    sys.stdout.flush()
                except BrokenPipeError:
                    # il lettore ha chiuso (| head): evita il traceback anche alla chiusura di stdout
                    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
                return 0
        finally:
            conn.close()
    except (db.DbError, UsageError, phases.TransitionError) as e:
        print(f"tollgate: {e}", file=sys.stderr)
        return 1
    except sqlite3.Error as e:
        print(f"tollgate: errore del database: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        if not isinstance(e, _external_errors()):
            raise
        print(f"tollgate: {e}", file=sys.stderr)
        return 1
    return 0
