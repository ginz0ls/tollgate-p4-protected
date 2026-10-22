"""plan-check (spec 7.5): intestazioni, scope dai task, must-have legati ai test."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import globs, profiles as prof

TEST_SEP = "— test:"
SKILL_CAP = 3
_SECTION = re.compile(r"^## (.+?)\s*$")
_TASK = re.compile(r"^### Task (\d+)\b[:.]?\s*(.*)$")
_FILE = re.compile(r"^\s*[-*]\s*(Create|Modify|Test):\s*(.+?)\s*$")
_TASK_MH = re.compile(r"^\s*\**Must-have\**:\**\s*(.+?)\s*$")
_MH = re.compile(r"^\s*(?:[-*]\s*)?\**(M\d+)\**\.\**\s*(.+?)\s*$")
_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_PAREN_AT = re.compile(r"(?:\s*\([^)]*\))?")
_HEADING = re.compile(r"^#{2,3} ")
_RANGE = re.compile(r":\d+(?:-\d+)?$")


@dataclass
class PlanTask:
    number: int
    title: str
    files: list[str] = field(default_factory=list)
    must_haves: list[str] | None = None
    test_files: list[str] = field(default_factory=list)


@dataclass
class MustHave:
    id: str
    text: str
    tests: list[str]


@dataclass
class PlanCheck:
    problems: list[str]
    warnings: list[str]
    scope: list[str]
    tasks: list[PlanTask]
    must_haves: list[MustHave]

    @property
    def ok(self) -> bool:
        return not self.problems


def _file_value(raw: str) -> str:
    value = _RANGE.sub("", raw.strip())
    return value[2:] if value.startswith("./") else value


_ITEM = re.compile(r"`([^`]+)`|([^\s,`]+)")
_SEP = re.compile(r"\s*(?:,|\s(?:e|and)\s)\s*")


def _file_values(raw: str) -> list[str]:
    """Una riga `Create:` porta uno o più file: l'elenco iniziale, di voci tra apici inversi o
    nude separate da virgole (o «e»). Si ferma al primo testo che non è una voce dell'elenco
    (trattino lungo, prosa); una parentesi di commento dopo una voce si salta."""
    out: list[str] = []
    pos = 0
    while True:
        m = _ITEM.match(raw, pos)
        if not m:
            break
        out.append(_file_value(m.group(1) or m.group(2)))
        pos = _PAREN_AT.match(raw, m.end()).end()
        sep = _SEP.match(raw, pos)
        if not sep:
            break
        pos = sep.end()
    return out


class _Fences:
    """Recinti di codice (CommonMark): apre ``` o ~~~ (3 o più); chiude solo lo stesso carattere,
    con lunghezza almeno pari e nient'altro sulla riga."""

    def __init__(self) -> None:
        self.marker: str | None = None

    def inside(self, line: str) -> bool:
        """True se la riga è un recinto (di apertura o chiusura) o sta dentro uno."""
        m = _FENCE_OPEN.match(line)
        if self.marker is None:
            if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
                self.marker = m.group(1)
                return True
            return False
        if m and m.group(1)[0] == self.marker[0] and len(m.group(1)) >= len(self.marker) \
                and not m.group(2).strip():
            self.marker = None
        return True


def _parse(text: str):
    sections: list[str] = []
    tasks: list[PlanTask] = []
    mh_lines: list[str] = []
    current_section, task = None, None
    fences = _Fences()
    for line in text.splitlines():
        if fences.inside(line):
            continue
        m = _SECTION.match(line)
        if m:
            current_section, task = m.group(1), None
            sections.append(current_section)
            continue
        m = _TASK.match(line)
        if m:
            task = PlanTask(int(m.group(1)), m.group(2).strip())
            tasks.append(task)
            continue
        if line.startswith("### "):
            task = None
            continue
        if task is not None:
            fm = _FILE.match(line)
            if fm:
                values = _file_values(fm.group(2))
                task.files.extend(values)
                if fm.group(1) == "Test":
                    task.test_files.extend(values)
                continue
            mm = _TASK_MH.match(line)
            if mm:
                task.must_haves = [x.strip() for x in mm.group(1).split(",") if x.strip()]
                continue
        if current_section == "Must-have" and task is None:
            mh_lines.append(line)
    return sections, tasks, mh_lines


def task_text(text: str, number: int) -> str | None:
    """Il testo di `### Task <number>` fino all'intestazione `##` o `###` successiva, esclusa.
    Le intestazioni dentro i recinti non chiudono il task."""
    fences = _Fences()
    out: list[str] | None = None
    for line in text.splitlines():
        if fences.inside(line):
            if out is not None:
                out.append(line)
            continue
        if out is not None:
            if _HEADING.match(line):
                break
            out.append(line)
            continue
        m = _TASK.match(line)
        if m and int(m.group(1)) == number:
            out = [line]
    return "\n".join(out).rstrip() if out is not None else None


def _must_haves(lines: list[str]) -> list[MustHave]:
    out = []
    for line in lines:
        m = _MH.match(line)
        if not m:
            continue
        body = m.group(2)
        if TEST_SEP in body:
            text, tests = body.split(TEST_SEP, 1)
            ids = [t.strip().strip("`") for t in tests.split(",") if t.strip()]
        else:
            text, ids = body, []
        out.append(MustHave(m.group(1), text.strip(), ids))
    return out


def check_plan(text: str, *, required_sections, max_scope_files: int, must_have_tests: bool,
               level: str, profiles: dict[str, dict], active_always) -> PlanCheck:
    problems: list[str] = []
    warnings: list[str] = []
    sections, tasks, mh_lines = _parse(text)
    scope = list(dict.fromkeys(f for t in tasks for f in t.files))
    active = prof.active_profiles(scope, profiles, active_always)
    needed = list(required_sections) + [s for n in active
                                         for s in profiles[n].get("plan_sections", [])]
    for s in dict.fromkeys(needed):
        if s not in sections:
            problems.append(f"manca la sezione «## {s}»")
    if not tasks:
        problems.append("nessun task (intestazioni «### Task N»)")
    for f in scope:
        if globs.is_pattern(f) or f.endswith("/"):
            problems.append(f"pattern o cartella non ammessi nello scope: {f}")
    if len(scope) > max_scope_files:
        problems.append(f"scope di {len(scope)} file, oltre il massimo di {max_scope_files}")
    must_haves = _must_haves(mh_lines)
    for kind, ids in (("", [m.id for m in must_haves]), ("task ", [t.number for t in tasks])):
        for i in dict.fromkeys(i for i in ids if ids.count(i) > 1):
            problems.append(f"{kind}{i} duplicato")
    if must_have_tests and level in ("L1", "L2"):
        if not must_haves:
            problems.append("nessun must-have nella sezione «## Must-have»")
        for mh in must_haves:
            if not mh.tests:
                problems.append(f"{mh.id} senza test: scrivi «{TEST_SEP} <classname::name>» "
                                f"oppure «{TEST_SEP} manuale»")
    known = {mh.id for mh in must_haves}
    for t in tasks:
        for ref in t.must_haves or []:
            if ref not in known:
                problems.append(f"task {t.number}: must-have {ref} inesistente")
        skills = prof.task_skills(t.files, profiles)
        if len(skills) > SKILL_CAP:
            warnings.append(f"task {t.number}: {len(skills)} skill dai profili (massimo "
                            f"{SKILL_CAP}): {', '.join(skills)}; il task va diviso")
    return PlanCheck(problems, warnings, scope, tasks, must_haves)
