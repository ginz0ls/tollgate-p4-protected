"""Profili: verticale di un file, profili attivi, skill di un task (spec 6.3, 9.2, 11.4)."""
from __future__ import annotations

from dataclasses import dataclass

from . import globs

_LEVELS = ("L0", "L1", "L2")
DEFAULT_IMPLEMENTER = "tollgate:implementer"
DEFAULT_REVIEWER = "tollgate:task-reviewer"
SKILL_CAP = 3


@dataclass
class Routing:
    implementer: str
    reviewer: str
    skills: list[str]
    reviewer_skills: list[str]
    split_candidate: bool


def _score(path: str, patterns) -> int | None:
    scores = [globs.literal_segments(p) for p in patterns if globs.match(p, path)]
    return max(scores) if scores else None


def vertical_for(path: str, profiles: dict[str, dict]) -> str | None:
    """Vince il pattern con più segmenti letterali; a parità il primo dichiarato."""
    best, best_score = None, -1
    for name, prof in profiles.items():
        if prof.get("kind", "vertical") != "vertical":
            continue
        s = _score(path, prof.get("paths", []))
        if s is not None and s > best_score:
            best, best_score = name, s
    return best


def active_profiles(files, profiles: dict[str, dict], always) -> list[str]:
    files = list(files)
    return [name for name, prof in profiles.items()
            if name in always or any(globs.match_any(prof.get("paths", []), f) for f in files)]


def task_skills(files, profiles: dict[str, dict]) -> list[str]:
    skills: list[str] = []
    for f in files:
        name = vertical_for(f, profiles)
        if name:
            for s in profiles[name].get("skills", []):
                if s not in skills:
                    skills.append(s)
    return skills


def min_level(names, profiles: dict[str, dict]) -> str:
    level = "L0"
    for n in names:
        lv = profiles.get(n, {}).get("min_level", "L0")
        if lv in _LEVELS and _LEVELS.index(lv) > _LEVELS.index(level):
            level = lv
    return level


def _union(lists) -> list[str]:
    return list(dict.fromkeys(x for items in lists for x in items))


def _single(values, default: str) -> str:
    """Il valore se i verticali ne dichiarano uno solo (non vuoto), altrimenti il generico."""
    distinct = list(dict.fromkeys(v for v in values if v))
    return distinct[0] if len(distinct) == 1 else default


def task_routing(files, profiles: dict[str, dict]) -> Routing:
    """Agenti e skill di un task (spec 6.3, decisione 15): verticali dai file, ordinati come
    sono dichiarati; un solo agente dichiarato vince, altrimenti i generici."""
    found = {vertical_for(f, profiles) for f in files} - {None}
    verticals = [n for n in profiles if n in found]
    agents = [profiles[n].get("agent") for n in verticals]
    reviewers = [profiles[n].get("reviewer") for n in verticals]
    cross = _union(profiles[n].get("cross", []) for n in verticals)
    skills = _union(profiles[n].get("skills", []) for n in verticals)
    reviewer_skills = _union([profiles[n].get("reviewer_skills", []) for n in verticals]
                             + [profiles[c].get("reviewer_skills", []) for c in cross
                                if c in profiles])
    split = (len(skills) > SKILL_CAP or len(reviewer_skills) > SKILL_CAP
             or len({a for a in agents if a}) > 1 or len({r for r in reviewers if r}) > 1)
    return Routing(_single(agents, DEFAULT_IMPLEMENTER), _single(reviewers, DEFAULT_REVIEWER),
                   skills[:SKILL_CAP], reviewer_skills[:SKILL_CAP], split)


def blocking_rules(names, profiles: dict[str, dict]) -> set[str]:
    """Regole `[blocca]` dei profili `names` (decisione 8)."""
    return set(_union(profiles.get(n, {}).get("blocking_rules", []) for n in names))


def known_rules(names, profiles: dict[str, dict]) -> set[str]:
    """Regole dichiarate dai profili `names`: una `R-…` fuori da qui blocca (fail-closed)."""
    return set(_union(profiles.get(n, {}).get("rules", []) for n in names))


def final_specialists(names, profiles: dict[str, dict]) -> list[str]:
    """Specialisti finali dei profili `names`: non vuoti, in ordine, senza doppioni."""
    return _union([profiles[n]["final_specialist"]] for n in names
                  if profiles.get(n, {}).get("final_specialist"))
