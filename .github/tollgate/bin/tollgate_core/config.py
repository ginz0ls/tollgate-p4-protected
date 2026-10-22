"""Caricamento e validazione di tollgate.toml (spec 11.4, 12.2, 3.2)."""
from __future__ import annotations

import copy
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .paths import State, test_env

SCHEMA_VERSION = 1
_AREA_READONLY = re.compile(r"^[^:]+:(reviewer|final)-")


class ConfigError(Exception):
    pass


class ConfigNotFound(ConfigError):
    pass


DEFAULTS: dict = {
    "schema_version": SCHEMA_VERSION,
    "project": {"allow_no_tests": False},
    "commands": {
        "setup": "", "verify": "", "test_related": "", "gate": ["verify"],
        "report": "", "report_related": "",
        "env_allow": ["PATH", "HOME", "LANG", "CI", "NODE_ENV"], "timeout_s": 900,
    },
    "gate": {"mode": ""},
    "acts": {"ttl_minutes": 10},
    "hooks": {"timeout_s": 20},
    "levels": {
        "sensitive_paths": ["**/migrations/**", "**/auth/**"],
        "sensitive_labels": ["security", "database"],
        "l0_max_files": 2, "l0_max_lines": 50, "l0_max_bytes": 4000,
    },
    "context": {"warn_pct": 45, "stop_pct": 55},
    "plan": {
        "required_sections": ["Fatti verificati", "Decisioni", "Interfacce", "Must-have",
                              "Scope", "Punti di arresto", "Rischi"],
        "max_scope_files": 30,
    },
    "scope": {
        "always": [],
        "lockfiles": {"package-lock.json": "package.json", "pnpm-lock.yaml": "package.json",
                      "poetry.lock": "pyproject.toml"},
    },
    "external_effects": {"commands": [], "project_scripts": ["deploy", "release"],
                         "allow": [], "mcp_allow": []},
    "test_guard": {
        "test_globs": [],
        "fixture_globs": ["**/fixtures/**/*.json", "**/__snapshots__/**"],
        "ci_globs": [".github/workflows/**"],
        "verification_globs": [
            "**/vitest.config.*", "**/vitest.setup.*", "**/jest.config.*", "**/playwright.config.*",
            "**/.mocharc.*", "**/conftest.py", "**/pytest.ini", "**/tox.ini", "**/setupTests.*",
            "**/.coveragerc", "**/.nycrc*", "**/cypress.config.*", "**/karma.conf.*",
            "**/.env.test", "scripts/check*"],
        "verification_watch": [
            "**/package.json", "**/vite.config.*", "**/tsconfig*.json", "**/setup.cfg",
            "**/pyproject.toml", "**/Makefile", "**/.babelrc", "**/babel.config.*",
            "**/.swcrc", "**/.npmrc"],
        "skip_markers": [], "assert_markers": [],
    },
    "spec_audit": {"spec_rounds": 4, "plan_rounds": 2, "spec_audit_cycles": 30},
    "tasks": {"task_lines_warn": 200, "task_lines_max": 500, "task_files_warn": 8,
              "max_turns": 60, "max_tokens": {"L0": 0, "L1": 400000, "L2": 800000}},
    "review": {
        "readonly_agents": ["tollgate:task-reviewer", "tollgate:final-reviewer",
                            "tollgate:finding-verifier", "tollgate:plan-adversary",
                            "tollgate:spec-adversary", "tollgate:spec-auditor", "Explore"],
        "output_dirs": ["reports/", "coverage/"], "max_findings": 15,
        "stale_minutes": 30, "models": {},
    },
    "severity": {
        "blocker": "perdita o esposizione di dati, azione eseguita due volte, sicurezza compromessa",
        "major": "un comportamento sbagliato o un passo che fallirebbe così com'è",
        "moderate": "debito o attrito che emergerà più avanti",
        "minor": "redazionale",
    },
    "retention": {"retention_days": 30, "events_days": 180},
    "profiles": {"active": []},
    "components": {k: True for k in (
        "scope_check", "plan_check", "test_guard", "context_guard", "subagent_receipt_gate",
        "single_writer", "readonly_check", "final_review", "spec_adversary", "spec_audit",
        "plan_adversary", "base_test_ids", "sentinel", "task_size", "task_budget",
        "definition_of_done", "must_have_tests", "report_fields", "reviewer_standard",
        "spec_pitch")},
}

PROFILE_DEFAULTS: dict = {
    "kind": "vertical", "cross": [], "paths": ["**"], "setup": "", "commands": {}, "gate": [],
    "test_related": "", "report": "", "test_globs": [], "skip_markers": [],
    "assert_markers": [], "plan_sections": [], "min_level": "L0", "dod": [], "checklist": "",
    "skills": [], "agent": "", "reviewer": "", "reviewer_skills": [], "final_specialist": "",
    "rules": [], "blocking_rules": [],
}

# Chiave del profilo -> forma del nome dell'agente `<plugin>:<forma>-<area>` (decisione 9).
AGENT_FORMS = {"agent": "implementer", "reviewer": "reviewer", "final_specialist": "final"}

# Chiavi con un tipo che il valore predefinito non descrive.
_STR_MAP = "mappa di stringhe"
_INT_MAP = "mappa di interi"
_STR_OR_MAP = "stringa o mappa di stringhe"
_SPECIAL = {
    "commands.report": _STR_OR_MAP, "tasks.max_tokens": _INT_MAP, "review.models": _STR_MAP,
    "scope.lockfiles": _STR_MAP, "profiles.*.commands": _STR_MAP, "profiles.*.report": _STR_OR_MAP,
}
_ENUMS = {"gate.mode": ("protected", "detect"), "profiles.*.kind": ("vertical", "cross"),
          "profiles.*.min_level": ("L0", "L1", "L2")}
# Sezioni che accettano chiavi nuove, con il tipo delle chiavi nuove.
_OPEN = {"commands": str, "components": bool}


@dataclass
class Config:
    data: dict
    warnings: list[str] = field(default_factory=list)

    def get(self, dotted: str):
        node = self.data
        for part in dotted.split("."):
            node = node[part]
        return node

    @property
    def profiles(self) -> dict[str, dict]:
        return {k: v for k, v in self.data["profiles"].items() if k != "active"}


def _is_str_map(v) -> bool:
    return isinstance(v, dict) and all(isinstance(x, str) for x in v.values())


def _type_ok(value, default, special: str | None) -> bool:
    if special == _STR_MAP:
        return _is_str_map(value)
    if special == _INT_MAP:
        return isinstance(value, dict) and all(
            isinstance(x, int) and not isinstance(x, bool) for x in value.values())
    if special == _STR_OR_MAP:
        return isinstance(value, str) or _is_str_map(value)
    if isinstance(default, bool):
        return isinstance(value, bool)
    if isinstance(default, int):
        return isinstance(value, int) and not isinstance(value, bool)
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        return isinstance(value, list) and all(isinstance(x, str) for x in value)
    return False


def _describe(default, special) -> str:
    if special:
        return special
    if isinstance(default, list):
        return "lista di stringhe"
    return type(default).__name__


def _set_key(table: dict, key: str, value, default, path: str, pattern: str) -> None:
    special = _SPECIAL.get(pattern)
    if not _type_ok(value, default, special):
        raise ConfigError(f"tipo sbagliato per {path}: atteso {_describe(default, special)}, "
                          f"trovato {type(value).__name__}")
    allowed = _ENUMS.get(pattern)
    if allowed and value not in allowed:
        raise ConfigError(f"valore non ammesso per {path}: {value!r} (ammessi: {', '.join(allowed)})")
    table[key] = value


def _merge_profile(name: str, raw, warnings: list[str]) -> dict:
    if not isinstance(raw, dict):
        raise ConfigError(f"tipo sbagliato per profiles.{name}: atteso una tabella")
    prof = copy.deepcopy(PROFILE_DEFAULTS)
    for key, value in raw.items():
        path = f"profiles.{name}.{key}"
        if key not in PROFILE_DEFAULTS:
            warnings.append(f"chiave sconosciuta: {path}")
            continue
        _set_key(prof, key, value, PROFILE_DEFAULTS[key], path, f"profiles.*.{key}")
    unknown = [r for r in prof["blocking_rules"] if r not in prof["rules"]]
    if unknown:
        raise ConfigError(f"profiles.{name}.blocking_rules: {', '.join(unknown)} "
                          f"non {'è' if len(unknown) == 1 else 'sono'} in profiles.{name}.rules")
    for key, form in AGENT_FORMS.items():
        value = prof[key]
        if value and not re.fullmatch(rf"[^:\s]+:{form}-[a-z0-9-]+", value):
            warnings.append(f"profilo {name}: {key} «{value}» non ha la forma "
                            f"<plugin>:{form}-<area>: uso l'agente generico")
            prof[key] = ""
    return prof


def load_config_text(text: str, source: str = "tollgate.toml") -> Config:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{source}: TOML non valido: {e}") from e
    if "schema_version" not in raw:
        raise ConfigError(f"{source}: manca schema_version")
    sv = raw["schema_version"]
    if not isinstance(sv, int) or isinstance(sv, bool):
        raise ConfigError(f"{source}: schema_version deve essere un intero")
    if sv > SCHEMA_VERSION:
        raise ConfigError(f"{source}: schema_version {sv} non supportata da questa versione di "
                          f"tollgate: aggiornare il plugin")
    if sv < 1:
        raise ConfigError(f"{source}: schema_version {sv} non valida")
    data = copy.deepcopy(DEFAULTS)
    warnings: list[str] = []
    for section, table in raw.items():
        if section == "schema_version":
            continue
        if section not in DEFAULTS:
            warnings.append(f"sezione sconosciuta: {section}")
            continue
        if not isinstance(table, dict):
            raise ConfigError(f"tipo sbagliato per {section}: atteso una tabella")
        for key, value in table.items():
            path = f"{section}.{key}"
            if section == "profiles" and key != "active":
                data["profiles"][key] = _merge_profile(key, value, warnings)
            elif key in DEFAULTS[section]:
                _set_key(data[section], key, value, DEFAULTS[section][key], path, path)
            elif section in _OPEN:
                sample = "" if _OPEN[section] is str else True
                _set_key(data[section], key, value, sample, path, path)
            else:
                warnings.append(f"chiave sconosciuta: {path}")
    declared = {k for k in data["profiles"] if k != "active"}
    for name in data["profiles"]["active"]:
        if name not in declared:
            warnings.append(f"profilo attivo non dichiarato: {name}")
    if not data["gate"]["mode"]:
        raise ConfigError(f"{source}: manca gate.mode (lo scrive /tollgate:init)")
    return Config(data, warnings)


def load_config_at(repo: Path, ref: str) -> Config:
    """Legge tollgate.toml da un riferimento git, mai dal working tree (spec 3.2)."""
    try:
        check = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            capture_output=True)
        if check.returncode != 0:
            raise ConfigError(f"riferimento git non valido: {ref}")
        r = subprocess.run(["git", "-C", str(repo), "show", f"{ref}:tollgate.toml"],
                           capture_output=True)
    except FileNotFoundError as e:
        raise ConfigError("git non disponibile") from e
    if r.returncode != 0:
        raise ConfigNotFound(f"tollgate.toml assente in {ref}")
    source = f"{ref}:tollgate.toml"
    try:
        text = r.stdout.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ConfigError(f"{source}: codifica non UTF-8") from e
    return load_config_text(text, source=source)


def load_config(state: State, repo: Path, ref: str, env=None) -> Config:
    override = test_env(state, "TOLLGATE_TEST_CONFIG", env)
    if override:
        try:
            text = Path(override).read_text(encoding="utf-8")
        except OSError as e:
            raise ConfigError(f"impossibile leggere {override}: {e.strerror}") from e
        except UnicodeDecodeError as e:
            raise ConfigError(f"{override}: codifica non UTF-8") from e
        return load_config_text(text, source=override)
    return load_config_at(repo, ref)


def is_readonly(cfg: Config, agent_type: str | None) -> bool:
    """Subagente di sola lettura (7.3): in `review.readonly_agents` o di un'area
    (`<plugin>:reviewer-*`, `<plugin>:final-*`)."""
    if not agent_type:
        return False
    return agent_type in cfg.get("review.readonly_agents") or bool(
        _AREA_READONLY.match(agent_type))


def output_excludes(cfg: Config) -> list[str]:
    """Cartelle di output (report, copertura, `.tollgate-run/`): fuori da livello e scope."""
    return list(cfg.get("review.output_dirs")) + [".tollgate-run/"]
