"""Prerequisiti di `start` (spec 6.1 passo 0, decisioni 7, 8 e 16)."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from tollgate_core import git
from tollgate_core.paths import repo_key

SUPERPOWERS_RANGE = ((6, 4, 1), (8, 0, 0))  # >= 6.4.1 e < 8.0.0
SUPERPOWERS_KEY = "superpowers@claude-plugins-official"
GATE_VERSION_FILE = ".github/tollgate/VERSION"
GATE_FILES = tuple(f".github/workflows/tollgate-{n}.yml"
                   for n in ("guard", "run", "verdict", "base", "sentinel")) + (GATE_VERSION_FILE,)
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _registry(claude_dir: Path) -> dict:
    """`plugins` di `installed_plugins.json` (versione 2); {} se assente o di altra forma."""
    try:
        data = json.loads((Path(claude_dir) / "plugins" / "installed_plugins.json")
                          .read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    plugins = data.get("plugins") if isinstance(data, dict) else None
    return plugins if isinstance(plugins, dict) else {}


def _entries(plugins: dict, key: str) -> list[dict]:
    value = plugins.get(key)
    return [e for e in value if isinstance(e, dict)] if isinstance(value, list) else []


def _parse_version(text) -> tuple[int, int, int] | None:
    m = _VERSION.match(text) if isinstance(text, str) else None
    return tuple(int(x) for x in m.groups()) if m else None


def superpowers_version(claude_dir: Path) -> tuple[int, int, int] | None:
    """Versione di Superpowers: prima la chiave esatta, poi `superpowers@*`; la più alta."""
    plugins = _registry(claude_dir)
    keys = [SUPERPOWERS_KEY] + sorted(k for k in plugins
                                      if k.startswith("superpowers@") and k != SUPERPOWERS_KEY)
    for key in keys:
        versions = [v for v in (_parse_version(e.get("version")) for e in _entries(plugins, key))
                    if v]
        if versions:
            return max(versions)
    return None


def gate_status(repo, ref: str) -> tuple[list[str], str | None]:
    """File del gate mancanti sul riferimento, e la versione scritta in `VERSION`."""
    missing = [f for f in GATE_FILES if not git.exists_at(repo, ref, f)]
    text = git.text_at(repo, ref, GATE_VERSION_FILE)
    return missing, (text.strip() or None) if text is not None else None


def is_github(repo) -> bool:
    """`remote.origin.url` grezzo: `git remote get-url` espande `insteadOf` (e nei test dà un
    percorso locale). La chiave del repo resta `repo_key(git.origin_url(repo))`."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "config", "--get", "remote.origin.url"],
                           capture_output=True, text=True, timeout=git.GIT_TIMEOUT_S,
                           stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return False
    url = r.stdout.strip()
    return r.returncode == 0 and bool(url) and repo_key(url).startswith("github.com/")


def skill_installed(name: str, *, claude_dir: Path, worktree: Path | None) -> bool:
    """Decisione 16: `<installPath>/skills/<nome>/SKILL.md` per `plugin:nome`, poi
    `~/.claude/skills/<nome>` e `<worktree>/.claude/skills/<nome>`."""
    plugin, sep, skill = name.rpartition(":")
    if not _SAFE_NAME.match(skill) or (sep and not _SAFE_NAME.match(plugin)):
        return False
    if sep:
        plugins = _registry(claude_dir)
        for key in plugins:
            if key.partition("@")[0] != plugin:
                continue
            for entry in _entries(plugins, key):
                path = entry.get("installPath")
                if isinstance(path, str) and (Path(path) / "skills" / skill / "SKILL.md").is_file():
                    return True
        return False
    roots = [Path(claude_dir) / "skills"] + ([Path(worktree) / ".claude" / "skills"]
                                             if worktree else [])
    return any((root / skill / "SKILL.md").is_file() for root in roots)
