"""Read ``uv.lock`` / ``pyproject.toml`` and diff lock states."""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - fixed argv, never shell=True
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from depguard.names import normalize

LOCK_PATH = Path("uv.lock")
PYPROJECT_PATH = Path("pyproject.toml")
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


@dataclass(frozen=True, slots=True)
class LockedPackage:
    name: str
    version: str
    source_kind: str  # registry | editable | directory | git | url | path | unknown
    source: str

    @property
    def is_registry(self) -> bool:
        return self.source_kind == "registry"

    @property
    def spec(self) -> str:
        return f"{self.name}=={self.version}"


@dataclass(frozen=True, slots=True)
class LockDiff:
    added: tuple[LockedPackage, ...]
    upgraded: tuple[tuple[LockedPackage, LockedPackage], ...]
    removed: tuple[LockedPackage, ...]

    @property
    def to_vet(self) -> tuple[LockedPackage, ...]:
        return (*self.added, *(new for _, new in self.upgraded))


def _source(entry: dict[str, Any]) -> tuple[str, str]:
    source = entry.get("source") or {}
    for kind in ("registry", "editable", "directory", "git", "url", "path", "virtual"):
        if kind in source:
            return kind, str(source[kind])
    return "unknown", ""


def parse_lock(text: str) -> dict[str, LockedPackage]:
    data = tomllib.loads(text)
    packages: dict[str, LockedPackage] = {}
    for entry in data.get("package", []):
        kind, src = _source(entry)
        pkg = LockedPackage(normalize(entry["name"]), str(entry.get("version", "")), kind, src)
        packages[pkg.name] = pkg
    return packages


def read_lock(path: Path = LOCK_PATH) -> dict[str, LockedPackage]:
    return parse_lock(path.read_text(encoding="utf-8"))


def _git_executable() -> str:
    return shutil.which("git") or "git"


def lock_at_ref(ref: str, path: Path = LOCK_PATH) -> dict[str, LockedPackage] | None:
    """Lock contents at a git ref, or ``None`` if the file did not exist there."""
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [_git_executable(), "show", f"{ref}:{path.as_posix()}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    return parse_lock(result.stdout)


def diff_locks(old: dict[str, LockedPackage], new: dict[str, LockedPackage]) -> LockDiff:
    added = tuple(pkg for name, pkg in sorted(new.items()) if name not in old)
    removed = tuple(pkg for name, pkg in sorted(old.items()) if name not in new)
    upgraded = tuple(
        (old[name], pkg)
        for name, pkg in sorted(new.items())
        if name in old and old[name].version != pkg.version
    )
    return LockDiff(added=added, upgraded=upgraded, removed=removed)


def _names(requirements: list[str]) -> set[str]:
    names = set()
    for req in requirements:
        match = _REQ_NAME_RE.match(req)
        if match:
            names.add(normalize(match.group(1)))
    return names


def direct_dependencies(path: Path = PYPROJECT_PATH) -> frozenset[str]:
    """Names declared in [project] deps, optional-dependencies and dependency-groups."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    names = _names(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        names |= _names(extra)
    for group in data.get("dependency-groups", {}).values():
        names |= _names([g for g in group if isinstance(g, str)])
    return frozenset(names)
