"""Package-name normalisation and typosquatting heuristics."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_NORMALIZE_RE = re.compile(r"[-_.]+")
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
_AFFIXES = ("python-", "py-", "py", "-python", "-py", "python")
_DATA_FILE = Path(__file__).parent / "data" / "top_packages.txt"


def normalize(name: str) -> str:
    """PEP 503 normalisation."""
    return _NORMALIZE_RE.sub("-", name).lower().strip()


def skeleton(name: str) -> str:
    """Collapse visually-confusable characters so ``requ3sts`` ≈ ``requests``."""
    return normalize(name).translate(_HOMOGLYPHS).replace("-", "")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


@lru_cache(maxsize=1)
def top_packages() -> frozenset[str]:
    if not _DATA_FILE.exists():
        return frozenset()
    names: set[str] = set()
    for line in _DATA_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            names.update(normalize(token) for token in line.split())
    return frozenset(names)


def strip_affixes(name: str) -> str:
    for affix in _AFFIXES:
        if name.startswith(affix) and len(name) > len(affix) + 1:
            return name[len(affix) :].strip("-")
        if name.endswith(affix) and len(name) > len(affix) + 1:
            return name[: -len(affix)].strip("-")
    return name


def typosquat_candidates(
    name: str, *, max_distance: int, known: frozenset[str] | None = None
) -> list[tuple[str, str]]:
    """Return ``(known_package, reason)`` pairs this name is suspiciously close to."""
    known = known if known is not None else top_packages()
    target = normalize(name)
    if target in known:
        return []
    target_skeleton = skeleton(target)
    hits: list[tuple[str, str]] = []
    for candidate in sorted(known):
        if skeleton(candidate) == target_skeleton:
            hits.append((candidate, "homoglyph/separator variant"))
            continue
        if abs(len(candidate) - len(target)) > max_distance:
            continue
        distance = levenshtein(target, candidate)
        if 0 < distance <= max_distance:
            hits.append((candidate, f"edit distance {distance}"))
    return hits


def affix_variant_of(name: str, known: frozenset[str] | None = None) -> str | None:
    known = known if known is not None else top_packages()
    target = normalize(name)
    if target in known:
        return None
    stripped = strip_affixes(target)
    return stripped if stripped != target and stripped in known else None
