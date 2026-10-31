"""Minimal PEP 440 version parsing and specifier matching (no third-party deps)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_VERSION_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d*))?
    (?:(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d*)))?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d*))?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.IGNORECASE | re.VERBOSE,
)

_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_INF = 10**9


class InvalidVersionError(ValueError):
    pass


@total_ordering
@dataclass(frozen=True, slots=True)
class Version:
    epoch: int
    release: tuple[int, ...]
    pre: tuple[int, int] | None
    post: int | None
    dev: int | None
    raw: str

    @property
    def is_prerelease(self) -> bool:
        return self.pre is not None or self.dev is not None

    @property
    def major(self) -> int:
        return self.release[0]

    @property
    def minor(self) -> int:
        return self.release[1] if len(self.release) > 1 else 0

    def _key(self) -> tuple[object, ...]:
        release = _strip_trailing_zeros(self.release)
        if self.pre is None and self.post is None and self.dev is not None:
            pre: tuple[int, ...] = (-_INF,)
        elif self.pre is None:
            pre = (_INF,)
        else:
            pre = self.pre
        post = -_INF if self.post is None else self.post
        dev = _INF if self.dev is None else self.dev
        return (self.epoch, release, pre, post, dev)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __str__(self) -> str:
        return self.raw


def _strip_trailing_zeros(release: tuple[int, ...]) -> tuple[int, ...]:
    out = list(release)
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return tuple(out)


def parse_version(text: str) -> Version:
    match = _VERSION_RE.match(text)
    if not match:
        raise InvalidVersionError(text)
    g = match.groupdict()
    pre = None
    if g["pre_l"]:
        pre = (_PRE_RANK[g["pre_l"].lower()], int(g["pre_n"] or 0))
    post = None
    if g["post_n1"]:
        post = int(g["post_n1"])
    elif g["post_l"]:
        post = int(g["post_n2"] or 0)
    dev = int(g["dev_n"] or 0) if g["dev_l"] else None
    return Version(
        epoch=int(g["epoch"] or 0),
        release=tuple(int(p) for p in g["release"].split(".")),
        pre=pre,
        post=post,
        dev=dev,
        raw=text.strip(),
    )


def try_parse_version(text: str) -> Version | None:
    try:
        return parse_version(text)
    except InvalidVersionError:
        return None


def bump_kind(current: Version, latest: Version) -> str:
    """Classify an upgrade as ``major``, ``minor``, ``patch`` or ``none``."""
    if latest <= current:
        return "none"
    if latest.major != current.major:
        return "major"
    if latest.minor != current.minor:
        return "minor"
    return "patch"


_SPEC_RE = re.compile(r"^\s*(?P<op>===|==|!=|~=|<=|>=|<|>)\s*(?P<ver>[^\s,]+)\s*$")


def _matches_clause(version: Version, op: str, target: str) -> bool | None:
    if target.endswith(".*"):
        prefix = tuple(int(p) for p in target[:-2].split(".") if p.isdigit())
        equal = version.release[: len(prefix)] == prefix
        return equal if op == "==" else not equal if op == "!=" else True
    other = try_parse_version(target)
    if other is None:
        return None
    if op == "~=":
        floor = other.release[:-1] if len(other.release) > 1 else other.release
        return version >= other and version.release[: len(floor)] == floor
    return {
        "==": version == other,
        "===": version.raw == other.raw,
        "!=": version != other,
        "<=": version <= other,
        ">=": version >= other,
        "<": version < other,
        ">": version > other,
    }[op]


def satisfies(version_text: str, specifier: str | None) -> bool | None:
    """Return True/False, or None when the specifier cannot be interpreted."""
    if not specifier or not specifier.strip():
        return True
    version = try_parse_version(version_text)
    if version is None:
        return None
    for clause in specifier.split(","):
        match = _SPEC_RE.match(clause)
        if not match:
            return None
        verdict = _matches_clause(version, match.group("op"), match.group("ver"))
        if verdict is None:
            return None
        if not verdict:
            return False
    return True
