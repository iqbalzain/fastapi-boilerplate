"""Load and validate ``depguard.toml``."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

DEFAULT_POLICY_PATH = Path("depguard.toml")


class PolicyError(ValueError):
    """Raised for an unreadable or inconsistent policy file."""


@dataclass(frozen=True, slots=True)
class PolicyException:
    package: str
    rule: str
    reason: str
    expires: date

    def is_active(self, today: date) -> bool:
        return today <= self.expires


@dataclass(frozen=True, slots=True)
class IgnoredVulnerability:
    id: str
    reason: str
    expires: date

    def is_active(self, today: date) -> bool:
        return today <= self.expires


@dataclass(frozen=True, slots=True)
class Policy:
    min_project_age_days: int = 90
    min_release_count: int = 3
    max_days_since_last_release: int = 730
    min_version_age_days: int = 7
    require_wheel: bool = True
    max_direct_dependencies: int = 30
    typosquat_max_distance: int = 2
    block_on_vulnerability: bool = True
    fail_on_network_error: bool = True
    python_version: str = "3.12"
    allowed_licenses: tuple[str, ...] = ("MIT", "BSD", "Apache", "PSF", "ISC", "MPL")
    denied_licenses: tuple[str, ...] = ("AGPL", "SSPL")
    denied_packages: frozenset[str] = frozenset()
    trusted_packages: frozenset[str] = frozenset()
    ignored_vulnerabilities: tuple[IgnoredVulnerability, ...] = ()
    exceptions: tuple[PolicyException, ...] = field(default_factory=tuple)

    def exception_for(
        self, package: str, rule: str, today: date | None = None
    ) -> PolicyException | None:
        today = today or datetime.now(UTC).date()
        for exc in self.exceptions:
            if exc.package == package and exc.rule == rule and exc.is_active(today):
                return exc
        return None

    def vulnerability_is_ignored(self, vuln_id: str, today: date | None = None) -> bool:
        today = today or datetime.now(UTC).date()
        return any(v.id == vuln_id and v.is_active(today) for v in self.ignored_vulnerabilities)


def _parse_date(raw: Any, context: str) -> date:
    if isinstance(raw, date):
        return raw
    try:
        return date.fromisoformat(str(raw))
    except ValueError as exc:
        raise PolicyError(f"{context}: 'expires' must be an ISO date, got {raw!r}") from exc


def _parse_exceptions(raw: list[dict[str, Any]]) -> tuple[PolicyException, ...]:
    parsed = []
    for item in raw:
        missing = {"package", "rule", "reason", "expires"} - item.keys()
        if missing:
            raise PolicyError(f"exception {item!r} is missing {sorted(missing)}")
        parsed.append(
            PolicyException(
                package=_normalize(item["package"]),
                rule=str(item["rule"]),
                reason=str(item["reason"]),
                expires=_parse_date(item["expires"], f"exception for {item['package']}"),
            )
        )
    return tuple(parsed)


def _parse_ignored(raw: list[dict[str, Any]]) -> tuple[IgnoredVulnerability, ...]:
    parsed = []
    for item in raw:
        missing = {"id", "reason", "expires"} - item.keys()
        if missing:
            raise PolicyError(f"vulnerability ignore {item!r} is missing {sorted(missing)}")
        parsed.append(
            IgnoredVulnerability(
                id=str(item["id"]),
                reason=str(item["reason"]),
                expires=_parse_date(item["expires"], f"ignore {item['id']}"),
            )
        )
    return tuple(parsed)


def _normalize(name: str) -> str:
    from depguard.names import normalize

    return normalize(name)


def load_policy(path: Path | None = None) -> Policy:
    path = path or DEFAULT_POLICY_PATH
    if not path.exists():
        return Policy()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path}: {exc}") from exc
    return policy_from_dict(data)


def policy_from_dict(data: dict[str, Any]) -> Policy:
    pol = data.get("policy", {})
    lic = data.get("licenses", {})
    pkgs = data.get("packages", {})
    vulns = data.get("vulnerabilities", {})
    defaults = Policy()
    return Policy(
        min_project_age_days=int(pol.get("min_project_age_days", defaults.min_project_age_days)),
        min_release_count=int(pol.get("min_release_count", defaults.min_release_count)),
        max_days_since_last_release=int(
            pol.get("max_days_since_last_release", defaults.max_days_since_last_release)
        ),
        min_version_age_days=int(pol.get("min_version_age_days", defaults.min_version_age_days)),
        require_wheel=bool(pol.get("require_wheel", defaults.require_wheel)),
        max_direct_dependencies=int(
            pol.get("max_direct_dependencies", defaults.max_direct_dependencies)
        ),
        typosquat_max_distance=int(
            pol.get("typosquat_max_distance", defaults.typosquat_max_distance)
        ),
        block_on_vulnerability=bool(
            pol.get("block_on_vulnerability", defaults.block_on_vulnerability)
        ),
        fail_on_network_error=bool(
            pol.get("fail_on_network_error", defaults.fail_on_network_error)
        ),
        python_version=str(pol.get("python_version", defaults.python_version)),
        allowed_licenses=tuple(lic.get("allowed", defaults.allowed_licenses)),
        denied_licenses=tuple(lic.get("denied", defaults.denied_licenses)),
        denied_packages=frozenset(_normalize(p) for p in pkgs.get("denied", [])),
        trusted_packages=frozenset(_normalize(p) for p in pkgs.get("trusted", [])),
        ignored_vulnerabilities=_parse_ignored(vulns.get("ignore", [])),
        exceptions=_parse_exceptions(data.get("exceptions", [])),
    )
