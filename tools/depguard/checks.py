"""Policy checks applied to a single package/version.

Keep this package compatible with Python 3.11+: the Claude Code hook runs it with
whatever ``python3`` is on PATH, before the project venv exists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import TYPE_CHECKING

from depguard.http import NetworkError
from depguard.names import affix_variant_of, normalize, typosquat_candidates
from depguard.osv import OSVClient
from depguard.pypi import PackageInfo, PyPIClient, Release
from depguard.versions import satisfies

if TYPE_CHECKING:
    from collections.abc import Callable

    from depguard.policy import Policy


class Level(IntEnum):
    PASS = 0
    INFO = 1
    WARN = 2
    FAIL = 3

    @property
    def symbol(self) -> str:
        return {0: "✓", 1: "i", 2: "⚠", 3: "✗"}[int(self)]


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    level: Level
    message: str


@dataclass(frozen=True, slots=True)
class VetResult:
    package: str
    requested_version: str | None
    resolved_version: str | None
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @property
    def worst(self) -> Level:
        return max((f.level for f in self.findings), default=Level.PASS)

    @property
    def failed(self) -> bool:
        return self.worst is Level.FAIL

    @property
    def suggestion(self) -> str:
        if self.resolved_version and self.requested_version != self.resolved_version:
            return f"{self.package}=={self.resolved_version}"
        return self.package


@dataclass(frozen=True, slots=True)
class VetContext:
    policy: Policy
    pypi: PyPIClient
    osv: OSVClient
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    check_provenance: bool = True


_SPEC_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?P<spec>.*)$")
_PIN_RE = re.compile(r"===?\s*(?P<ver>[^\s,;]+)")
_REPO_HOSTS = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org", "sr.ht")


def parse_spec(spec: str) -> tuple[str, str | None]:
    """``"Requests[security]==2.31.0"`` → ``("requests", "2.31.0")``."""
    match = _SPEC_RE.match(spec)
    if not match:
        raise ValueError(f"not a valid requirement: {spec!r}")
    pin = _PIN_RE.search(match.group("spec"))
    return normalize(match.group("name")), pin.group("ver") if pin else None


# --- individual checks --------------------------------------------------------
if TYPE_CHECKING:
    Check = Callable[[PackageInfo, Release, VetContext], Finding | None]


def _age_days(moment: datetime | None, now: datetime) -> int | None:
    return None if moment is None else (now - moment).days


def check_project_age(info: PackageInfo, _: Release, ctx: VetContext) -> Finding | None:
    age = _age_days(info.first_upload, ctx.now)
    rule = "min_project_age_days"
    if age is None:
        return Finding(rule, Level.WARN, "no upload timestamps available")
    if age < ctx.policy.min_project_age_days:
        return Finding(
            rule,
            Level.FAIL,
            f"project is only {age} days old (min {ctx.policy.min_project_age_days})",
        )
    return Finding(rule, Level.PASS, f"project first published {age} days ago")


def check_release_count(info: PackageInfo, _: Release, ctx: VetContext) -> Finding | None:
    count = len(info.releases)
    rule = "min_release_count"
    if count < ctx.policy.min_release_count:
        return Finding(
            rule, Level.FAIL, f"only {count} release(s) (min {ctx.policy.min_release_count})"
        )
    return Finding(rule, Level.PASS, f"{count} releases")


def check_maintained(info: PackageInfo, _: Release, ctx: VetContext) -> Finding | None:
    age = _age_days(info.last_upload, ctx.now)
    rule = "max_days_since_last_release"
    if age is not None and age > ctx.policy.max_days_since_last_release:
        return Finding(
            rule, Level.WARN, f"last release was {age} days ago; project may be abandoned"
        )
    return Finding(rule, Level.PASS, f"last release {age} days ago")


def check_version_cooldown(_: PackageInfo, release: Release, ctx: VetContext) -> Finding | None:
    age = _age_days(release.uploaded_at, ctx.now)
    rule = "min_version_age_days"
    if age is None:
        return Finding(rule, Level.WARN, f"{release.version}: upload time unknown")
    if age < ctx.policy.min_version_age_days:
        return Finding(
            rule,
            Level.FAIL,
            f"{release.version} was published {age} day(s) ago; "
            f"cooldown is {ctx.policy.min_version_age_days} days",
        )
    return Finding(rule, Level.PASS, f"{release.version} published {age} days ago")


def check_yanked(_: PackageInfo, release: Release, __: VetContext) -> Finding | None:
    if release.yanked:
        return Finding(
            "yanked", Level.FAIL, f"{release.version} has been yanked by its maintainers"
        )
    return None


def check_wheel(_: PackageInfo, release: Release, ctx: VetContext) -> Finding | None:
    if not release.has_wheel:
        level = Level.FAIL if ctx.policy.require_wheel else Level.WARN
        return Finding(
            "require_wheel",
            level,
            f"{release.version} is sdist-only (setup.py executes at install)",
        )
    return None


def _license_text(info: PackageInfo) -> str:
    classifiers = [c for c in info.classifiers if c.startswith("License ::")]
    return " | ".join(filter(None, [info.license, *classifiers]))


def check_license(info: PackageInfo, _: Release, ctx: VetContext) -> Finding | None:
    text = _license_text(info)
    lowered = text.lower()
    if not text:
        return Finding("license", Level.WARN, "no license metadata published")
    denied = [d for d in ctx.policy.denied_licenses if d.lower() in lowered]
    if denied:
        return Finding("license", Level.FAIL, f"license {text!r} matches denied term(s) {denied}")
    if any(a.lower() in lowered for a in ctx.policy.allowed_licenses):
        return Finding("license", Level.PASS, text[:80])
    return Finding("license", Level.WARN, f"license {text!r} is not on the allow-list; review it")


def check_repository_url(info: PackageInfo, _: Release, __: VetContext) -> Finding | None:
    urls = " ".join(info.project_urls.values()).lower()
    if any(host in urls for host in _REPO_HOSTS):
        return None
    return Finding("repository_url", Level.WARN, "no public source repository linked in metadata")


def check_python_compat(info: PackageInfo, _: Release, ctx: VetContext) -> Finding | None:
    ok = satisfies(ctx.policy.python_version, info.requires_python)
    if ok is False:
        return Finding(
            "python_version",
            Level.FAIL,
            f"requires-python {info.requires_python!r} excludes {ctx.policy.python_version}",
        )
    if ok is None:
        return Finding(
            "python_version",
            Level.WARN,
            f"could not interpret requires-python {info.requires_python!r}",
        )
    return None


def check_dependency_count(info: PackageInfo, _: Release, ctx: VetContext) -> Finding | None:
    runtime = [d for d in info.requires_dist if "extra ==" not in d]
    if len(runtime) > ctx.policy.max_direct_dependencies:
        return Finding(
            "max_direct_dependencies",
            Level.WARN,
            f"pulls in {len(runtime)} direct runtime dependencies",
        )
    return None


def check_provenance(info: PackageInfo, release: Release, ctx: VetContext) -> Finding | None:
    if not ctx.check_provenance:
        return None
    wheels = [f for f in release.filenames if f.endswith(".whl")] or list(release.filenames)
    if not wheels:
        return None
    attested = ctx.pypi.has_provenance(info.name, release.version, wheels[0])
    if attested is True:
        return Finding("provenance", Level.PASS, "PEP 740 attestation present (Trusted Publishing)")
    if attested is False:
        return Finding(
            "provenance", Level.INFO, "no PEP 740 attestation; build provenance unverifiable"
        )
    return None


HEURISTIC_CHECKS: tuple[Check, ...] = (
    check_project_age,
    check_release_count,
    check_maintained,
    check_repository_url,
    check_dependency_count,
)
ALWAYS_CHECKS: tuple[Check, ...] = (
    check_version_cooldown,
    check_yanked,
    check_wheel,
    check_license,
    check_python_compat,
    check_provenance,
)


# --- orchestration ------------------------------------------------------------
def _typosquat_findings(name: str, ctx: VetContext) -> list[Finding]:
    hits = typosquat_candidates(name, max_distance=ctx.policy.typosquat_max_distance)
    findings = [
        Finding("typosquat", Level.FAIL, f"{name!r} looks like {known!r} ({reason})")
        for known, reason in hits
    ]
    variant = affix_variant_of(name)
    if variant:
        findings.append(
            Finding(
                "typosquat",
                Level.WARN,
                f"{name!r} is an affix variant of {variant!r}; confirm it is the intended package",
            )
        )
    return findings


def _resolve_release(info: PackageInfo, requested: str | None, ctx: VetContext) -> Release | None:
    if requested is not None:
        return info.release(requested)
    cutoff = ctx.now - timedelta(days=ctx.policy.min_version_age_days)
    return info.latest_stable_before(cutoff) or info.release(info.latest_version)


def _vulnerability_findings(name: str, version: str, ctx: VetContext) -> list[Finding]:
    findings = []
    for vuln in ctx.osv.query(name, version):
        if ctx.policy.vulnerability_is_ignored(vuln.id):
            findings.append(
                Finding("vulnerability", Level.INFO, f"{vuln.display_id} ignored by policy")
            )
            continue
        level = Level.FAIL if ctx.policy.block_on_vulnerability else Level.WARN
        fix = f"; fixed in {', '.join(vuln.fixed_versions)}" if vuln.fixed_versions else ""
        sev = f" [{vuln.severity}]" if vuln.severity else ""
        findings.append(
            Finding("vulnerability", level, f"{vuln.display_id}{sev}: {vuln.summary}{fix}")
        )
    return findings or [Finding("vulnerability", Level.PASS, f"no known advisories for {version}")]


def apply_exceptions(package: str, findings: list[Finding], policy: Policy) -> list[Finding]:
    out = []
    for finding in findings:
        exc = policy.exception_for(package, finding.rule) if finding.level is Level.FAIL else None
        if exc:
            out.append(
                Finding(
                    finding.rule,
                    Level.WARN,
                    f"{finding.message} (exception: {exc.reason}, until {exc.expires})",
                )
            )
        else:
            out.append(finding)
    return out


def vet_package(spec: str, ctx: VetContext) -> VetResult:
    name, requested = parse_spec(spec)
    if name in ctx.policy.denied_packages:
        return VetResult(
            name,
            requested,
            None,
            (Finding("denied_package", Level.FAIL, "package is on the deny-list"),),
        )

    trusted = name in ctx.policy.trusted_packages
    findings: list[Finding] = [] if trusted else _typosquat_findings(name, ctx)

    try:
        info = ctx.pypi.fetch(name)
    except NetworkError as exc:
        level = Level.FAIL if ctx.policy.fail_on_network_error else Level.WARN
        return VetResult(
            name,
            requested,
            None,
            (*findings, Finding("network", level, f"could not reach PyPI: {exc}")),
        )
    if info is None:
        return VetResult(
            name,
            requested,
            None,
            (*findings, Finding("exists", Level.FAIL, "package not found on PyPI")),
        )

    release = _resolve_release(info, requested, ctx)
    if release is None:
        return VetResult(
            name,
            requested,
            None,
            (*findings, Finding("exists", Level.FAIL, f"version {requested!r} not found")),
        )

    checks = ALWAYS_CHECKS if trusted else (*HEURISTIC_CHECKS, *ALWAYS_CHECKS)
    findings.extend(f for check in checks if (f := check(info, release, ctx)) is not None)
    try:
        findings.extend(_vulnerability_findings(name, release.version, ctx))
    except NetworkError as exc:
        level = Level.FAIL if ctx.policy.fail_on_network_error else Level.WARN
        findings.append(Finding("network", level, f"could not reach OSV: {exc}"))

    return VetResult(
        name, requested, release.version, tuple(apply_exceptions(name, findings, ctx.policy))
    )
