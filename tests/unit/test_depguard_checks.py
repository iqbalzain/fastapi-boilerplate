from datetime import UTC, date, datetime, timedelta

import pytest

from depguard.checks import Level, VetContext, apply_exceptions, parse_spec, vet_package
from depguard.http import NetworkError
from depguard.osv import Vulnerability
from depguard.policy import Policy, PolicyException
from depguard.pypi import PackageInfo, Release

NOW = datetime(2026, 11, 1, tzinfo=UTC)


def release(version: str, days_ago: int, *, yanked: bool = False, wheel: bool = True) -> Release:
    return Release(
        version=version,
        uploaded_at=NOW - timedelta(days=days_ago),
        yanked=yanked,
        has_wheel=wheel,
        filenames=(f"pkg-{version}-py3-none-any.whl",),
    )


def package(name="goodpkg", releases=None, **overrides) -> PackageInfo:
    releases = releases or (release("1.0", 400), release("1.1", 200), release("1.2", 30))
    fields = {
        "name": name,
        "summary": "A fine package",
        "license": "MIT",
        "classifiers": ("License :: OSI Approved :: MIT License",),
        "requires_python": ">=3.9",
        "project_urls": {"Source": "https://github.com/x/goodpkg"},
        "requires_dist": ("httpx>=0.27",),
        "releases": releases,
        "latest_version": releases[-1].version,
    }
    fields.update(overrides)
    return PackageInfo(**fields)


class FakePyPI:
    def __init__(
        self, packages: dict[str, PackageInfo], *, provenance: bool | None = True, fail=False
    ):
        self.packages = packages
        self.provenance = provenance
        self.fail = fail

    def fetch(self, name):
        if self.fail:
            raise NetworkError("boom")
        return self.packages.get(name)

    def has_provenance(self, name, version, filename):
        return self.provenance


class FakeOSV:
    def __init__(
        self, vulns: dict[tuple[str, str], tuple[Vulnerability, ...]] | None = None, fail=False
    ):
        self.vulns = vulns or {}
        self.fail = fail

    def query(self, name, version):
        if self.fail:
            raise NetworkError("osv down")
        return self.vulns.get((name, version), ())

    def query_batch(self, pins):
        return {pin: tuple(v.id for v in self.vulns[pin]) for pin in pins if pin in self.vulns}


def ctx(packages=None, policy: Policy | None = None, osv=None, pypi=None) -> VetContext:
    packages = packages if packages is not None else {"goodpkg": package()}
    return VetContext(
        policy=policy or Policy(),
        pypi=pypi or FakePyPI(packages),
        osv=osv or FakeOSV(),
        now=NOW,
    )


def rules(result, level=None):
    return {f.rule for f in result.findings if level is None or f.level is level}


def test_parse_spec():
    assert parse_spec("Requests[security]==2.31.0") == ("requests", "2.31.0")
    assert parse_spec("httpx>=0.27") == ("httpx", None)
    with pytest.raises(ValueError, match="not a valid requirement"):
        parse_spec("==1.0")


def test_clean_package_passes_and_resolves_cooled_down_version():
    result = vet_package("goodpkg", ctx())
    assert not result.failed, result.findings
    assert result.resolved_version == "1.2"
    assert "provenance" in rules(result, Level.PASS)


def test_cooldown_selects_older_version_when_latest_is_fresh():
    pkg = package(releases=(release("1.0", 400), release("1.1", 200), release("2.0", 2)))
    result = vet_package("goodpkg", ctx({"goodpkg": pkg}))
    assert result.resolved_version == "1.1"
    assert result.suggestion == "goodpkg==1.1"

    pinned = vet_package("goodpkg==2.0", ctx({"goodpkg": pkg}))
    assert pinned.failed
    assert "min_version_age_days" in rules(pinned, Level.FAIL)


def test_young_project_and_few_releases_fail():
    pkg = package(releases=(release("0.1", 2),))
    result = vet_package("goodpkg", ctx({"goodpkg": pkg}))
    assert {"min_project_age_days", "min_release_count", "min_version_age_days"} <= rules(
        result, Level.FAIL
    )


def test_trusted_packages_skip_heuristics_but_not_vulns():
    pkg = package(releases=(release("0.1", 10),))
    vuln = Vulnerability("GHSA-1", "bad", ("CVE-2026-1",), ("0.2",), "HIGH")
    policy = Policy(trusted_packages=frozenset({"goodpkg"}))
    result = vet_package(
        "goodpkg", ctx({"goodpkg": pkg}, policy=policy, osv=FakeOSV({("goodpkg", "0.1"): (vuln,)}))
    )
    assert "min_project_age_days" not in rules(result)
    assert "vulnerability" in rules(result, Level.FAIL)
    assert any("fixed in 0.2" in f.message for f in result.findings)


def test_ignored_vulnerability_is_informational():
    vuln = Vulnerability("GHSA-1", "bad", (), (), None)
    from depguard.policy import IgnoredVulnerability

    policy = Policy(
        ignored_vulnerabilities=(IgnoredVulnerability("GHSA-1", "unreachable", NOW.date()),)
    )
    result = vet_package("goodpkg", ctx(policy=policy, osv=FakeOSV({("goodpkg", "1.2"): (vuln,)})))
    assert not result.failed
    assert "vulnerability" in rules(result, Level.INFO)


def test_yanked_sdist_license_and_python_checks():
    pkg = package(
        releases=(
            release("1.0", 400),
            release("1.1", 200),
            release("1.2", 30, yanked=True, wheel=False),
        ),
        license="GNU Affero General Public License v3",
        classifiers=(),
        requires_python=">=3.13",
        project_urls={},
        requires_dist=tuple(f"dep{i}" for i in range(40)),
    )
    result = vet_package(
        "goodpkg==1.2", ctx({"goodpkg": pkg}, policy=Policy(denied_licenses=("AGPL", "Affero")))
    )
    failed = rules(result, Level.FAIL)
    assert {"yanked", "require_wheel", "license", "python_version"} <= failed
    assert {"repository_url", "max_direct_dependencies"} <= rules(result, Level.WARN)


def test_missing_package_denied_package_and_typosquat():
    assert "exists" in rules(vet_package("nonexistent-thing-xyz", ctx()), Level.FAIL)
    assert "denied_package" in rules(
        vet_package("badpkg", ctx(policy=Policy(denied_packages=frozenset({"badpkg"})))), Level.FAIL
    )
    result = vet_package("requets", ctx({}))
    assert "typosquat" in rules(result, Level.FAIL)


def test_network_failure_fails_closed_or_warns():
    closed = vet_package("goodpkg", ctx(pypi=FakePyPI({}, fail=True)))
    assert "network" in rules(closed, Level.FAIL)
    open_ = vet_package(
        "goodpkg", ctx(pypi=FakePyPI({}, fail=True), policy=Policy(fail_on_network_error=False))
    )
    assert "network" in rules(open_, Level.WARN)
    osv_down = vet_package("goodpkg", ctx(osv=FakeOSV(fail=True)))
    assert "network" in rules(osv_down, Level.FAIL)


def test_exceptions_downgrade_failures_until_expiry():
    pkg = package(releases=(release("0.1", 10),))
    exc = PolicyException(
        "goodpkg", "min_project_age_days", "first-party lib", NOW.date() + timedelta(days=30)
    )
    policy = Policy(exceptions=(exc,))
    result = vet_package("goodpkg", ctx({"goodpkg": pkg}, policy=policy))
    levels = {f.rule: f.level for f in result.findings}
    assert levels["min_project_age_days"] is Level.WARN
    assert levels["min_release_count"] is Level.FAIL

    from depguard.checks import Finding

    expired = Policy(exceptions=(PolicyException("goodpkg", "x", "r", date(2000, 1, 1)),))
    out = apply_exceptions("goodpkg", [Finding("x", Level.FAIL, "m")], expired)
    assert out[0].level is Level.FAIL
