from datetime import date
from pathlib import Path

import pytest

from depguard.lockfile import diff_locks, direct_dependencies, parse_lock
from depguard.policy import PolicyError, load_policy, policy_from_dict

LOCK_OLD = """
version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "Requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "leftpad"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
"""

LOCK_NEW = """
version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "rich"
version = "13.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "internal"
version = "0.0.1"
source = { git = "https://github.com/x/internal?rev=abc" }
"""


def test_parse_and_diff():
    old, new = parse_lock(LOCK_OLD), parse_lock(LOCK_NEW)
    assert old["requests"].version == "2.31.0"
    assert new["internal"].source_kind == "git"
    diff = diff_locks(old, new)
    assert [p.name for p in diff.added] == ["internal", "rich"]
    assert [(o.version, n.version) for o, n in diff.upgraded] == [("2.31.0", "2.32.0")]
    assert [p.name for p in diff.removed] == ["leftpad"]
    assert {p.name for p in diff.to_vet} == {"internal", "rich", "requests"}
    assert new["rich"].spec == "rich==13.0"


def test_direct_dependencies(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["FastAPI>=0.1", "pydantic[email]>=2"]
[project.optional-dependencies]
obs = ["sentry-sdk"]
[dependency-groups]
dev = ["pytest", {include-group = "lint"}]
lint = ["ruff"]
"""
    )
    assert direct_dependencies(pyproject) == {"fastapi", "pydantic", "sentry-sdk", "pytest", "ruff"}


def test_policy_loading(tmp_path: Path):
    assert load_policy(tmp_path / "missing.toml").min_project_age_days == 90
    policy = policy_from_dict(
        {
            "policy": {"min_project_age_days": 10},
            "packages": {"denied": ["Bad_Pkg"], "trusted": ["requests"]},
            "vulnerabilities": {
                "ignore": [{"id": "GHSA-1", "reason": "r", "expires": "2030-01-01"}]
            },
            "exceptions": [
                {"package": "Foo", "rule": "license", "reason": "r", "expires": date(2030, 1, 1)}
            ],
        }
    )
    assert policy.min_project_age_days == 10
    assert "bad-pkg" in policy.denied_packages
    assert policy.vulnerability_is_ignored("GHSA-1")
    assert policy.exception_for("foo", "license") is not None
    assert policy.exception_for("foo", "other") is None


def test_policy_errors(tmp_path: Path):
    bad = tmp_path / "depguard.toml"
    bad.write_text("exceptions = [{package = 'x'}]")
    with pytest.raises(PolicyError, match="missing"):
        load_policy(bad)
    bad.write_text("exceptions = [{package='x', rule='r', reason='r', expires='soon'}]")
    with pytest.raises(PolicyError, match="ISO date"):
        load_policy(bad)
    bad.write_text("this is not toml")
    with pytest.raises(PolicyError):
        load_policy(bad)
