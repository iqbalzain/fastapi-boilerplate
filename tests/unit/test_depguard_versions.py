import pytest

from depguard.versions import InvalidVersionError, bump_kind, parse_version, satisfies


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0.0", "1.0.1"),
        ("1.0.dev1", "1.0a1"),
        ("1.0a1", "1.0b1"),
        ("1.0rc1", "1.0"),
        ("1.0", "1.0.post1"),
        ("1.0.post1", "1.1"),
        ("2.0", "2.0.0.1"),
        ("0!9", "1!0"),
    ],
)
def test_ordering(lower, higher):
    assert parse_version(lower) < parse_version(higher)


def test_equivalence_and_prerelease_flag():
    assert parse_version("1.0") == parse_version("1.0.0")
    assert parse_version("v1.2") == parse_version("1.2")
    assert parse_version("1.0rc1").is_prerelease
    assert not parse_version("1.0").is_prerelease
    with pytest.raises(InvalidVersionError):
        parse_version("not-a-version")


def test_bump_kind():
    v = parse_version
    assert bump_kind(v("1.2.3"), v("2.0.0")) == "major"
    assert bump_kind(v("1.2.3"), v("1.3.0")) == "minor"
    assert bump_kind(v("1.2.3"), v("1.2.4")) == "patch"
    assert bump_kind(v("1.2.3"), v("1.2.3")) == "none"


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("3.12", ">=3.8", True),
        ("3.12", ">=3.8,<3.12", False),
        ("3.12", "!=3.12.*", False),
        ("3.12.1", "==3.12.*", True),
        ("3.12", "~=3.10", True),
        ("4.0", "~=3.10", False),
        ("3.12", "", True),
        ("3.12", None, True),
        ("3.12", ">=three", None),
    ],
)
def test_requires_python(version, spec, expected):
    assert satisfies(version, spec) is expected
