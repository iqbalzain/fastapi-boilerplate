from depguard.names import affix_variant_of, levenshtein, normalize, skeleton, typosquat_candidates

KNOWN = frozenset({"requests", "urllib3", "numpy", "python-dotenv", "django"})


def test_normalize_and_skeleton():
    assert normalize("Requests_Toolbelt.Extra") == "requests-toolbelt-extra"
    assert skeleton("requ3sts") == "requests"
    assert skeleton("ur11ib3") == skeleton("urllib3")


def test_levenshtein():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3
    assert levenshtein("same", "same") == 0


def test_typosquat_detection():
    assert typosquat_candidates("requests", max_distance=2, known=KNOWN) == []
    hits = typosquat_candidates("requets", max_distance=2, known=KNOWN)
    assert ("requests", "edit distance 1") in hits
    hits = typosquat_candidates("ur11ib3", max_distance=2, known=KNOWN)
    assert hits and hits[0][0] == "urllib3"
    assert typosquat_candidates("completely-different", max_distance=2, known=KNOWN) == []


def test_affix_variant():
    assert affix_variant_of("python-requests", known=KNOWN) == "requests"
    assert affix_variant_of("django-python", known=KNOWN) == "django"
    assert affix_variant_of("python-dotenv", known=KNOWN) is None  # exact known name
    assert affix_variant_of("unrelated", known=KNOWN) is None
