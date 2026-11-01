import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import pytest
from redoscan.parser import parse, ParseError, walk

@pytest.mark.parametrize("pattern", [
    r"^(a+)+$",
    r"(?P<name>\d{2,4})-(?:x|y)*?z++",
    r"[^\]a-z\d]+(?i)abc",
    r"(?<=a)b(?!c)",
    r"\p{L}+\k<name>(?>ab)",
    r"a{,3}b{2}",
    r"(?(1)a|b)",
    r"[]a]",
    r"(?x) a b # comment\n c",
    r"\w\W\s\S\d\D",
    r"a|b|c|",
    r"(a(b(c)d)e)",
])
def test_parses_without_error(pattern):
    result = parse(pattern)
    assert result.root is not None

@pytest.mark.parametrize("bad", ["(", "a)", "*a", "[a", "a{3,2}", "a\\"])
def test_rejects_malformed_patterns(bad):
    with pytest.raises(ParseError):
        parse(bad)

def test_named_group_increments_capture_count():
    r = parse(r"(a)(?P<x>b)(c)")
    assert r.ncap == 3

def test_backreference_feature_flag():
    r = parse(r"(a)\1")
    assert "backref" in r.features

def test_atomic_feature_flag():
    r = parse(r"(?>a+)")
    assert "atomic" in r.features

def test_lookaround_feature_flag():
    r = parse(r"(?=a)(?!b)(?<=c)(?<!d)")
    assert "lookaround" in r.features

def test_walk_visits_all_nodes():
    r = parse(r"(a|b)c")
    kinds = [type(n).__name__ for n in walk(r.root)]
    assert "Alt" in kinds and "Group" in kinds
