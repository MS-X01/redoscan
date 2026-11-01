import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from redoscan.charset import CharSet, Alphabet, DIGIT, WORD, DOT

def test_union_normalizes_overlap():
    a = CharSet([(1, 5), (3, 8)])
    assert a.ranges == ((1, 8),)

def test_negate_roundtrip():
    a = CharSet([(5, 10)])
    assert a.negate().negate() == a

def test_intersect_disjoint_is_empty():
    a = CharSet([(0, 10)])
    b = CharSet([(20, 30)])
    assert a.intersect(b).is_empty()

def test_digit_word_overlap():
    assert not DIGIT.intersect(WORD).is_empty()

def test_dot_excludes_newline():
    nl = ord("\n")
    assert nl not in DOT
    assert ord("a") in DOT

def test_alphabet_mask_roundtrip():
    alpha = Alphabet([DIGIT, WORD])
    m = alpha.mask(DIGIT)
    assert alpha.sample(m) in "0123456789"

def test_casefold_adds_both_cases():
    a = CharSet.of("a")
    folded = a.casefold()
    assert ord("A") in folded and ord("a") in folded
