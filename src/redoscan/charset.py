"""Character-set algebra and alphabet partitioning.

A :class:`CharSet` is an immutable, normalised list of inclusive code-point
ranges.  The analyser never enumerates characters: it partitions the alphabet
into equivalence classes (:class:`Alphabet`) so that every set becomes a small
bit mask and intersection is a single ``&``.
"""
from __future__ import annotations

from bisect import bisect_left
from typing import Iterable, List, Optional, Tuple

MAX_CP = 0x10FFFF
PREFERRED = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.,:;/@#"
POISON_PREFERRED = "!~#@%^&*+= \n\x00|"

Range = Tuple[int, int]


def _norm(ranges: Iterable[Range]) -> Tuple[Range, ...]:
    rs = sorted((lo, hi) for lo, hi in ranges if lo <= hi)
    out: List[Range] = []
    for lo, hi in rs:
        if out and lo <= out[-1][1] + 1:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return tuple(out)


class CharSet:
    __slots__ = ("ranges",)

    def __init__(self, ranges: Iterable[Range] = ()):
        self.ranges = _norm(ranges)

    # constructors -----------------------------------------------------
    @classmethod
    def of(cls, *chars: str) -> "CharSet":
        return cls([(ord(c), ord(c)) for c in chars])

    @classmethod
    def span(cls, lo: int, hi: int) -> "CharSet":
        return cls([(lo, hi)])

    # algebra ----------------------------------------------------------
    def union(self, other: "CharSet") -> "CharSet":
        return CharSet(self.ranges + other.ranges)

    def negate(self) -> "CharSet":
        out: List[Range] = []
        prev = 0
        for lo, hi in self.ranges:
            if lo > prev:
                out.append((prev, lo - 1))
            prev = hi + 1
        if prev <= MAX_CP:
            out.append((prev, MAX_CP))
        return CharSet(out)

    def intersect(self, other: "CharSet") -> "CharSet":
        out: List[Range] = []
        a, b = self.ranges, other.ranges
        i = j = 0
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return CharSet(out)

    def casefold(self) -> "CharSet":
        """Add the other-case counterpart of every cased character (Latin range)."""
        extra: List[Range] = []
        for lo, hi in self.ranges:
            for cp in range(lo, min(hi, 0x24F) + 1):
                ch = chr(cp)
                for alt in (ch.lower(), ch.upper()):
                    if len(alt) == 1 and alt != ch:
                        extra.append((ord(alt), ord(alt)))
        return CharSet(self.ranges + tuple(extra)) if extra else self

    # queries ----------------------------------------------------------
    def __contains__(self, cp: int) -> bool:
        for lo, hi in self.ranges:
            if lo <= cp <= hi:
                return True
            if lo > cp:
                break
        return False

    def is_empty(self) -> bool:
        return not self.ranges

    def is_full(self) -> bool:
        return self.ranges == ((0, MAX_CP),)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CharSet) and self.ranges == other.ranges

    def __hash__(self) -> int:
        return hash(self.ranges)

    def __repr__(self) -> str:
        return "CharSet(%s)" % ",".join("%x-%x" % r for r in self.ranges[:6])


EMPTY = CharSet()
ANY = CharSet([(0, MAX_CP)])
DIGIT = CharSet.span(0x30, 0x39)
WORD = CharSet([(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)])
SPACE = CharSet([(9, 13), (32, 32), (0xA0, 0xA0), (0x1680, 0x1680), (0x2000, 0x200A),
                 (0x2028, 0x2029), (0x202F, 0x202F), (0x205F, 0x205F), (0x3000, 0x3000),
                 (0xFEFF, 0xFEFF)])
NEWLINE = CharSet.of("\n")
DOT = ANY.intersect(NEWLINE.negate())
DOT_JS = ANY.intersect(CharSet([(10, 10), (13, 13), (0x2028, 0x2029)]).negate())
HSPACE = CharSet([(9, 9), (32, 32), (0xA0, 0xA0), (0x1680, 0x1680), (0x2000, 0x200A),
                  (0x202F, 0x202F), (0x205F, 0x205F), (0x3000, 0x3000)])
LETTER = CharSet([(0x41, 0x5A), (0x61, 0x7A), (0xC0, 0xD6), (0xD8, 0xF6), (0xF8, 0x24F),
                  (0x370, 0x3FF), (0x400, 0x52F), (0x5D0, 0x5EA), (0x620, 0x64A),
                  (0x671, 0x6D3), (0x4E00, 0x9FFF)])
UPPER = CharSet([(0x41, 0x5A), (0xC0, 0xD6), (0xD8, 0xDE)])
LOWER = CharSet([(0x61, 0x7A), (0xDF, 0xF6), (0xF8, 0xFF)])
UNI_DIGIT = CharSet([(0x30, 0x39), (0x660, 0x669), (0x6F0, 0x6F9)])
PUNCT = CharSet([(0x21, 0x2F), (0x3A, 0x40), (0x5B, 0x60), (0x7B, 0x7E)])
XDIGIT = CharSet([(0x30, 0x39), (0x41, 0x46), (0x61, 0x66)])

POSIX = {
    "alpha": CharSet([(0x41, 0x5A), (0x61, 0x7A)]),
    "digit": DIGIT,
    "alnum": CharSet([(0x30, 0x39), (0x41, 0x5A), (0x61, 0x7A)]),
    "upper": CharSet([(0x41, 0x5A)]),
    "lower": CharSet([(0x61, 0x7A)]),
    "space": CharSet([(9, 13), (32, 32)]),
    "blank": CharSet([(9, 9), (32, 32)]),
    "punct": PUNCT,
    "word": WORD,
    "xdigit": XDIGIT,
    "cntrl": CharSet([(0, 31), (127, 127)]),
    "print": CharSet([(32, 126)]),
    "graph": CharSet([(33, 126)]),
}


class Alphabet:
    """Partition of the code-point space into classes; sets become bit masks."""

    def __init__(self, sets: Iterable[CharSet]):
        pts = {0, MAX_CP + 1}
        for s in sets:
            for lo, hi in s.ranges:
                pts.add(lo)
                pts.add(hi + 1)
        self.points = sorted(pts)
        self.nclasses = len(self.points) - 1
        self.full = (1 << self.nclasses) - 1

    def mask(self, cs: CharSet) -> int:
        m = 0
        for lo, hi in cs.ranges:
            i = bisect_left(self.points, lo)
            j = bisect_left(self.points, hi + 1)
            for k in range(i, j):
                m |= 1 << k
        return m

    def _interval(self, k: int) -> Tuple[int, int]:
        return self.points[k], self.points[k + 1] - 1

    def sample(self, mask: int, preferred: str = PREFERRED) -> Optional[str]:
        """Pick a readable representative character from a mask."""
        if not mask:
            return None
        classes = [k for k in range(self.nclasses) if mask >> k & 1]
        for ch in preferred:
            cp = ord(ch)
            for k in classes:
                lo, hi = self._interval(k)
                if lo <= cp <= hi:
                    return ch
        k = classes[0]
        lo, hi = self._interval(k)
        cp = max(lo, 0x21) if max(lo, 0x21) <= hi else lo
        if 0xD800 <= cp <= 0xDFFF:
            cp = 0xE000 if hi >= 0xE000 else 0x20
        return chr(cp)

    def sample_poison(self, mask: int) -> Optional[str]:
        return self.sample(mask, POISON_PREFERRED)
