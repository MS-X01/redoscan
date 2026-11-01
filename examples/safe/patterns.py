"""Hardened versions of the patterns in examples/vulnerable/patterns.py.

Each fix below removes the specific ambiguity redoscan found, using the
narrowest change that does it -- see docs/METHOD.md for why each shape works.
"""
import re

# The inner a+ no longer needs an outer repeat at all: a single unbounded
# group already matches any run of a's. (Nesting a+ inside (...)+ was the
# bug, not the + itself.)
NESTED_QUANTIFIER = re.compile(r"^a+$")

# Drop the pointless repeat around the character class: it already matches
# one-or-more characters by itself.
OPTIONAL_NESTED = re.compile(r"^[a-zA-Z0-9_.-]+@")

# The two alternatives were identical, so the alternation added ambiguity
# with no benefit; a single unbounded group does the same job.
DUPLICATE_ALTERNATION = re.compile(r"^a+$")

# Three adjacent \s* groups never needed to be three groups.
OVERLAPPING_PLUS_CHAIN = re.compile(r"^\s*$")

# Exclude '=' from both .* groups so they can no longer both claim the same
# characters -- there is exactly one way to split the string now.
DOT_STAR_CHAIN = re.compile(r"^[^=]*=[^=]*$")

# An atomic group around the attributes isn't quite enough on its own: it
# stops backtracking *inside* that group, but [a-z]+ right before it can
# still give back letters one at a time, each time triggering a fresh
# O(n) atomic rescan, which is still O(n^2) overall. Requiring a mandatory
# space before any attributes removes the overlap entirely: a space is never
# an [a-z] character, so there is exactly one valid split point.
HTML_TAG = re.compile(r"<([a-z]+)(?:\s[^>]*)?>")
