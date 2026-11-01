"""Tolerant regular-expression parser.

Understands the common syntax shared by Python ``re``, JavaScript, PCRE (PHP),
Java and .NET: groups (capturing, named, non-capturing, atomic, look-around),
character classes, escapes, lazy/possessive quantifiers, inline flags and
verbose mode.  Constructs it cannot model (recursion, conditionals ...) are kept
as ``Unsupported`` nodes and reported, never silently dropped.
"""
from __future__ import annotations

import re
from typing import Iterator, List, Optional, Set

from . import charset as cs
from .charset import CharSet


class ParseError(ValueError):
    pass


# --------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------
class Node:
    kind = "node"

    def __init__(self, start: int = 0, end: int = 0):
        self.start = start
        self.end = end

    def children(self) -> List["Node"]:
        return []


class Empty(Node):
    kind = "empty"


class Chars(Node):
    kind = "chars"

    def __init__(self, charset: CharSet, start=0, end=0, is_dot=False):
        super().__init__(start, end)
        self.cs = charset
        self.is_dot = is_dot


class Seq(Node):
    kind = "seq"

    def __init__(self, items: List[Node], start=0, end=0):
        super().__init__(start, end)
        self.items = items

    def children(self):
        return self.items


class Alt(Node):
    kind = "alt"

    def __init__(self, options: List[Node], start=0, end=0):
        super().__init__(start, end)
        self.options = options

    def children(self):
        return self.options


class Group(Node):
    kind = "group"

    def __init__(self, body: Node, capturing: bool, name: Optional[str], start=0, end=0):
        super().__init__(start, end)
        self.body = body
        self.capturing = capturing
        self.name = name

    def children(self):
        return [self.body]


class Repeat(Node):
    kind = "repeat"

    def __init__(self, body: Node, min_: int, max_: Optional[int], greedy=True,
                 possessive=False, start=0, end=0):
        super().__init__(start, end)
        self.body = body
        self.min = min_
        self.max = max_
        self.greedy = greedy
        self.possessive = possessive

    def children(self):
        return [self.body]


class Anchor(Node):
    kind = "anchor"

    def __init__(self, what: str, start=0, end=0):
        super().__init__(start, end)
        self.what = what


class Look(Node):
    kind = "look"

    def __init__(self, body: Node, ahead: bool, negative: bool, start=0, end=0):
        super().__init__(start, end)
        self.body = body
        self.ahead = ahead
        self.negative = negative

    def children(self):
        return [self.body]


class Atomic(Node):
    kind = "atomic"

    def __init__(self, body: Node, start=0, end=0):
        super().__init__(start, end)
        self.body = body

    def children(self):
        return [self.body]


class Backref(Node):
    kind = "backref"

    def __init__(self, ref, start=0, end=0):
        super().__init__(start, end)
        self.ref = ref


class Unsupported(Node):
    kind = "unsupported"

    def __init__(self, what: str, start=0, end=0):
        super().__init__(start, end)
        self.what = what


def walk(node: Node) -> Iterator[Node]:
    yield node
    for child in node.children():
        yield from walk(child)


class ParseResult:
    def __init__(self, root: Node, pattern: str, flags: str, ncap: int,
                 features: Set[str], warnings: List[str]):
        self.root = root
        self.pattern = pattern
        self.flags = flags
        self.ncap = ncap
        self.features = features
        self.warnings = warnings


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------
_QUANT_RE = re.compile(r"\{(\d*)(,)?(\d*)\}")
_SIMPLE_ESC = {"n": "\n", "r": "\r", "t": "\t", "f": "\f", "v": "\v", "a": "\a", "e": "\x1b"}
_PROPS = {
    "l": cs.LETTER, "letter": cs.LETTER, "alpha": cs.LETTER, "alphabetic": cs.LETTER,
    "lu": cs.UPPER, "upper": cs.UPPER, "uppercase": cs.UPPER, "ll": cs.LOWER,
    "lower": cs.LOWER, "lowercase": cs.LOWER, "n": cs.UNI_DIGIT, "nd": cs.UNI_DIGIT,
    "digit": cs.UNI_DIGIT, "p": cs.PUNCT, "punct": cs.PUNCT, "s": cs.SPACE,
    "space": cs.SPACE, "z": cs.SPACE, "zs": cs.SPACE, "xdigit": cs.XDIGIT,
    "alnum": cs.LETTER.union(cs.UNI_DIGIT), "word": cs.WORD, "w": cs.WORD,
    "ascii": cs.CharSet.span(0, 127), "any": cs.ANY,
}


class Parser:
    def __init__(self, pattern: str, flags: str = "", flavor: str = "auto"):
        self.s = pattern
        self.n = len(pattern)
        self.i = 0
        self.flavor = flavor
        self.ic = "i" in flags
        self.dotall = "s" in flags
        self.verbose = "x" in flags
        self.ncap = 0
        self.features: Set[str] = set()
        self.warnings: List[str] = []

    # helpers ----------------------------------------------------------
    def peek(self, off: int = 0) -> str:
        j = self.i + off
        return self.s[j] if j < self.n else ""

    def startswith(self, text: str) -> bool:
        return self.s.startswith(text, self.i)

    def fold(self, charset: CharSet) -> CharSet:
        return charset.casefold() if self.ic else charset

    def dot_set(self) -> CharSet:
        if self.dotall:
            return cs.ANY
        return cs.DOT_JS if self.flavor == "js" else cs.DOT

    # entry ------------------------------------------------------------
    def parse(self) -> Node:
        node = self.parse_alt()
        if self.i < self.n:
            raise ParseError("unmatched ')' at position %d" % self.i)
        return node

    def parse_alt(self) -> Node:
        start = self.i
        options = [self.parse_seq()]
        while self.peek() == "|":
            self.i += 1
            options.append(self.parse_seq())
        if len(options) == 1:
            return options[0]
        return Alt(options, start, self.i)

    def skip_verbose(self) -> None:
        if not self.verbose:
            return
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t\r\n\f\v":
                self.i += 1
            elif c == "#":
                while self.i < self.n and self.s[self.i] != "\n":
                    self.i += 1
            else:
                break

    def parse_seq(self) -> Node:
        start = self.i
        items: List[Node] = []
        while True:
            self.skip_verbose()
            c = self.peek()
            if c == "" or c == "|" or c == ")":
                break
            atom = self.parse_atom()
            if atom is None:
                continue
            atom = self.parse_quantifiers(atom)
            items.append(atom)
        if not items:
            return Empty(start, self.i)
        if len(items) == 1:
            return items[0]
        return Seq(items, start, self.i)

    # quantifiers ------------------------------------------------------
    def _read_quantifier(self):
        c = self.peek()
        if c == "*":
            self.i += 1
            return 0, None
        if c == "+":
            self.i += 1
            return 1, None
        if c == "?":
            self.i += 1
            return 0, 1
        if c == "{":
            m = _QUANT_RE.match(self.s, self.i)
            if m:
                lo, comma, hi = m.group(1), m.group(2), m.group(3)
                if lo == "" and (hi == "" or not comma):
                    return None
                if lo == "" and self.flavor not in ("python", "auto"):
                    return None
                n = int(lo) if lo else 0
                if not comma:
                    mx: Optional[int] = n
                else:
                    mx = int(hi) if hi else None
                if mx is not None and mx < n:
                    raise ParseError("bad repetition range {%s}" % m.group(0))
                self.i = m.end()
                return n, mx
        return None

    def parse_quantifiers(self, atom: Node) -> Node:
        while True:
            self.skip_verbose()
            start = atom.start
            q = self._read_quantifier()
            if q is None:
                return atom
            greedy, possessive = True, False
            if self.peek() == "?":
                greedy = False
                self.i += 1
                self.features.add("lazy")
            elif self.peek() == "+":
                possessive = True
                self.i += 1
                self.features.add("possessive")
            if isinstance(atom, (Anchor, Look)):
                # quantified zero-width assertion: harmless, keep as is
                continue
            atom = Repeat(atom, q[0], q[1], greedy, possessive, start, self.i)

    # atoms ------------------------------------------------------------
    def parse_atom(self) -> Optional[Node]:
        start = self.i
        c = self.s[self.i]
        if c == "(":
            return self.parse_group()
        if c == "[":
            return self.parse_class()
        if c == ".":
            self.i += 1
            return Chars(self.dot_set(), start, self.i, is_dot=True)
        if c == "^":
            self.i += 1
            return Anchor("^", start, self.i)
        if c == "$":
            self.i += 1
            return Anchor("$", start, self.i)
        if c == "\\":
            return self.parse_escape()
        if c in "*+?":
            raise ParseError("nothing to repeat at position %d" % self.i)
        self.i += 1
        return Chars(self.fold(CharSet.of(c)), start, self.i)

    # groups -----------------------------------------------------------
    def _close(self) -> None:
        if self.peek() != ")":
            raise ParseError("missing ')' in group")
        self.i += 1

    def _skip_to_close(self) -> None:
        depth = 1
        while self.i < self.n and depth:
            c = self.s[self.i]
            if c == "\\":
                self.i += 1
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            self.i += 1
        if depth:
            raise ParseError("missing ')' in group")

    def parse_group(self) -> Optional[Node]:
        start = self.i
        self.i += 1  # '('
        saved = (self.ic, self.dotall, self.verbose)
        try:
            if self.peek() != "?":
                if self.peek() == "*":  # PCRE verbs like (*SKIP) / (*UTF8)
                    self._skip_to_close()
                    self.features.add("unsupported")
                    return Unsupported("(*verb)", start, self.i)
                self.ncap += 1
                body = self.parse_alt()
                self._close()
                return Group(body, True, None, start, self.i)
            self.i += 1  # '?'
            c = self.peek()
            if c == ":":
                self.i += 1
                body = self.parse_alt()
                self._close()
                return Group(body, False, None, start, self.i)
            if c == "|":
                self.i += 1
                body = self.parse_alt()
                self._close()
                return Group(body, False, None, start, self.i)
            if c == ">":
                self.i += 1
                body = self.parse_alt()
                self._close()
                self.features.add("atomic")
                return Atomic(body, start, self.i)
            if c in "=!":
                self.i += 1
                body = self.parse_alt()
                self._close()
                self.features.add("lookaround")
                return Look(body, True, c == "!", start, self.i)
            if c == "<" and self.peek(1) in "=!":
                neg = self.peek(1) == "!"
                self.i += 2
                body = self.parse_alt()
                self._close()
                self.features.add("lookaround")
                return Look(body, False, neg, start, self.i)
            if c == "#":
                while self.i < self.n and self.s[self.i] != ")":
                    self.i += 1
                self._close()
                return None
            name = None
            if c == "P" and self.peek(1) == "<":
                end = self.s.find(">", self.i)
                if end < 0:
                    raise ParseError("unterminated group name")
                name = self.s[self.i + 2:end]
                self.i = end + 1
            elif c == "P" and self.peek(1) == "=":
                end = self.s.find(")", self.i)
                if end < 0:
                    raise ParseError("unterminated named backreference")
                ref = self.s[self.i + 2:end]
                self.i = end + 1
                self.features.add("backref")
                return Backref(ref, start, self.i)
            elif c == "P" and self.peek(1) == ">":
                self._skip_to_close()
                self.features.add("unsupported")
                return Unsupported("recursion", start, self.i)
            elif c == "<":
                end = self.s.find(">", self.i)
                if end < 0:
                    raise ParseError("unterminated group name")
                name = self.s[self.i + 1:end]
                self.i = end + 1
            elif c == "'":
                end = self.s.find("'", self.i + 1)
                if end < 0:
                    raise ParseError("unterminated group name")
                name = self.s[self.i + 1:end]
                self.i = end + 1
            if name is not None:
                self.ncap += 1
                self.features.add("named_groups")
                body = self.parse_alt()
                self._close()
                return Group(body, True, name, start, self.i)
            if c == "(":
                # conditional (?(cond)yes|no): model as alternation of both branches
                depth = 0
                while self.i < self.n:
                    ch = self.s[self.i]
                    if ch == "\\":
                        self.i += 1
                    elif ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            self.i += 1
                            break
                    self.i += 1
                body = self.parse_alt()
                self._close()
                self.features.add("conditional")
                self.warnings.append("conditional group approximated as alternation")
                return Group(body, False, None, start, self.i)
            if c in "R&" or c.isdigit() or (c in "+-" and self.peek(1).isdigit()):
                self._skip_to_close()
                self.features.add("unsupported")
                self.warnings.append("recursion / subroutine call not analysed")
                return Unsupported("recursion", start, self.i)
            # inline flags: (?i) (?i-s) (?i:...)
            m = re.compile(r"([a-zA-Z]*)(?:-([a-zA-Z]*))?([:)])").match(self.s, self.i)
            if m:
                on, off, term = m.group(1), m.group(2) or "", m.group(3)
                self.i = m.end()
                if "i" in on:
                    self.ic = True
                if "s" in on:
                    self.dotall = True
                if "x" in on:
                    self.verbose = True
                if "i" in off:
                    self.ic = False
                if "s" in off:
                    self.dotall = False
                if "x" in off:
                    self.verbose = False
                if term == ")":
                    saved = (self.ic, self.dotall, self.verbose)  # applies to rest of scope
                    return None
                body = self.parse_alt()
                self._close()
                return Group(body, False, None, start, self.i)
            raise ParseError("unknown group syntax '(?%s' at position %d" % (c, self.i))
        finally:
            self.ic, self.dotall, self.verbose = saved

    # escapes ----------------------------------------------------------
    def _hex(self, count: int) -> int:
        digits = self.s[self.i:self.i + count]
        if len(digits) != count or not re.fullmatch(r"[0-9a-fA-F]+", digits):
            raise ParseError("bad hex escape at position %d" % self.i)
        self.i += count
        return int(digits, 16)

    def _property(self, negated: bool) -> CharSet:
        if self.peek() == "{":
            end = self.s.find("}", self.i)
            if end < 0:
                raise ParseError("unterminated \\p{...}")
            name = self.s[self.i + 1:end]
            self.i = end + 1
        else:
            name = self.peek()
            self.i += 1
        if name.startswith("^"):
            negated = not negated
            name = name[1:]
        key = re.sub(r"^(is|in|script=|sc=|gc=|general_category=)", "", name.lower().replace("_", ""))
        base = _PROPS.get(key)
        if base is None:
            base = cs.ANY
            self.warnings.append("unicode property \\p{%s} approximated as any character" % name)
            self.features.add("approx")
        return base.negate() if negated else base

    def _class_escape(self, c: str):
        """Escape common to class and non-class context. Returns CharSet or int code point."""
        if c == "d":
            return cs.DIGIT
        if c == "D":
            return cs.DIGIT.negate()
        if c == "w":
            return cs.WORD
        if c == "W":
            return cs.WORD.negate()
        if c == "s":
            return cs.SPACE
        if c == "S":
            return cs.SPACE.negate()
        if c == "h":
            return cs.HSPACE
        if c == "H":
            return cs.HSPACE.negate()
        if c in "pP":
            return self._property(c == "P")
        if c in _SIMPLE_ESC:
            return ord(_SIMPLE_ESC[c])
        if c == "x":
            if self.peek() == "{":
                end = self.s.find("}", self.i)
                if end < 0:
                    raise ParseError("bad \\x{...}")
                val = int(self.s[self.i + 1:end] or "0", 16)
                self.i = end + 1
                return val
            return self._hex(2)
        if c == "u":
            if self.peek() == "{":
                end = self.s.find("}", self.i)
                if end < 0:
                    raise ParseError("bad \\u{...}")
                val = int(self.s[self.i + 1:end] or "0", 16)
                self.i = end + 1
                return val
            return self._hex(4)
        if c == "c" and self.peek().isalpha():
            val = ord(self.peek().upper()) ^ 64
            self.i += 1
            return val
        if c == "0":
            digits = ""
            while len(digits) < 2 and self.peek() in "01234567" and self.peek():
                digits += self.peek()
                self.i += 1
            return int(digits or "0", 8)
        return ord(c)

    def parse_escape(self) -> Optional[Node]:
        start = self.i
        self.i += 1
        if self.i >= self.n:
            raise ParseError("trailing backslash")
        c = self.s[self.i]
        self.i += 1
        if c in "bB":
            return Anchor("\\" + c, start, self.i)
        if c in "AZzG":
            return Anchor("\\" + c, start, self.i)
        if c == "K":
            return Anchor("\\K", start, self.i)
        if c in "RX":
            self.features.add("approx")
            return Chars(cs.ANY, start, self.i)
        if c == "Q":
            end = self.s.find("\\E", self.i)
            text = self.s[self.i:end] if end >= 0 else self.s[self.i:]
            self.i = end + 2 if end >= 0 else self.n
            items = [Chars(self.fold(CharSet.of(ch)), start, self.i) for ch in text]
            if not items:
                return None
            return Seq(items, start, self.i) if len(items) > 1 else items[0]
        if c == "E":
            return None
        if c == "k" and self.peek() in "<{'":
            closer = {"<": ">", "{": "}", "'": "'"}[self.peek()]
            end = self.s.find(closer, self.i + 1)
            if end < 0:
                raise ParseError("bad \\k reference")
            ref = self.s[self.i + 1:end]
            self.i = end + 1
            self.features.add("backref")
            return Backref(ref, start, self.i)
        if c == "g" and self.peek() in "<{'-0123456789":
            if self.peek() in "<{'":
                closer = {"<": ">", "{": "}", "'": "'"}[self.peek()]
                end = self.s.find(closer, self.i + 1)
                ref = self.s[self.i + 1:end]
                self.i = end + 1
            else:
                m = re.compile(r"-?\d+").match(self.s, self.i)
                ref = m.group(0) if m else ""
                self.i = m.end() if m else self.i
            self.features.add("backref")
            return Backref(ref, start, self.i)
        if c in "123456789":
            digits = c
            while self.peek().isdigit() and int(digits + self.peek()) <= max(self.ncap, 9):
                digits += self.peek()
                self.i += 1
            self.features.add("backref")
            return Backref(int(digits), start, self.i)
        val = self._class_escape(c)
        if isinstance(val, CharSet):
            return Chars(val, start, self.i)
        return Chars(self.fold(CharSet.span(val, val)), start, self.i)

    # character classes ------------------------------------------------
    def parse_class(self) -> Node:
        start = self.i
        self.i += 1
        negate = False
        if self.peek() == "^":
            negate = True
            self.i += 1
        total = CharSet()
        first = True
        while True:
            if self.i >= self.n:
                raise ParseError("unterminated character class")
            c = self.s[self.i]
            if c == "]" and not (first and self.flavor != "js"):
                self.i += 1
                break
            first = False
            item = self._class_item()
            if (isinstance(item, int) and self.peek() == "-" and self.peek(1) not in ("]", "")):
                save = self.i
                self.i += 1
                hi_item = self._class_item()
                if isinstance(hi_item, int):
                    if hi_item < item:
                        raise ParseError("bad character range in class")
                    total = total.union(CharSet.span(item, hi_item))
                    continue
                self.i = save  # 'a-\d': treat '-' as literal
            if isinstance(item, int):
                total = total.union(CharSet.span(item, item))
            else:
                total = total.union(item)
        total = self.fold(total)
        if negate:
            total = total.negate()
        return Chars(total, start, self.i)

    def _class_item(self):
        c = self.s[self.i]
        if c == "[" and self.peek(1) == ":":
            end = self.s.find(":]", self.i + 2)
            if end > 0:
                name = self.s[self.i + 2:end]
                neg = name.startswith("^")
                base = cs.POSIX.get(name.lstrip("^"))
                if base is not None:
                    self.i = end + 2
                    return base.negate() if neg else base
        if c == "\\":
            self.i += 1
            if self.i >= self.n:
                raise ParseError("trailing backslash in class")
            e = self.s[self.i]
            self.i += 1
            if e == "b":
                return 8
            if e in "BAZzGEQ":
                return ord(e)
            return self._class_escape(e)
        self.i += 1
        return ord(c)


def parse(pattern: str, flags: str = "", flavor: str = "auto") -> ParseResult:
    p = Parser(pattern, flags, flavor)
    root = p.parse()
    return ParseResult(root, pattern, flags, p.ncap, p.features, p.warnings)
