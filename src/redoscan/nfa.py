"""AST -> NFA -> epsilon-free "position graph".

The static analysis needs to know whether a regex can match the *same* input in
more than one way, because that is exactly what a backtracking engine pays for
when a match fails.  We therefore keep path **multiplicity**: if two different
epsilon paths lead to the same position, the graph records a double edge.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from . import parser as P
from .charset import Alphabet, CharSet

CAP_MIN = 3          # mandatory copies kept when expanding x{n,}
CAP_MAX = 8          # bounded counts above this are approximated as unbounded
MAX_POSITIONS = 220  # refuse static analysis above this many character positions
CLOSURE_STEP_LIMIT = 40000


class TooComplex(Exception):
    pass


class Edge:
    __slots__ = ("src", "dst", "cs", "node", "ancestors", "atomic_ancestors")

    def __init__(self, src: int, dst: int, charset: CharSet, node: P.Chars, ancestors,
                 atomic_ancestors=()):
        self.src = src
        self.dst = dst
        self.cs = charset
        self.node = node
        self.ancestors = ancestors
        # ids of enclosing Atomic (and possessive-Repeat) AST nodes: these
        # suppress backtracking, so two edges that only diverge *within* a
        # shared atomic scope represent a single committed derivation, not
        # real ambiguity. See `nfa.py`'s build_repeat for the possessive case
        # and `engine.py`'s `_shares_committed_scope`.
        self.atomic_ancestors = atomic_ancestors


class Graph:
    """Epsilon-free automaton. Node i == "just consumed character edge i"."""

    def __init__(self):
        self.edges: List[Edge] = []
        self.masks: List[int] = []
        self.trans: List[List[Tuple[int, int]]] = []   # node -> [(next_node, multiplicity)]
        self.init: List[Tuple[int, int]] = []
        self.accepting: List[bool] = []
        self.init_accepting = False
        self.alphabet: Optional[Alphabet] = None
        self.flags: set = set()          # approximations / unsupported features seen
        self.approx_counts = False
        self.truncated = False

    @property
    def n(self) -> int:
        return len(self.edges)


class _Builder:
    def __init__(self):
        self.eps: List[List[int]] = []
        self.edges: List[Edge] = []
        self.edge_by_src: Dict[int, List[int]] = {}
        self.stack: List[P.Repeat] = []
        self.atomic_stack: List[int] = []
        self.flags: set = set()
        self.approx_counts = False

    def new(self) -> int:
        self.eps.append([])
        return len(self.eps) - 1

    def add_eps(self, a: int, b: int) -> None:
        self.eps[a].append(b)

    def add_edge(self, a: int, b: int, node: P.Chars) -> None:
        if len(self.edges) >= MAX_POSITIONS:
            raise TooComplex("more than %d character positions" % MAX_POSITIONS)
        idx = len(self.edges)
        self.edges.append(Edge(a, b, node.cs, node, tuple(self.stack), tuple(self.atomic_stack)))
        self.edge_by_src.setdefault(a, []).append(idx)

    # structure --------------------------------------------------------
    def build(self, node: P.Node, s: int, e: int) -> None:
        t = type(node)
        if t is P.Chars:
            self.add_edge(s, e, node)
        elif t is P.Seq:
            cur = s
            last = len(node.items) - 1
            for k, item in enumerate(node.items):
                nxt = e if k == last else self.new()
                self.build(item, cur, nxt)
                cur = nxt
        elif t is P.Alt:
            for opt in node.options:
                bs, be = self.new(), self.new()
                self.add_eps(s, bs)
                self.build(opt, bs, be)
                self.add_eps(be, e)
        elif t is P.Group:
            self.build(node.body, s, e)
        elif t is P.Atomic:
            self.flags.add("atomic")
            self.atomic_stack.append(id(node))
            try:
                self.build(node.body, s, e)
            finally:
                self.atomic_stack.pop()
        elif t is P.Repeat:
            if node.possessive:
                self.flags.add("possessive")
                # A possessive quantifier `x++` behaves exactly like an
                # atomic group wrapped around `x+`: once it has grabbed as
                # much as it can, it never gives characters back. Model it
                # the same way, so it also suppresses ambiguity like (?>...).
                self.atomic_stack.append(id(node))
                try:
                    self.build_repeat(node, s, e)
                finally:
                    self.atomic_stack.pop()
            else:
                self.build_repeat(node, s, e)
        elif t is P.Look:
            self.flags.add("lookaround")
            self.add_eps(s, e)
        elif t is P.Backref:
            self.flags.add("backref")
            self.add_eps(s, e)
        elif t is P.Unsupported:
            self.flags.add("unsupported")
            self.add_eps(s, e)
        else:  # Empty, Anchor
            self.add_eps(s, e)

    def _star(self, body: P.Node, s: int, e: int) -> None:
        loop, bs, be = self.new(), self.new(), self.new()
        self.add_eps(s, loop)
        self.add_eps(loop, bs)
        self.build(body, bs, be)
        self.add_eps(be, loop)
        self.add_eps(loop, e)

    def _plus(self, body: P.Node, s: int, e: int) -> None:
        bs, be, loop = self.new(), self.new(), self.new()
        self.add_eps(s, bs)
        self.build(body, bs, be)
        self.add_eps(be, loop)
        self.add_eps(loop, bs)
        self.add_eps(loop, e)

    def build_repeat(self, r: P.Repeat, s: int, e: int) -> None:
        lo, hi = r.min, r.max
        self.stack.append(r)
        try:
            if hi == 0:
                self.add_eps(s, e)
                return
            if hi is not None and hi > CAP_MAX:
                self.approx_counts = True
                hi = None
                lo = min(lo, CAP_MIN)
            if hi is None:
                if lo > CAP_MIN:
                    self.approx_counts = True
                    lo = CAP_MIN
                if lo == 0:
                    self._star(r.body, s, e)
                else:
                    cur = s
                    for _ in range(lo - 1):
                        nxt = self.new()
                        self.build(r.body, cur, nxt)
                        cur = nxt
                    self._plus(r.body, cur, e)
            else:
                cur = s
                for _ in range(lo):
                    nxt = self.new()
                    self.build(r.body, cur, nxt)
                    cur = nxt
                for _ in range(hi - lo):
                    self.add_eps(cur, e)
                    nxt = self.new()
                    self.build(r.body, cur, nxt)
                    cur = nxt
                self.add_eps(cur, e)
        finally:
            self.stack.pop()

    # epsilon closure with path multiplicity --------------------------
    def closure(self, start: int, accept: int):
        res: Dict[int, int] = {}
        acc = 0
        steps = 0
        truncated = False

        def record(v: int):
            nonlocal acc
            for ei in self.edge_by_src.get(v, ()):
                res[ei] = min(2, res.get(ei, 0) + 1)
            if v == accept:
                acc = min(2, acc + 1)

        stack = [[start, 0]]
        onpath = {start}
        record(start)
        while stack:
            top = stack[-1]
            u, idx = top
            outs = self.eps[u]
            if idx < len(outs):
                top[1] += 1
                v = outs[idx]
                if v in onpath:
                    continue
                steps += 1
                if steps > CLOSURE_STEP_LIMIT:
                    truncated = True
                    break
                onpath.add(v)
                record(v)
                stack.append([v, 0])
            else:
                stack.pop()
                onpath.discard(u)
        return res, acc, truncated


def build_graph(root: P.Node) -> Graph:
    b = _Builder()
    s0, acc = b.new(), b.new()
    b.build(root, s0, acc)
    g = Graph()
    g.edges = b.edges
    g.flags = set(b.flags)
    g.approx_counts = b.approx_counts
    n = len(b.edges)
    alpha = Alphabet([e.cs for e in b.edges])
    g.alphabet = alpha
    g.masks = [alpha.mask(e.cs) for e in b.edges]
    trunc = False
    init, init_acc, t0 = b.closure(s0, acc)
    trunc = trunc or t0
    g.init = sorted(init.items())
    g.init_accepting = init_acc > 0
    for ei in range(n):
        res, a, t = b.closure(b.edges[ei].dst, acc)
        trunc = trunc or t
        g.trans.append(sorted(res.items()))
        g.accepting.append(a > 0)
    g.truncated = trunc
    return g
