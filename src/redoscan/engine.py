"""Ambiguity detection: the static core of redoscan.

Two complementary analyses run over the NFA built from the pattern:

``EDA`` (Exponential Degree of Ambiguity)
    Built as a *product automaton* over pairs of character-consuming
    positions.  If the product graph contains a reachable cycle on a pair
    ``(i, j)`` with ``i != j`` (or ``i == j`` reached with multiplicity 2),
    there are two distinct ways to consume the same substring and return to
    the same pair of positions.  Repeating that substring ``k`` times gives
    ``2^k`` equivalent paths through the automaton -- textbook catastrophic
    backtracking.  This mirrors the construction used in the academic
    literature on static ReDoS detection (Weideman et al., 2017).

``IDA`` (Polynomial Degree of Ambiguity)
    A cheaper, purely structural check: sibling quantified groups in the same
    sequence whose character sets overlap (``\\d+\\d+``, ``.*.*b``) cause a
    polynomial (not exponential) blow-up, because the engine must try every
    split point between the two groups.  Degree grows with the number of
    chained overlapping quantifiers.

Both analyses are approximations of an NP-hard problem; see ``docs/METHOD.md``
for precision/recall notes.  redoscan treats a finding as a *lead*, and backs
every static finding with a dynamic timing check (see ``dynamic.py``) before
calling it confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import parser as P
from .nfa import Graph, build_graph


@dataclass
class Finding:
    kind: str                      # "EDA" | "IDA" | "info" | a vulnscan rule code (e.g. "SQLI")
    severity: str                  # "critical" | "high" | "medium" | "low" | "info"
    message: str
    pump_prefix: str = ""
    pump_group: str = ""
    pump_suffix: str = ""
    repeats_hint: int = 24
    degree: int = 2
    span: Optional[Tuple[int, int]] = None
    detail: str = ""
    category: str = "redos"        # "redos" | "sqli" | "cmdi" | "deser" | "crypto" | "rand"
                                    # | "path" | "ssrf" | "idor" -- used by --category filtering
    cwe: str = ""                  # e.g. "CWE-89", blank for redos findings
    confidence: str = "confirmed-by-analysis"  # "confirmed-by-analysis" (redos: proven by the
                                    # automaton search) | "heuristic" (vulnscan: pattern-matched,
                                    # needs a human to confirm it's really reachable/exploitable)
    evidence: str = ""             # for vulnscan: the actual source line that matched

    def pump(self, repeats: int) -> str:
        return self.pump_prefix + self.pump_group * repeats + self.pump_suffix


@dataclass
class AnalysisResult:
    findings: List[Finding] = field(default_factory=list)
    features: Set[str] = field(default_factory=set)
    warnings: List[str] = field(default_factory=list)
    truncated: bool = False
    approx_counts: bool = False
    n_positions: int = 0

    @property
    def worst_severity(self) -> str:
        order = ["critical", "high", "medium", "low", "info"]
        present = {f.severity for f in self.findings}
        for s in order:
            if s in present:
                return s
        return "info"


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _reach_accept(g: Graph) -> List[bool]:
    n = g.n
    can = list(g.accepting)
    rev: List[List[int]] = [[] for _ in range(n)]
    for i in range(n):
        for j, _m in g.trans[i]:
            rev[j].append(i)
    stack = [i for i in range(n) if can[i]]
    seen = set(stack)
    while stack:
        u = stack.pop()
        for p in rev[u]:
            if p not in seen:
                seen.add(p)
                can[p] = True
                stack.append(p)
    return can


def _common_repeat_depth(a: Tuple[P.Repeat, ...], b: Tuple[P.Repeat, ...]) -> int:
    common = set(id(x) for x in a) & set(id(x) for x in b)
    return len(common)


def _shares_committed_scope(g: Graph, i: int, j: int) -> bool:
    """True if edges i and j sit inside the same atomic group or possessive
    quantifier. Such a scope commits to exactly one derivation and never
    backtracks into it, so two paths that only differ *inside* it are not
    real ambiguity from the outside -- this is precisely what makes
    `(?>a+)+` and `a++` safe rewrites of the vulnerable `(a+)+`."""
    ai = g.edges[i].atomic_ancestors
    aj = g.edges[j].atomic_ancestors
    return bool(set(ai) & set(aj))


def _sample_pair(g: Graph, i: int, j: int) -> str:
    m = g.masks[i] & g.masks[j]
    if not m:
        m = g.masks[i]
    ch = g.alphabet.sample_poison(m) or g.alphabet.sample(m) or "a"
    return ch


class _EDASearch:
    """DFS over the product automaton of edge-index pairs."""

    MAX_PRODUCT_STATES = 60000
    MAX_DEPTH = 4000

    def __init__(self, g: Graph):
        self.g = g
        self.can_accept = _reach_accept(g)
        self.visited: Set[Tuple[int, int]] = set()
        self.found: List[Finding] = []
        self.budget = self.MAX_PRODUCT_STATES
        self.seen_signatures: Set[frozenset] = set()

    # A product-state pair (i, j) represents "two independent copies of the
    # automaton, having read the same input so far, currently sitting right
    # after character-edges i and j respectively".  Two copies can always
    # trivially pick the *same* transition, so the diagonal (i, i) is always
    # reachable and does not by itself mean anything.  What matters is
    # whether the pair was ever produced by a genuine *divergence*: either an
    # off-diagonal pair (i != j), or a diagonal pair reached through two
    # distinct epsilon-paths converging back onto the same edge (tracked via
    # multiplicity). A cycle is only reported if at least one step on it was
    # such a genuine divergence -- otherwise it is just one thread looping,
    # counted twice.
    def start_pairs(self) -> List[Tuple[Tuple[int, int], bool, str]]:
        g = self.g
        pairs: List[Tuple[Tuple[int, int], bool, str]] = []
        for i, m in g.init:
            div = m >= 2 and not _shares_committed_scope(g, i, i)
            pairs.append(((i, i), div, "the start of the pattern"))
        init_idx = [i for i, _m in g.init]
        for a in range(len(init_idx)):
            for b in range(a + 1, len(init_idx)):
                i, j = init_idx[a], init_idx[b]
                if g.masks[i] & g.masks[j] and not _shares_committed_scope(g, i, j):
                    lo, hi = (i, j) if i <= j else (j, i)
                    pairs.append(((lo, hi), True, "the start of the pattern"))
        return pairs

    def successors(self, pair: Tuple[int, int]):
        g = self.g
        i, j = pair
        out = []
        if i == j:
            ts = g.trans[i]
            for a in range(len(ts)):
                ia, ma = ts[a]
                committed = _shares_committed_scope(g, ia, ia) if ma >= 2 else False
                # A self-transition reached via >=2 distinct epsilon paths is
                # only real ambiguity if those paths are not both sealed
                # inside the same atomic/possessive scope as the edge itself.
                div = ma >= 2 and not committed
                # Emit the diagonal target once per distinct epsilon-path that
                # reaches it (capped at 2), so a genuine "two ways back to the
                # same edge" convergence is visible to the route-counting in
                # `_has_branching` and not silently collapsed to one route.
                reps = 1 if committed else max(1, ma)
                for _ in range(reps):
                    out.append(((ia, ia), div))
                for b in range(a + 1, len(ts)):
                    ib, _mb = ts[b]
                    if g.masks[ia] & g.masks[ib] and not _shares_committed_scope(g, ia, ib):
                        lo, hi = (ia, ib) if ia <= ib else (ib, ia)
                        out.append(((lo, hi), True))
        else:
            for ia, _ma in g.trans[i]:
                for ib, _mb in g.trans[j]:
                    if g.masks[ia] & g.masks[ib] and not _shares_committed_scope(g, ia, ib):
                        lo, hi = (ia, ib) if ia <= ib else (ib, ia)
                        out.append(((lo, hi), True))
        return out

    def run(self) -> List[Finding]:
        for pair, divergent, origin in self.start_pairs():
            self._dfs(pair, [pair], [divergent], {pair: 0}, origin)
            if self.budget <= 0 or len(self.found) >= 12:
                break
        return self.found

    def _dfs(self, pair, path, div_path, on_path, origin):
        if self.budget <= 0 or len(path) > self.MAX_DEPTH or len(self.found) >= 12:
            return
        self.budget -= 1
        if pair in self.visited:
            return
        self.visited.add(pair)
        for nxt, div in self.successors(pair):
            if nxt in on_path:
                start_pos = on_path[nxt]
                if div or any(div_path[start_pos:]):
                    self._report_cycle(path, start_pos, nxt, origin)
                continue
            on_path[nxt] = len(path)
            self._dfs(nxt, path + [nxt], div_path + [div], on_path, origin)
            del on_path[nxt]

    def _can_reach(self, src: Tuple[int, int], target: Tuple[int, int], budget: int) -> bool:
        """Bounded reachability check inside the product graph."""
        if src == target:
            return True
        seen = {src}
        stack = [src]
        while stack and budget > 0:
            u = stack.pop()
            for v, _div in self.successors(u):
                if v == target:
                    return True
                if v not in seen:
                    seen.add(v)
                    stack.append(v)
                    budget -= 1
                    if budget <= 0:
                        break
        return False

    def _has_branching(self, pair: Tuple[int, int]) -> bool:
        """True if there is more than one distinct route from `pair` back to
        `pair` -- i.e. each lap around the loop offers a real choice, which is
        what makes the cost double per repetition (exponential). This covers
        two cases: (a) two *different* epsilon derivations both land back on
        `pair` directly (tracked as a multiplicity >= 2 self-transition, the
        classic "(a+)+" shape), or (b) two distinct intermediate pairs each
        have their own independent path back to `pair` (e.g. an alternation
        with two overlapping branches inside the loop). A single deterministic
        loop (exactly one route back) only contributes polynomially, not
        exponentially."""
        raw = self.successors(pair)
        route_count: Dict[Tuple[int, int], int] = {}
        for t, _d in raw:
            route_count[t] = route_count.get(t, 0) + 1
        if route_count.get(pair, 0) >= 2:
            return True
        hits = 0
        remaining = 3000
        for t in route_count:
            if self._can_reach(t, pair, remaining):
                hits += 1
                if hits >= 2:
                    return True
        return False

    def _report_cycle(self, path_pairs, start_pos, closing_pair, origin):
        g = self.g
        cycle = path_pairs[start_pos:]
        if len(cycle) < 1:
            return
        i0, j0 = closing_pair
        if not (self.can_accept[i0] or self.can_accept[j0]):
            return
        sig = frozenset(cycle)
        if sig in self.seen_signatures:
            return
        self.seen_signatures.add(sig)
        pump_chars = [_sample_pair(g, i, j) for (i, j) in cycle]
        pump = "".join(pump_chars)
        edge0 = g.edges[i0]
        depth = _common_repeat_depth(edge0.ancestors, g.edges[j0].ancestors)
        where = "position %d" % edge0.node.start
        branching = self._has_branching(closing_pair)
        if branching:
            severity = "critical" if len(cycle) <= 3 else "high"
            self.found.append(Finding(
                kind="EDA",
                severity=severity,
                message=(
                    "Exponential blow-up: from %s the engine can go around the loop near "
                    "%s in more than one distinct way and land back in the same place "
                    "every time. Each repeat of the trigger text doubles the number of "
                    "paths the engine has to try once the match ultimately fails."
                    % (origin, where)
                ),
                pump_group=pump,
                pump_suffix="\x00",
                repeats_hint=22,
                degree=2,
                span=(edge0.node.start, edge0.node.end),
                detail="ambiguous cycle length %d, shared quantifier depth %d" % (len(cycle), depth),
            ))
        else:
            self.found.append(Finding(
                kind="IDA",
                severity="medium",
                message=(
                    "Polynomial blow-up: from %s there are two different ways to read the "
                    "same text around %s, but only one way back into the loop, so the cost "
                    "grows with the square of the input length rather than exponentially."
                    % (origin, where)
                ),
                pump_group=pump,
                pump_suffix="\x00",
                repeats_hint=3000,
                degree=2,
                span=(edge0.node.start, edge0.node.end),
                detail="ambiguous cycle length %d (single route back)" % len(cycle),
            ))


def _first_set(node: P.Node) -> Tuple[Optional[Tuple], bool]:
    """Very small 'can match empty / first characters' helper for IDA scan."""
    from .charset import CharSet
    t = type(node)
    if t is P.Chars:
        return node.cs, False
    if t is P.Empty or t is P.Anchor:
        return CharSet(), True
    if t is P.Group or t is P.Atomic:
        return _first_set(node.body)
    if t is P.Repeat:
        cs, nullable = _first_set(node.body)
        return cs, nullable or node.min == 0
    if t is P.Seq:
        total = CharSet()
        for item in node.items:
            cs, nullable = _first_set(item)
            total = total.union(cs)
            if not nullable:
                return total, False
        return total, True
    if t is P.Alt:
        total = CharSet()
        nullable = False
        for opt in node.options:
            cs, n = _first_set(opt)
            total = total.union(cs)
            nullable = nullable or n
        return total, nullable
    if t is P.Backref or t is P.Unsupported:
        return CharSet([(0, 0x10FFFF)]), True
    return CharSet(), True


def _scan_ida(node: P.Node, findings: List[Finding]) -> None:
    for sub in P.walk(node):
        if type(sub) is not P.Seq:
            continue
        chain: List[P.Repeat] = []
        for item in sub.items:
            is_quant = isinstance(item, P.Repeat) and item.max is None and item.min <= 1
            if is_quant:
                chain.append(item)
                continue
            if type(item) is P.Anchor:
                continue
            _flush_ida_chain(chain, findings)
            chain = []
        _flush_ida_chain(chain, findings)


def _flush_ida_chain(chain: List[P.Repeat], findings: List[Finding]) -> None:
    if len(chain) < 2:
        return
    sets = [_first_set(r.body)[0] for r in chain]
    overlapping = []
    for k in range(len(sets) - 1):
        if not sets[k].intersect(sets[k + 1]).is_empty():
            overlapping.append(k)
    if not overlapping:
        return
    degree = len(overlapping) + 1
    first, last = chain[0], chain[-1]
    from .charset import Alphabet
    overlap_set = sets[overlapping[0]].intersect(sets[overlapping[0] + 1])
    ch = Alphabet([overlap_set]).sample(Alphabet([overlap_set]).mask(overlap_set)) or "a"
    findings.append(Finding(
        kind="IDA",
        severity="medium" if degree <= 2 else "high",
        message=(
            "Polynomial blow-up: %d adjacent unbounded groups (position %d-%d) can all "
            "match the same kind of character. The engine tries every way to split the "
            "input between them, costing roughly O(n^%d) on a long non-matching input."
            % (len(chain), first.start, last.end, degree)
        ),
        pump_prefix="",
        pump_group=ch,
        pump_suffix="\x00",
        repeats_hint=4000,
        degree=degree,
        span=(first.start, last.end),
        detail="%d overlapping adjacent quantifiers" % len(chain),
    ))


def analyse(pattern: str, flags: str = "", flavor: str = "auto") -> AnalysisResult:
    result = AnalysisResult()
    try:
        parsed = P.parse(pattern, flags, flavor)
    except P.ParseError as e:
        result.findings.append(Finding("info", "info", "Could not parse pattern: %s" % e))
        return result
    result.features = parsed.features
    result.warnings = list(parsed.warnings)
    if "backref" in parsed.features:
        result.warnings.append(
            "pattern uses backreferences: exact ambiguity analysis is undecidable for "
            "backreferences, results below ignore them (treated as wildcards)")
    if "unsupported" in parsed.features:
        result.warnings.append(
            "pattern uses recursion/subroutine calls or PCRE verbs: that part was not analysed")

    try:
        g = build_graph(parsed.root)
    except Exception as e:  # TooComplex or similar
        result.findings.append(Finding(
            "info", "info",
            "Pattern too large for exact static analysis (%s); try --timeout-only mode." % e))
        return result

    result.n_positions = g.n
    result.truncated = g.truncated
    result.approx_counts = g.approx_counts
    if g.approx_counts:
        result.warnings.append(
            "a large bounded repeat count ({n,m} with m > %d) was approximated as unbounded "
            "for analysis purposes" % 8)

    eda = _EDASearch(g).run()
    result.findings.extend(eda)
    _scan_ida(parsed.root, result.findings)

    result.findings = _dedupe_findings(result.findings)
    result.findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return result


_MAX_FINDINGS_PER_PATTERN = 5


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """Collapse findings that point at overlapping source spans.

    The product-automaton search can rediscover the same underlying
    ambiguity from several different seeds (e.g. once per alternation
    branch), producing multiple findings whose spans overlap heavily. Only
    the single most severe finding per overlapping-span cluster is useful to
    a reader; the rest are noise. Clusters are kept separate (not merged) if
    their spans do not overlap, since those represent genuinely different
    parts of the pattern.
    """
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with_span = [f for f in findings if f.span]
    without_span = [f for f in findings if not f.span]
    with_span.sort(key=lambda f: (f.span[0], -f.span[1]))

    clusters: List[List[Finding]] = []
    for f in with_span:
        placed = False
        for cluster in clusters:
            lo = min(c.span[0] for c in cluster)
            hi = max(c.span[1] for c in cluster)
            if f.span[0] < hi and f.span[1] > lo:  # overlaps this cluster's span
                cluster.append(f)
                placed = True
                break
        if not placed:
            clusters.append([f])

    representatives: List[Finding] = []
    for cluster in clusters:
        cluster.sort(key=lambda f: (order.get(f.severity, 9), -len(f.pump_group)))
        best = cluster[0]
        if len(cluster) > 1:
            extra_kinds = sorted({c.kind for c in cluster})
            best.detail = (best.detail + " " if best.detail else "") + (
                "(%d related findings collapsed into this one)" % len(cluster))
        representatives.append(best)

    representatives.sort(key=lambda f: order.get(f.severity, 9))
    kept = representatives[:_MAX_FINDINGS_PER_PATTERN]
    return kept + without_span[: max(0, _MAX_FINDINGS_PER_PATTERN - len(kept))]
