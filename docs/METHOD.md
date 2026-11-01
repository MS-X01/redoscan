# How redoscan works

redoscan has two independent layers. The static layer finds *leads*; the
dynamic layer turns a lead into *evidence*. Treat a static-only finding as
"worth a human look," and a dynamically-confirmed finding as "reproduced on
this machine, with this engine, just now."

## 1. Parse

`parser.py` turns the pattern text into an AST that is tolerant of the
syntax differences between Python's `re`, JavaScript, PCRE (PHP), Java and
.NET: named/atomic/non-capturing groups, lookaround, lazy and possessive
quantifiers, inline flags, verbose mode, `\p{...}` properties, POSIX
classes. Constructs the analysis genuinely cannot reason about soundly
(recursion, subroutine calls, conditional patterns, PCRE control verbs) are
kept as explicit `Unsupported` nodes rather than silently dropped, and are
listed in the pattern's warnings.

## 2. Build an NFA, then an epsilon-free position graph

`nfa.py` does a standard Thompson construction, then eliminates epsilon
transitions via closure, producing a graph where each node is "just consumed
character-edge *i*". Crucially, the epsilon closure keeps **path
multiplicity** (capped at 2): if two different epsilon paths both arrive at
the same edge, that is recorded, because it is exactly the "two ways to take
the same step" that makes `(a+)+` dangerous.

Atomic groups (`(?>...)`) and possessive quantifiers (`x++`) are tracked
separately: edges inside one are tagged with that group's identity. Backtracking
is suppressed inside such a group, so two paths that only diverge *within*
the same atomic scope are not real ambiguity — this is what lets redoscan
recognise `(?>a+)+` as the safe, already-fixed version of `(a+)+` instead of
flagging the fix itself.

## 3. Product-automaton search (EDA / IDA)

This is the core of the static analysis, following the approach used in the
academic literature on static ReDoS detection (Weideman, Van der Merwe et
al., *"Analyzing Matching Time Behavior of Backtracking Regular Expression
Matchers by Using Ambiguity of NFA"*, and the follow-up static-analysis work
built on it).

Build a graph on **pairs** of positions `(i, j)`, meaning "two independent
copies of the automaton, having read the same input so far, sitting right
after character-edges `i` and `j`". A pair transitions to `(i', j')` if both
`i → i'` and `j → j'` are reachable and their character sets overlap (i.e.
there is a next character both copies could read). Two copies can always
trivially pick the same transition, so the diagonal `(i, i)` is always
reachable and means nothing on its own — what matters is whether the pair was
ever produced by a **genuine divergence**: an off-diagonal pair, or a
diagonal pair reached by two distinct epsilon paths converging on the same
edge (multiplicity ≥ 2).

If the search finds a cycle back to a pair that was reached through genuine
divergence, that proves the regex can read the same substring in more than
one way and return to the same place — the substring is a *pump*. The last
step is what distinguishes **EDA** (exponential) from **IDA** (polynomial):

- If there is more than one distinct route from the pair back to itself —
  either a direct multiplicity-≥2 self-transition, or two different
  intermediate pairs that can each independently find their own way back —
  each lap through the loop offers a real choice. Repeating the pump `k`
  times multiplies the path count by a constant factor each time: `O(2^k)`.
  This is reported as **EDA / exponential**.
- If there is exactly one route back (a simple, deterministic cycle), the
  ambiguity contributes a single extra split point rather than a repeated
  branching choice. This is the signature of sequential/adjacent ambiguity
  (`\d+\d+`, `.*.*=.*`) and costs polynomial time, not exponential. Reported
  as **IDA / polynomial**, with the degree read off the AST-level scan below.

A separate, cheaper AST-level scan (`_scan_ida`) also flags chains of
adjacent unbounded quantifiers with overlapping character sets directly from
the syntax tree (`a*a*a*`, `\s*\s*\s*`) — this catches the common polynomial
case even when it doesn't cleanly surface as a single product-graph cycle,
and its reported degree is the number of overlapping groups chained
together.

Findings whose source spans overlap are collapsed to the single most severe
one before being shown — the product search often rediscovers the same
underlying ambiguity from several seeds, and a reader needs one actionable
item per vulnerable region, not five.

## 4. Dynamic confirmation

`dynamic.py` takes a finding's pump string, runs the *actual* pattern
against the *actual* regex engine (`re` for Python; the extractor also
records which language a pattern came from so a future version can dispatch
to `node`, PHP's PCRE, etc.) at increasing pump lengths, under a hard
subprocess timeout (a thread-based timeout cannot interrupt a C-level
regex engine mid-backtrack, so a killable subprocess is used instead).

Growth is classified by the **per-character growth factor**
`b = (t2/t1)^(1/Δn)` between consecutive samples. True exponential
backtracking (`t ~ b^n`) keeps this factor roughly constant as `n` grows,
because every additional character still multiplies the remaining work by
the same branching factor. Polynomial growth (`t ~ n^d`) makes this factor
decay toward 1 as `n` grows, because a power law flattens out in relative
terms. A hard timeout at a short input length is decisive on its own: no
realistic small-degree polynomial produces a multi-second hang at the input
lengths redoscan samples.

## 5. The other checks (vulnscan)

Everything above is `engine.py` and is specific to ReDoS. `vulnscan.py` is a
second, independent, and much simpler kind of analysis covering eleven more
vulnerability classes: SQL injection (CWE-89), command injection (CWE-78),
insecure deserialization (CWE-502), weak cryptography (CWE-327), insecure
randomness (CWE-330), path traversal (CWE-22), SSRF (CWE-918), IDOR
(CWE-639), denial of service via single-request resource exhaustion
(CWE-400/409/776), authentication/session weaknesses (CWE-798/614/352/347),
and memory safety in C (CWE-120/242).

Volumetric/network-layer DDoS is deliberately not one of them. It's an
infrastructure concern — rate limiting, a WAF/CDN, SYN cookies at the OS
level — not a property of the source code, so there's no regex that could
meaningfully detect it; claiming to would be exactly the overstated-
confidence problem this whole module tries to avoid by labelling itself
`heuristic`. The `dos` category instead covers what *is* a code-level
pattern: a single request that can make the server do unbounded work (a
decompression bomb, unchecked XML entity expansion, an unbounded request
body).

It works by regular-expression pattern matching over source text -- the same
basic technique as a grep-based linter -- not by building and reasoning
about an automaton. That is a meaningfully weaker form of evidence than the
ReDoS engine provides, and redoscan says so explicitly: every finding from
this module carries `confidence="heuristic"`, is labelled "pattern-matched
lead, not proven" in every report, and is never backed by the dynamic
timing confirmation `dynamic.py` provides for ReDoS. Treat it as a triage
list a human still has to walk through, not a verdict.

A few rules go further and check the *context* around a match, not just the
match itself -- e.g. the IDOR rules suppress the finding if a common
auth/ownership keyword (`current_user`, `@login_required`, `->authorize`, ...)
appears nearby, on the theory that its presence probably means a check
already exists. This cuts obvious false positives but is still fundamentally
shallow: IDOR in particular is a *business-logic* flaw (does this specific
check correctly enforce ownership for this specific resource?), which cannot
be determined from syntax alone. A finding here means "worth a human
look", never "confirmed vulnerable", and a clean scan means "nothing these
patterns recognise", never "provably safe" -- unlike a ReDoS finding, which
is backed by an actual construction, or a ReDoS *clean* result, which means
the product-automaton search covered every reachable pair and found none.

## Known limitations

- **Backreferences and recursion** make matching formally undecidable in
  general; such patterns are parsed and their other parts are still
  analysed, but the backreference/recursive part itself is treated as a
  wildcard and the pattern is flagged with a warning rather than silently
  trusted.
- **Bounded repeats** above a small cap (`{n,m}` with `m` large) are
  approximated as unbounded, since the exact count rarely changes whether a
  construct is ambiguous, and keeping the exact count would blow up the
  state space for no analytical benefit.
- **Patterns above ~220 character-matching positions** are not analysed
  exactly; redoscan reports this explicitly rather than guessing.
- Dynamic confirmation only runs against **Python's `re`** today — a finding
  from a JS/PHP/Java/.NET source file is still statically analysed in that
  flavour's syntax, but `--confirm` times it against Python's engine as an
  approximation, which is usually representative (all of these are
  backtracking NFA engines with the same fundamental failure mode) but can
  differ in exact constants.
- This is a **heuristic tool**, not a formal verifier. Treat every finding as
  a lead worth a human look, dynamically confirmed findings as reproduced
  evidence, and the absence of a finding as "nothing found by these two
  analyses" rather than a proof of safety.
