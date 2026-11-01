"""Dynamic confirmation.

Static analysis in :mod:`engine` finds *leads*. This module turns a lead into
evidence by actually running the pattern, against increasing pump lengths,
through the regex engine the pattern is meant for, under a hard wall-clock
timeout, and fitting a curve to the measured growth. Exponential growth in
match time as input length increases linearly is the real-world signature of
catastrophic backtracking; this is what distinguishes a confirmed finding
from a theoretical one.
"""
from __future__ import annotations

import math
import multiprocessing as mp
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .engine import Finding


@dataclass
class TimingPoint:
    length: int
    seconds: float
    timed_out: bool


@dataclass
class DynamicResult:
    finding: Finding
    points: List[TimingPoint] = field(default_factory=list)
    verdict: str = "unknown"      # confirmed-exponential | confirmed-polynomial | inconclusive | not-reproduced
    growth_ratio: Optional[float] = None
    worst_seconds: float = 0.0
    worst_length: int = 0
    attack_string: str = ""


def _worker(pattern: str, flags: int, text: str, q: "mp.Queue") -> None:
    try:
        rx = re.compile(pattern, flags)
        t0 = time.perf_counter()
        rx.search(text)
        q.put(time.perf_counter() - t0)
    except Exception as e:  # pragma: no cover - defensive
        q.put(("error", str(e)))


def _timed_search(pattern: str, flags: int, text: str, timeout: float) -> Tuple[float, bool]:
    """Run `re.search` in a subprocess with a hard timeout.

    A subprocess (not a thread) is required: Python's `re` engine is a C
    extension that does not check for interrupts while backtracking, so a
    thread-based timeout cannot stop it. Killing the process is the only
    reliable way to bound a potentially-exponential search.
    """
    ctx = mp.get_context("fork") if hasattr(mp, "get_context") else mp
    q: mp.Queue = ctx.Queue()
    p = ctx.Process(target=_worker, args=(pattern, flags, text, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join(1)
        if p.is_alive():
            p.kill()
        return timeout, True
    try:
        val = q.get_nowait()
    except Exception:
        return timeout, True
    if isinstance(val, tuple):
        return 0.0, False  # engine-level error; treat as fast/no-op
    return val, False


def _re_flags(flag_str: str) -> int:
    f = 0
    if "i" in flag_str:
        f |= re.IGNORECASE
    if "s" in flag_str:
        f |= re.DOTALL
    if "x" in flag_str:
        f |= re.VERBOSE
    if "m" in flag_str:
        f |= re.MULTILINE
    return f


DEFAULT_LENGTHS = [5, 10, 15, 20, 25, 30]
DEFAULT_TIMEOUT = 1.0


def confirm(pattern: str, flags: str, finding: Finding,
            lengths: List[int] = None, timeout: float = DEFAULT_TIMEOUT) -> DynamicResult:
    lengths = lengths or DEFAULT_LENGTHS
    res = DynamicResult(finding=finding)
    reflags = _re_flags(flags)
    for n in lengths:
        attack = finding.pump_prefix + finding.pump_group * n
        # the non-matching suffix is what forces the engine to exhaust the
        # search space instead of succeeding on the first try
        attack += finding.pump_suffix.replace("\x00", "!") if finding.pump_suffix else "\x00"
        attack = attack.replace("\x00", "!")
        t, timed_out = _timed_search(pattern, reflags, attack, timeout)
        res.points.append(TimingPoint(n, t, timed_out))
        if t > res.worst_seconds:
            res.worst_seconds = t
            res.worst_length = n
            res.attack_string = attack
        if timed_out:
            break
    res.verdict, res.growth_ratio = _classify(res.points)
    return res


def _classify(points: List[TimingPoint]) -> Tuple[str, Optional[float]]:
    """Distinguish exponential from polynomial growth from timing samples.

    The key is the *per-character* growth factor ``b = (t2/t1)^(1/dn)``
    between consecutive samples with length gap ``dn``. For true exponential
    backtracking (``t ~ b^n``) this factor stays roughly constant as n grows,
    because each extra character still multiplies the work by the same
    branching factor. For polynomial growth (``t ~ n^d``) the per-character
    factor decays toward 1 as n grows, since a power law flattens out in
    relative (multiplicative) terms. A timeout is decisive on its own: no
    realistic small-degree polynomial produces a hard hang at a short input.
    """
    if any(p.timed_out for p in points):
        return "confirmed-exponential", None
    useful = [p for p in points if p.seconds > 1e-5]
    if len(useful) < 2:
        if points and points[-1].seconds > 0.25:
            return "confirmed-polynomial", None
        return "not-reproduced", None
    if points[-1].seconds < 0.01:
        return "not-reproduced", None

    factors = []
    for a, b in zip(useful, useful[1:]):
        dn = b.length - a.length
        if dn <= 0 or a.seconds <= 0:
            continue
        ratio = max(b.seconds / a.seconds, 1e-9)
        factors.append(ratio ** (1.0 / dn))

    if not factors:
        return "confirmed-polynomial" if points[-1].seconds > 0.1 else "inconclusive", None

    first_b, last_b = factors[0], factors[-1]
    # Sustained (non-decaying) per-character multiplier clearly above 1 is
    # the exponential signature; a factor decaying toward 1 as n grows is
    # the polynomial signature.
    if last_b > 1.01 and last_b >= first_b * 0.8:
        return "confirmed-exponential", last_b
    if points[-1].seconds > 0.05:
        return "confirmed-polynomial", last_b
    return "inconclusive", last_b


def min_pump_to_hang(pattern: str, flags: str, finding: Finding, target_seconds: float = 2.0,
                      max_len: int = 10000, timeout: float = 3.0) -> Optional[int]:
    """Binary-search the shortest pump count that makes the match take
    longer than `target_seconds`, for a convincing proof-of-concept."""
    reflags = _re_flags(flags)
    lo, hi = 1, 8
    while hi <= max_len:
        attack = (finding.pump_prefix + finding.pump_group * hi +
                  (finding.pump_suffix.replace("\x00", "!") if finding.pump_suffix else "!"))
        t, timed_out = _timed_search(pattern, reflags, attack, timeout)
        if timed_out or t >= target_seconds:
            break
        lo, hi = hi, hi * 2
    else:
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        attack = (finding.pump_prefix + finding.pump_group * mid +
                  (finding.pump_suffix.replace("\x00", "!") if finding.pump_suffix else "!"))
        t, timed_out = _timed_search(pattern, reflags, attack, timeout)
        if timed_out or t >= target_seconds:
            hi = mid
        else:
            lo = mid + 1
    return lo
