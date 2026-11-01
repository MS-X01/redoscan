"""Rendering: terminal (ANSI colour), JSON, and a static HTML report.

Two different kinds of finding flow through here: ReDoS findings from
`engine.py` (category="redos", confidence="confirmed-by-analysis", backed by
an attack-string "pump" that can be grown to a proof) and vulnscan findings
from `vulnscan.py` (other categories, confidence="heuristic", backed by a
single matched source line). Both are `Finding` objects so they share one
rendering path, but the bit of detail shown per finding -- an attack sample
vs. a CWE + "verify by hand" note -- differs by what's actually available.
"""
from __future__ import annotations

import html
import json
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .engine import AnalysisResult, Finding
from .html_template import TEMPLATE
from .vulnscan import CATEGORY_LABELS

SEV_COLOR = {
    "critical": "\033[1;97;41m",  # white on red
    "high": "\033[1;31m",         # red
    "medium": "\033[1;33m",       # yellow
    "low": "\033[1;36m",          # cyan
    "info": "\033[0;90m",         # grey
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

def _c(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{RESET}" if use_color else text


_DISPLAY_SUBS = {" ": "\u00b7", "\t": "\u2192"}  # space -> ·, tab -> →, for visibility only


def format_pump_sample(finding: Finding, repeats: Optional[int] = None) -> str:
    n = repeats or min(finding.repeats_hint, 40)
    sample = finding.pump(n).replace("\x00", "")
    if len(sample) > 60:
        sample = sample[:57] + "..."
    out_chars = []
    for c in sample:
        if c in _DISPLAY_SUBS:
            out_chars.append(_DISPLAY_SUBS[c])
        elif c.isprintable():
            out_chars.append(c)
        else:
            out_chars.append(repr(c)[1:-1])
    return "".join(out_chars) or "(empty)"


_SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_ORDER_LIST = ["critical", "high", "medium", "low", "info"]


def _short_message(message: str) -> str:
    cut = message.find(". ")
    return message if cut < 0 else message[:cut + 1]


def _sev_tag(sev: str, use_color: bool, width: int = 8) -> str:
    label = _SEV_LABEL.get(sev, sev.upper()).ljust(width)
    return _c(label, SEV_COLOR.get(sev, ""), use_color)


def _category_counts(results: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in results:
        for f in e["result"].findings:
            counts[f.category] = counts.get(f.category, 0) + 1
    return counts


def render_terminal(results: List[Dict[str, Any]], use_color: bool = True, verbose: bool = False,
                     scanned_desc: Optional[str] = None) -> str:
    # With colour off, the style constants must be empty too -- otherwise raw
    # escape codes leak into pipes and saved .txt reports.
    BOLD, DIM, RESET = (globals()["BOLD"], globals()["DIM"], globals()["RESET"]) if use_color else ("", "", "")
    flagged = [e for e in results if e["result"].findings]
    clean = [e for e in results if not e["result"].findings]
    scanned_desc = scanned_desc if scanned_desc is not None else "%d location(s) scanned" % len(results)
    sev_counts: Dict[str, int] = {}
    for e in flagged:
        sev_counts[e["result"].worst_severity] = sev_counts.get(e["result"].worst_severity, 0) + 1
    cat_counts = _category_counts(results)

    out: List[str] = []

    # --- summary bar ---------------------------------------------------
    if flagged:
        parts = [f"{_sev_tag(s, use_color, 0)} {sev_counts[s]}" for s in _SEV_ORDER_LIST if sev_counts.get(s)]
        out.append("  ".join(parts))
        cat_parts = [f"{CATEGORY_LABELS.get(c, c.upper())}: {n}" for c, n in
                     sorted(cat_counts.items(), key=lambda kv: -kv[1]) if c != "redos"]
        redos_n = cat_counts.get("redos", 0)
        if redos_n:
            cat_parts.insert(0, f"ReDoS: {redos_n}")
        if cat_parts:
            out.append(_c("  ".join(cat_parts), "\033[2m", use_color))
    else:
        out.append(_c("no issues found", "\033[1;32m", use_color))
    out.append(_c(f"{len(flagged)} location(s) flagged -- {scanned_desc}", "\033[2m", use_color))
    out.append("")

    # --- flagged locations, most severe first ---------------------------
    flagged.sort(key=lambda e: _SEV_ORDER.get(e["result"].worst_severity, 9))
    rule = _c("\u2500" * 64, "\033[2m", use_color)
    for entry in flagged:
        r: AnalysisResult = entry["result"]
        loc = entry.get("location", "<source>")
        code = entry.get("display_code", "")
        out.append(rule)
        out.append(f"{_sev_tag(r.worst_severity, use_color)} {BOLD}{loc}{RESET}" if use_color
                    else f"[{_SEV_LABEL.get(r.worst_severity)}] {loc}")
        out.append(f"  {code}")
        out.append("")
        shown = r.findings if verbose else r.findings[:3]
        for i, f in enumerate(shown):
            kind_tag = _c(f"{f.kind:>6}", SEV_COLOR.get(f.severity, ""), use_color)
            msg = f.message if verbose else _short_message(f.message)
            out.append(f"  {kind_tag}  {msg}")
            if f.category == "redos":
                sample = format_pump_sample(f)
                out.append(f"          {DIM}sample: {sample}{RESET}")
            else:
                tag = f"{f.cwe} \u00b7 " if f.cwe else ""
                out.append(f"          {DIM}{tag}pattern-matched lead, not proven -- verify by hand{RESET}")
            if verbose and f.detail:
                out.append(f"          {DIM}{f.detail}{RESET}")
            dyn = entry.get("dynamic", {}).get(id(f))
            if dyn:
                v = dyn.get("verdict", "")
                vcolor = "\033[1;31m" if v.startswith("confirmed") else "\033[2m"
                out.append(f"          {_c('confirmed:', vcolor, use_color)} {v}  "
                            f"(worst {dyn.get('worst_seconds', 0):.3f}s at {dyn.get('worst_length', '?')}x)")
                if dyn.get("poc_repeats"):
                    out.append(f"          {DIM}proof of concept: {dyn['poc_repeats']}x the sample unit above{RESET}")
            if i < len(shown) - 1:
                out.append("")
        if len(r.findings) > len(shown):
            out.append(f"  {DIM}+ {len(r.findings) - len(shown)} more finding(s) here (--verbose){RESET}")
        if r.warnings:
            out.append("")
            for w in r.warnings:
                out.append(f"  {_c('note:', DIM, use_color)} {w}")
        out.append("")

    if verbose and clean:
        out.append(rule)
        for entry in clean:
            ok = _c("OK", "\033[32m", use_color)
            out.append(f"  {ok}  {entry.get('location', '<source>')}")
        out.append("")

    total_findings = sum(len(e["result"].findings) for e in flagged)
    out.append(rule)
    summary_color = "\033[1;31m" if total_findings else "\033[1;32m"
    out.append(_c(f"{total_findings} finding(s) in {len(flagged)} location(s) -- {scanned_desc}",
                   summary_color, use_color))
    return "\n".join(out)


def to_json(results: List[Dict[str, Any]]) -> str:
    payload = []
    for entry in results:
        r: AnalysisResult = entry["result"]
        payload.append({
            "location": entry.get("location"),
            "code_label": entry.get("code_label", "pattern"),
            "code": entry.get("display_code", ""),
            "flags": entry.get("flags", ""),
            "flavor": entry.get("flavor", "auto"),
            "severity": r.worst_severity,
            "n_positions": r.n_positions,
            "truncated": r.truncated,
            "approx_counts": r.approx_counts,
            "warnings": r.warnings,
            "findings": [
                {
                    "kind": f.kind,
                    "category": f.category,
                    "cwe": f.cwe,
                    "confidence": f.confidence,
                    "severity": f.severity,
                    "message": f.message,
                    "span": f.span,
                    "degree": f.degree,
                    "detail": f.detail,
                    "evidence": f.evidence,
                    "attack_sample": format_pump_sample(f) if f.category == "redos" else None,
                    "repeats_hint": f.repeats_hint,
                    "dynamic": entry.get("dynamic", {}).get(id(f)),
                }
                for f in r.findings
            ],
        })
    return json.dumps({"generated": int(time.time()), "results": payload}, indent=2)


_LANG_LABELS = {
    "python": "Python", "js": "JavaScript / TypeScript", "php": "PHP", "java": "Java",
    "kotlin": "Kotlin", "dotnet": "C# / .NET", "c": "C", "bash": "Bash", "go": "Go",
    "ruby": "Ruby", "pcre": "Regex (PCRE)", "auto": "Regex (CLI)", "": "Unknown",
}

_FAVICON_SVG = (
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 26 26'%3E"
    "%3Crect width='26' height='26' rx='6' fill='%231D1D1D'/%3E"
    "%3Cpath d='M13 4 L21 7.5 V13 C21 18 17.5 21.3 13 22.5 C8.5 21.3 5 18 5 13 V7.5 Z' "
    "stroke='%23FF0000' stroke-width='1.6' fill='none'/%3E"
    "%3Cpath d='M10 13 L12 15 L16.5 10' stroke='%23FF0000' stroke-width='1.8' "
    "stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E"
)


def _relative_to_target(file: str, target: Optional[str]) -> str:
    """Show paths relative to the scanned directory (keeps the report short and
    avoids leaking the absolute path of the machine it was generated on)."""
    import os
    if not target or target.startswith("<"):
        return file
    try:
        base = target if os.path.isdir(target) else os.path.dirname(target)
        rel = os.path.relpath(os.path.abspath(file), base)
        return file if rel.startswith("..") else rel.replace(os.sep, "/")
    except ValueError:
        return file


def _split_location(entry: Dict[str, Any]):
    """(file, line) for an entry, preferring explicit keys set by the CLI."""
    if entry.get("path"):
        return entry["path"], int(entry.get("line") or 0)
    loc = entry.get("location") or "<source>"
    head, _, tail = loc.rpartition(":")
    if head and tail.isdigit():
        return head, int(tail)
    return loc, 0


def build_report_data(results: List[Dict[str, Any]], scanned_desc: Optional[str] = None,
                      target: Optional[str] = None) -> Dict[str, Any]:
    """Flatten scan results into the JSON structure the HTML report renders."""
    findings: List[Dict[str, Any]] = []
    clean: List[Dict[str, Any]] = []
    used_cats = set()
    used_langs = set()
    for entry in results:
        r: AnalysisResult = entry["result"]
        file, line = _split_location(entry)
        file = _relative_to_target(file, target)
        lang = entry.get("lang") or entry.get("flavor") or ""
        used_langs.add(lang)
        if not r.findings:
            clean.append({"file": file, "line": line, "lang": lang,
                          "code": entry.get("display_code", "")})
            continue
        for f in r.findings:
            used_cats.add(f.category)
            dyn = entry.get("dynamic", {}).get(id(f))
            is_redos = f.category == "redos"
            sample_raw = ""
            sample = ""
            if is_redos:
                sample = format_pump_sample(f)
                sample_raw = f.pump(min(f.repeats_hint, 40)).replace("\x00", "")
            findings.append({
                "severity": f.severity,
                "category": f.category,
                "kind": f.kind,
                "cwe": f.cwe or ("CWE-1333" if is_redos else ""),
                "conf": "heuristic" if f.confidence == "heuristic" else "proven",
                "lang": lang,
                "file": file,
                "line": line,
                "message": f.message,
                "detail": f.detail or "",
                "code": entry.get("display_code", ""),
                "codeLabel": entry.get("code_label", "pattern"),
                "evidence": f.evidence or "",
                "sample": sample,
                "sampleRaw": sample_raw,
                "dyn": dyn,
                "warnings": list(r.warnings),
            })
    cat_labels = {c: CATEGORY_LABELS.get(c, "ReDoS" if c == "redos" else c)
                  for c in used_cats | {"redos"}}
    return {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "scanned": scanned_desc or "%d location(s) scanned" % len(results),
        "target": target or "",
        "findings": findings,
        "clean": clean,
        "catLabels": cat_labels,
        "langLabels": {l: _LANG_LABELS.get(l, l) for l in used_langs | set(_LANG_LABELS)},
    }


def _json_for_script(obj: Any) -> str:
    """JSON that is safe to embed inside a <script> element."""
    return (json.dumps(obj, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def render_html(results: List[Dict[str, Any]], scanned_desc: Optional[str] = None,
                target: Optional[str] = None) -> str:
    """Self-contained, searchable, filterable HTML report (see html_template.py)."""
    data = build_report_data(results, scanned_desc, target)
    n = len(data["findings"])
    title_suffix = " \u2014 %d finding(s)" % n if n else " \u2014 clean"
    return (TEMPLATE
            .replace("@@TITLE_SUFFIX@@", title_suffix)
            .replace("@@FAVICON@@", _FAVICON_SVG)
            .replace("@@VERSION@@", __version__)
            .replace("@@DATA@@", _json_for_script(data)))
