"""redoscan command-line interface."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .dynamic import confirm, min_pump_to_hang
from .engine import AnalysisResult, analyse
from .extractor import Candidate, extract_from_text, iter_file_texts
from .report import render_html, render_terminal, to_json
from .vulnscan import CATEGORY_LABELS, scan_text

_FLAVOR_BY_LANG = {
    "python": "python", "js": "js", "php": "pcre", "java": "pcre",
    "kotlin": "pcre", "dotnet": "dotnet", "pcre": "pcre",
    # C uses POSIX extended regex and bash uses POSIX ERE/BRE depending on
    # context; both are close enough to PCRE syntax for the tolerant parser
    # that treating them as "pcre" is a reasonable approximation, not an
    # exact match -- see docs/METHOD.md.
    "c": "pcre", "bash": "pcre",
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}
VULN_CATEGORIES = sorted(CATEGORY_LABELS)


_DESCRIPTION = """\
redoscan %s - find ReDoS-vulnerable regexes, and prove it.
Static automaton analysis + dynamic timing, plus pattern-based checks for
11 more vulnerability classes (SQLi, CMDi, deserialization, crypto, SSRF,
IDOR, DoS, auth, memory safety, ...) across 10 languages.
""" % __version__

_EXAMPLES = """\
Examples:
  redoscan ./src                          scan a project; also saves an HTML report
  redoscan --pattern '^(a+)+$'            check one regex, no files needed
  redoscan ./src --checks redos           ReDoS engine only
  redoscan ./src --category sqli,cmdi     only these vulnerability categories
  redoscan ./src --confirm                time each ReDoS finding against the real engine
  redoscan ./src --poc                    also print the shortest hanging input (PoC)
  redoscan ./src -f json -o report.json   machine-readable output
  redoscan ./src --fail-on high --no-html-report
                                          CI gate: exit 1 on critical/high, skip HTML

Exit status:
  0   no finding at or above --fail-on
  1   at least one finding at or above --fail-on
  2   usage error (bad option, missing target, unknown category)

Files:
  redoscan-report-<timestamp>.html        saved after every scan (see --no-html-report)

Docs:    docs/METHOD.md  (how it works; what "confirmed" vs "heuristic" means)
Project: https://github.com/MS-X01/redoscan
"""


class _LinuxHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Help layout in the style of classic Unix tools: long option first, then
    the short alias, then the value placeholder:

        --format, -f {terminal,json,html}    primary output ...

    instead of argparse's default ``--format {..}, -f {..}`` which repeats the
    placeholder after every alias."""

    def __init__(self, prog, indent_increment=2, max_help_position=34, width=None):
        super().__init__(prog, indent_increment, max_help_position, width)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)
        opts = sorted(action.option_strings, key=lambda o: (not o.startswith("--"), len(o)))
        if action.nargs == 0:
            return ", ".join(opts)
        metavar = self._format_args(action, self._get_default_metavar_for_optional(action))
        return "%s %s" % (", ".join(opts), metavar)

    def _format_usage(self, usage, actions, groups, prefix):
        return super()._format_usage(usage, actions, groups, "Usage: ")


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redoscan",
        usage="redoscan [OPTIONS] TARGET\n       redoscan [OPTIONS] --pattern REGEX",
        formatter_class=_LinuxHelpFormatter,
        add_help=False,
        description=_DESCRIPTION,
        epilog=_EXAMPLES)

    g = p.add_argument_group("Target")
    g.add_argument("target", nargs="?", default=None, metavar="TARGET",
                   help="file or directory to scan (omit when using --pattern)")
    g.add_argument("--pattern", "-e", action="append", default=[], metavar="REGEX",
                   help="scan one regex given on the command line; repeatable "
                        "(ReDoS checks only)")
    g.add_argument("--flags", default="", metavar="FLAGS",
                   help="flags applied to --pattern, e.g. 'i'")
    g.add_argument("--flavor", default="auto", choices=["auto", "python", "js", "pcre", "dotnet"],
                   help="regex dialect to assume for --pattern (default: auto)")

    g = p.add_argument_group("Analysis")
    g.add_argument("--checks", choices=["all", "redos", "vulns"], default="all",
                   help="what to run: ReDoS engine, the other vulnerability checks, or both "
                        "(default: all)")
    g.add_argument("--category", action="append", default=[], metavar="CATS",
                   help="limit vulnerability checks to these categories, comma-separated "
                        "or repeated; see --list-categories")
    g.add_argument("--list-categories", action="store_true",
                   help="print the available --category values and exit")
    g.add_argument("--confirm", action="store_true",
                   help="time each ReDoS finding against the real engine (slower; one "
                        "subprocess per sample, hard-killed on timeout)")
    g.add_argument("--confirm-timeout", type=float, default=1.0, metavar="SECONDS",
                   help="per-sample timeout for --confirm (default: 1.0)")
    g.add_argument("--poc", action="store_true",
                   help="print the shortest input that makes a confirmed finding take "
                        ">2s (implies --confirm)")

    g = p.add_argument_group("Filtering")
    g.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"],
                   default="info", help="only report findings at or above this level "
                                        "(default: info)")
    g.add_argument("--confidence", choices=["all", "confirmed", "heuristic"], default="all",
                   help="'confirmed' = automaton-proven ReDoS only; 'heuristic' = "
                        "pattern-matched leads only (default: all)")

    g = p.add_argument_group("Output")
    g.add_argument("--format", "-f", choices=["terminal", "json", "html"], default="terminal",
                   help="primary output format (default: terminal)")
    g.add_argument("--output", "-o", metavar="FILE",
                   help="write the primary report to FILE instead of stdout")
    g.add_argument("--save", action="store_true",
                   help="also save the primary report to an auto-named file")
    g.add_argument("--html-report", default=None, metavar="FILE",
                   help="write the HTML report to FILE (default: "
                        "redoscan-report-<timestamp>.html)")
    g.add_argument("--no-html-report", action="store_true",
                   help="do not auto-save the HTML report")
    g.add_argument("--verbose", "-v", action="store_true",
                   help="full finding detail, and list clean patterns too")
    g.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    g = p.add_argument_group("CI")
    g.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any", "never"],
                   default="high",
                   help="exit 1 if a finding at or above this severity exists; 'never' "
                        "always exits 0 (default: high)")

    g = p.add_argument_group("Misc")
    g.add_argument("--version", action="version", version="redoscan %s" % __version__,
                   help="show version and exit")
    g.add_argument("--help", "-h", action="help", help="show this help and exit")
    return p


def _target_label(args) -> str:
    if args.pattern:
        return "<%d pattern(s) from the command line>" % len(args.pattern)
    return str(Path(args.target).resolve()) if args.target else ""


class CliError(Exception):
    pass


def _parse_categories(raw: List[str]) -> Optional[set]:
    if not raw:
        return None
    cats = set()
    for item in raw:
        cats.update(c.strip().lower() for c in item.split(",") if c.strip())
    unknown = cats - set(VULN_CATEGORIES)
    if unknown:
        raise CliError(
            "unknown --category value(s): %s (choices: %s)" %
            (", ".join(sorted(unknown)), ", ".join(VULN_CATEGORIES)))
    return cats


def _flavor_for_lang(lang: str, override: str) -> str:
    if override and override != "auto":
        return override
    return _FLAVOR_BY_LANG.get(lang, "auto")


def _collect_from_pattern_args(args) -> List[Dict[str, Any]]:
    entries = []
    for pat in args.pattern:
        r = analyse(pat, args.flags, args.flavor)
        entries.append({
            "location": "<cli>", "code_label": "pattern", "display_code": pat,
            "flags": args.flags, "flavor": args.flavor, "result": r,
        })
    return entries


class ScanTotals:
    def __init__(self):
        self.n_files = 0
        self.n_regex = 0

    def describe(self) -> str:
        parts = ["%d file(s)" % self.n_files]
        if self.n_regex:
            parts.append("%d regex pattern(s)" % self.n_regex)
        return ", ".join(parts) + " scanned"


def _collect_from_target(args, categories: Optional[set]) -> (List[Dict[str, Any]], "ScanTotals"):
    target = Path(args.target)
    if not target.exists():
        raise CliError("%s does not exist" % target)
    entries: List[Dict[str, Any]] = []
    totals = ScanTotals()
    for path, lang, text in iter_file_texts(str(target)):
        totals.n_files += 1
        if args.checks in ("all", "redos"):
            for cand in extract_from_text(text, lang, path):
                totals.n_regex += 1
                flavor = _flavor_for_lang(lang, args.flavor)
                r = analyse(cand.pattern, cand.flags, flavor)
                loc = "%s:%d" % (cand.path, cand.line)
                entries.append({
                    "location": loc, "code_label": "pattern", "display_code": cand.pattern,
                    "flags": cand.flags, "flavor": flavor, "result": r,
                    "path": cand.path, "line": cand.line, "lang": lang,
                })
        if args.checks in ("all", "vulns"):
            for loc, finding in scan_text(text, lang, path, categories=categories):
                _p, _, _ln = loc.rpartition(":")
                entries.append({
                    "location": loc, "code_label": "code", "display_code": finding.evidence,
                    "flags": "", "flavor": lang, "result": AnalysisResult(findings=[finding]),
                    "path": _p or loc, "line": int(_ln) if _ln.isdigit() else 0, "lang": lang,
                })
    return entries, totals


def _apply_filters(entries: List[Dict[str, Any]], args) -> List[Dict[str, Any]]:
    min_rank = SEVERITY_RANK.get(args.min_severity, 9)
    out = []
    for entry in entries:
        r: AnalysisResult = entry["result"]
        kept = [f for f in r.findings if SEVERITY_RANK.get(f.severity, 9) <= min_rank]
        if args.confidence == "confirmed":
            kept = [f for f in kept if f.confidence != "heuristic"]
        elif args.confidence == "heuristic":
            kept = [f for f in kept if f.confidence == "heuristic"]
        r.findings = kept
        if kept or args.verbose:
            out.append(entry)
    return out


def run(argv: Optional[List[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)

    if args.list_categories:
        for c in VULN_CATEGORIES:
            print("%-10s %s" % (c, CATEGORY_LABELS[c]))
        return 0

    try:
        categories = _parse_categories(args.category)
    except CliError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    try:
        if args.pattern:
            all_entries = _collect_from_pattern_args(args)
            scanned_desc = "%d pattern(s) scanned" % len(all_entries)
            n_scanned = len(all_entries)
        elif args.target:
            all_entries, totals = _collect_from_target(args, categories)
            scanned_desc = totals.describe()
            n_scanned = totals.n_files
        else:
            print("error: provide a file/directory to scan, or use --pattern", file=sys.stderr)
            return 2
    except CliError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    if n_scanned == 0:
        print("nothing to scan: no regex literals or matching source files found", file=sys.stderr)
        return 0

    results = _apply_filters(all_entries, args)

    if args.confirm or args.poc:
        for entry in results:
            r: AnalysisResult = entry["result"]
            redos_findings = [f for f in r.findings if f.category == "redos"]
            if not redos_findings:
                continue
            pattern = entry["display_code"] if entry["code_label"] == "pattern" else None
            if pattern is None:
                continue
            dyn_map = {}
            for f in redos_findings:
                d = confirm(pattern, entry.get("flags", ""), f, timeout=args.confirm_timeout)
                info = {"verdict": d.verdict, "growth_factor": d.growth_ratio,
                        "worst_seconds": d.worst_seconds, "worst_length": d.worst_length}
                if args.poc and d.verdict.startswith("confirmed"):
                    n = min_pump_to_hang(pattern, entry.get("flags", ""), f,
                                         timeout=max(2.5, args.confirm_timeout))
                    info["poc_repeats"] = n
                dyn_map[id(f)] = info
            entry["dynamic"] = dyn_map

    # --- primary output -------------------------------------------------
    if args.format == "json":
        out_text = to_json(results)
    elif args.format == "html":
        out_text = render_html(results, scanned_desc=scanned_desc, target=_target_label(args))
    else:
        out_text = render_terminal(results, use_color=(not args.no_color) and sys.stdout.isatty(),
                                    verbose=args.verbose, scanned_desc=scanned_desc)

    ext = {"terminal": "txt", "json": "json", "html": "html"}[args.format]
    save_path = args.output
    if args.save and not save_path:
        save_path = "redoscan-report-%s.%s" % (time.strftime("%Y%m%d-%H%M%S"), ext)
    if save_path:
        plain_text = out_text if args.format != "terminal" else render_terminal(
            results, use_color=False, verbose=args.verbose, scanned_desc=scanned_desc)
        Path(save_path).write_text(plain_text, encoding="utf-8")

    printed_to_stdout = not (args.output and not args.save)
    if printed_to_stdout:
        print(out_text)
    else:
        print("wrote %s" % save_path, file=sys.stderr)

    # --- HTML report, on by default --------------------------------------
    html_path = args.html_report
    if not args.no_html_report and html_path is None and args.format != "html":
        html_path = "redoscan-report-%s.html" % time.strftime("%Y%m%d-%H%M%S")
    if html_path:
        Path(html_path).write_text(render_html(results, scanned_desc=scanned_desc, target=_target_label(args)), encoding="utf-8")
        print("\nHTML report: %s (open it in a browser for the easiest view)" % html_path,
              file=sys.stderr)
    elif save_path and printed_to_stdout:
        print("saved to %s" % save_path, file=sys.stderr)

    if args.fail_on == "never":
        return 0
    threshold = "any" if args.fail_on == "any" else args.fail_on
    rank = -1 if threshold == "any" else SEVERITY_RANK[threshold]
    for entry in results:
        for f in entry["result"].findings:
            if threshold == "any" or SEVERITY_RANK.get(f.severity, 9) <= rank:
                return 1
    return 0


def main() -> None:
    try:
        sys.exit(run())
    except BrokenPipeError:
        # The reader (e.g. `| head`) closed the pipe early; that's not an
        # error from redoscan's point of view. Silence the default Python
        # traceback and avoid a second one on interpreter shutdown by
        # redirecting stdout to devnull before exiting.
        import os
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)


if __name__ == "__main__":
    main()
