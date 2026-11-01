"""Pull regular-expression literals out of source files.

This is intentionally a lightweight lexical scan, not a full parser for each
language: it looks for the call sites and literal forms developers actually
use (`re.compile(...)`, `/pattern/flags`, `preg_match(...)`, `new RegExp(...)`,
`Pattern.compile(...)`) and extracts the pattern text plus flags. False
positives (a string that merely looks like a regex) are expected and are
filtered later by the parser simply failing to parse -- extraction optimises
for not missing real patterns over never flagging a non-pattern.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

LANG_BY_EXT = {
    ".py": "python", ".pyi": "python",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js",
    ".php": "php", ".phtml": "php",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "dotnet",
    ".go": "go",
    ".rb": "ruby",
    ".c": "c", ".h": "c",
    ".sh": "bash", ".bash": "bash",
}

SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "__pycache__",
             "dist", "build", "target", ".tox", "site-packages"}


@dataclass
class Candidate:
    path: str
    line: int
    col: int
    pattern: str
    flags: str
    flavor: str
    raw: str
    context: str


def iter_files(root: str, extra_exts: Optional[List[str]] = None) -> Iterator[Path]:
    exts = set(LANG_BY_EXT) | set(extra_exts or [])
    p = Path(root)
    if p.is_file():
        if p.suffix in exts:
            yield p
        return
    for sub in p.rglob("*"):
        if sub.is_dir():
            continue
        if any(part in SKIP_DIRS for part in sub.parts):
            continue
        if sub.suffix in exts:
            yield sub


# --- per-language literal matchers -----------------------------------------
_PY_STR = r"""(?P<q>'''|\"\"\"|'|")(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)"""
_PY_CALL = re.compile(
    r"\b(?:re|regex)\.(?:compile|match|fullmatch|search|findall|finditer|sub|subn|split)\s*\(\s*"
    r"(?:r|R|rb|Rb|br|Br)?" + _PY_STR, re.VERBOSE)
_PY_PREFIXED = re.compile(r"\b(?:r|R)" + _PY_STR)

_JS_CALL = re.compile(
    r"\bnew\s+RegExp\s*\(\s*(?P<q>'|\"|`)(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)"
    r"(?:\s*,\s*(?P<q2>'|\"|`)(?P<flags>[a-z]*)(?P=q2))?")
_JS_LITERAL = re.compile(
    r"(?<![\w$)\]])/(?P<body>(?:\\.|\[(?:\\.|[^\]])*\]|[^/\\\n])+)/(?P<flags>[a-z]*)")
_JS_CALL_SITE = re.compile(r"\.(?:test|exec|match|matchAll|replace|replaceAll|split)\s*\(")

# PHP: preg_* functions take a delimited pattern string. Non-paired
# delimiters (/, #, ~, %, !) are by far the common case in real code, so
# that's what's supported; bracket-paired delimiters ({}, (), [], <>) are
# rarer and intentionally left unextracted rather than risking a fragile
# regex-of-regexes.
_PHP_CALL = re.compile(
    r"\b(?:preg_match|preg_match_all|preg_replace|preg_split|preg_quote|preg_grep|preg_replace_callback)\s*\(\s*"
    r"(?P<q>'|\")(?P<delim>[/#~%!])(?P<body>(?:\\.|(?!(?P=delim)|(?P=q))[^\\])*)(?P=delim)(?P<flags>[a-zA-Z]*)(?P=q)")

_JAVA_CALL = re.compile(
    r"\bPattern\.compile\s*\(\s*(?P<q>\"|\"\"\")(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)"
    r"(?:\s*,\s*(?P<flagsexpr>[\w.| ]+))?")

_DOTNET_CALL = re.compile(
    r"\bnew\s+Regex\s*\(\s*(?:@)?(?P<q>\"|\"\"\")(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)"
    r"(?:\s*,\s*RegexOptions\.(?P<flagsexpr>[\w\s|.]+))?")

_GO_CALL = re.compile(
    r"\bregexp\.(?:MustCompile|Compile)(?:POSIX)?\s*\(\s*`(?P<backtick>[^`]*)`"
    r"|\bregexp\.(?:MustCompile|Compile)(?:POSIX)?\s*\(\s*\"(?P<body>(?:\\.|[^\"\\])*)\"")

_RUBY_LITERAL = re.compile(r"(?<![\w)\]])/(?P<body>(?:\\.|\[(?:\\.|[^\]])*\]|[^/\\\n])+)/(?P<flags>[imxounse]*)")

# Kotlin: Regex("..."), "...".toRegex(), and Java's Pattern.compile("...") (Kotlin
# can call Java APIs directly with the same syntax).
_KOTLIN_REGEX_CTOR = re.compile(r"""\bRegex\s*\(\s*(?P<q>")(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)""")
_KOTLIN_TO_REGEX = re.compile(r"""(?P<q>")(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)\s*\.\s*toRegex\s*\(""")

# C: regcomp(&re, "pattern", flags) -- POSIX extended regex, close enough to
# PCRE syntax for the tolerant parser; exact POSIX-ERE quirks are a known
# approximation (see docs/METHOD.md).
_C_REGCOMP = re.compile(r"""\bregcomp\s*\(\s*&?\s*\w+\s*,\s*(?P<q>")(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)""")

# Bash: [[ $x =~ pattern ]] (quoted or bare token) and grep/egrep -E/-P 'pattern'.
_BASH_COND = re.compile(r"""=~\s*(?:(?P<q>["'])(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)|(?P<bare>[^\s\]]+))""")
_BASH_GREP = re.compile(
    r"""\b(?:egrep|grep\s+(?:-\w+\s+)*-[A-Za-z]*[EP][A-Za-z]*)\s+(?:-\w+\s+)*"""
    r"""(?P<q>["'])(?P<body>(?:\\.|(?!(?P=q)).)*?)(?P=q)""")


def _line_col(text: str, idx: int):
    line = text.count("\n", 0, idx) + 1
    last_nl = text.rfind("\n", 0, idx)
    col = idx - last_nl
    return line, col


def _unescape_py(body: str, raw_prefix: bool) -> str:
    if raw_prefix:
        return body
    try:
        return body.encode("utf-8").decode("unicode_escape")
    except Exception:
        return body


def _context_line(text: str, idx: int) -> str:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    end = end if end >= 0 else len(text)
    return text[start:end].strip()[:160]


def extract_python(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _PY_CALL.finditer(text):
        raw = text[m.start():m.end()]
        is_raw = bool(re.match(r"\b(?:re|regex)\.\w+\s*\(\s*(r|R|rb|Rb|br|Br)", raw))
        body = m.group("body")
        pattern = _unescape_py(body, is_raw)
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, pattern, "", "python", raw[:80], _context_line(text, m.start())))
    # bare r"..." assigned to a variable that looks pattern-ish is too noisy;
    # skip bare prefixed strings to keep precision high.
    return out


def extract_js(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _JS_CALL.finditer(text):
        flags = m.group("flags") or ""
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, m.group("body"), flags, "js",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    for m in _JS_LITERAL.finditer(text):
        # Heuristic: only accept a /.../ literal if it's followed (within a
        # short distance) by a regex-ish call, or preceded by typical
        # assignment/compare context, to avoid matching division operators.
        tail = text[m.end():m.end() + 40]
        head = text[max(0, m.start() - 20):m.start()]
        looks_like_regex = bool(_JS_CALL_SITE.match(tail.lstrip())) or bool(
            re.search(r"(=|\(|,|return|:|\|\|)\s*$", head))
        body = m.group("body")
        if not looks_like_regex or len(body) < 1:
            continue
        if re.fullmatch(r"[\w\s./*+-]*", body) and "\\" not in body and len(body) < 3:
            continue  # almost certainly arithmetic, e.g. `a / b/c`
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, body, m.group("flags") or "", "js",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    return out


def extract_php(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _PHP_CALL.finditer(text):
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, m.group("body"), m.group("flags") or "", "php",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    return out


_JAVA_FLAG_MAP = {"CASE_INSENSITIVE": "i", "DOTALL": "s", "COMMENTS": "x", "MULTILINE": "m"}


def extract_java(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _JAVA_CALL.finditer(text):
        flags = "".join(v for k, v in _JAVA_FLAG_MAP.items() if m.group("flagsexpr") and k in m.group("flagsexpr"))
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, m.group("body"), flags, "java",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    return out


_DOTNET_FLAG_MAP = {"IgnoreCase": "i", "Singleline": "s", "IgnorePatternWhitespace": "x", "Multiline": "m"}


def extract_dotnet(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _DOTNET_CALL.finditer(text):
        flags = "".join(v for k, v in _DOTNET_FLAG_MAP.items() if m.group("flagsexpr") and k in m.group("flagsexpr"))
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, m.group("body"), flags, "dotnet",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    return out


def extract_go(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _GO_CALL.finditer(text):
        body = m.group("backtick") if m.group("backtick") is not None else m.group("body")
        gi = m.start("backtick") if m.group("backtick") is not None else m.start("body")
        line, col = _line_col(text, gi)
        out.append(Candidate(path, line, col, body, "", "pcre",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    return out


def extract_ruby(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _RUBY_LITERAL.finditer(text):
        head = text[max(0, m.start() - 20):m.start()]
        if not re.search(r"(=|\(|,|=~|match|return|:)\s*$", head):
            continue
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, m.group("body"), m.group("flags") or "", "pcre",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    return out


def extract_kotlin(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _KOTLIN_REGEX_CTOR.finditer(text):
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, m.group("body"), "", "pcre",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    for m in _KOTLIN_TO_REGEX.finditer(text):
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, m.group("body"), "", "pcre",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    out.extend(extract_java(text, path))  # Pattern.compile("...") works the same in Kotlin
    return out


def extract_c(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _C_REGCOMP.finditer(text):
        pattern = _unescape_py(m.group("body"), raw_prefix=False)
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, pattern, "", "pcre",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    return out


def extract_bash(text: str, path: str) -> List[Candidate]:
    out = []
    for m in _BASH_COND.finditer(text):
        body = m.group("body") if m.group("body") is not None else m.group("bare")
        if not body:
            continue
        gi = m.start("body") if m.group("body") is not None else m.start("bare")
        line, col = _line_col(text, gi)
        out.append(Candidate(path, line, col, body, "", "pcre",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    for m in _BASH_GREP.finditer(text):
        line, col = _line_col(text, m.start("body"))
        out.append(Candidate(path, line, col, m.group("body"), "", "pcre",
                              text[m.start():m.end()][:80], _context_line(text, m.start())))
    return out


_EXTRACTORS = {
    "python": extract_python,
    "js": extract_js,
    "php": extract_php,
    "java": extract_java,
    "kotlin": extract_kotlin,
    "dotnet": extract_dotnet,
    "go": extract_go,
    "ruby": extract_ruby,
    "c": extract_c,
    "bash": extract_bash,
}


def extract_from_text(text: str, lang: str, path: str = "<string>") -> List[Candidate]:
    fn = _EXTRACTORS.get(lang)
    if not fn:
        return []
    try:
        return fn(text, path)
    except re.error:
        return []


def extract_from_file(path: Path) -> List[Candidate]:
    lang = LANG_BY_EXT.get(path.suffix)
    if not lang:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return extract_from_text(text, lang, str(path))


def extract_from_path(root: str) -> List[Candidate]:
    out: List[Candidate] = []
    for f in iter_files(root):
        out.extend(extract_from_file(f))
    return out


def iter_file_texts(root: str) -> Iterator[tuple]:
    """Yield (path, lang, text) for every scannable source file under
    `root`, reading each file exactly once -- used so regex-literal
    extraction and the vulnscan rule scanner don't each re-read every file."""
    for f in iter_files(root):
        lang = LANG_BY_EXT.get(f.suffix)
        if not lang:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        yield str(f), lang, text
