import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from redoscan.extractor import extract_from_text

def test_python_compile_call():
    text = 'import re\nP = re.compile(r"^(a+)+$")\n'
    cands = extract_from_text(text, "python")
    assert [c.pattern for c in cands] == [r"^(a+)+$"]
    assert cands[0].line == 2

def test_python_raw_vs_escaped():
    text = r'''re.match(r'\d+', x)''' + '\n' + r'''re.match('\\d+', y)'''
    cands = extract_from_text(text, "python")
    assert all(c.pattern == r"\d+" for c in cands)

def test_js_new_regexp_with_flags():
    cands = extract_from_text('new RegExp("^a+$", "gi")', "js")
    assert cands[0].pattern == "^a+$"
    assert cands[0].flags == "gi"

def test_js_literal_requires_call_context():
    cands = extract_from_text("let y = a / b / c;", "js")
    assert cands == []

def test_js_literal_with_test_call():
    cands = extract_from_text("if (/^a+$/.test(x)) {}", "js")
    assert cands[0].pattern == "^a+$"

def test_php_preg_match():
    cands = extract_from_text("preg_match('/^a+$/i', $x);", "php")
    assert cands[0].pattern == "^a+$"
    assert cands[0].flags == "i"

def test_java_pattern_compile():
    cands = extract_from_text('Pattern.compile("^a+$", Pattern.CASE_INSENSITIVE);', "java")
    assert cands[0].pattern == "^a+$"
    assert cands[0].flags == "i"

def test_dotnet_new_regex():
    cands = extract_from_text('new Regex(@"^a+$", RegexOptions.IgnoreCase);', "dotnet")
    assert cands[0].pattern == "^a+$"
    assert cands[0].flags == "i"

def test_go_backtick_literal():
    cands = extract_from_text("regexp.MustCompile(`^a+$`)", "go")
    assert cands[0].pattern == "^a+$"

def test_ruby_literal_with_match_operator():
    cands = extract_from_text("if x =~ /^a+$/i", "ruby")
    assert cands[0].pattern == "^a+$"

def test_unknown_lang_returns_empty():
    assert extract_from_text("anything", "cobol") == []


def test_kotlin_regex_constructor():
    cands = extract_from_text('val re = Regex("^a+$")', "kotlin")
    assert cands[0].pattern == "^a+$"


def test_kotlin_to_regex_extension():
    cands = extract_from_text('val ok = "^a+$".toRegex()', "kotlin")
    assert cands[0].pattern == "^a+$"


def test_kotlin_java_pattern_compile_also_works():
    cands = extract_from_text('Pattern.compile("^a+$")', "kotlin")
    assert cands[0].pattern == "^a+$"


def test_c_regcomp():
    cands = extract_from_text('regcomp(&re, "^a+$", REG_EXTENDED);', "c")
    assert cands[0].pattern == "^a+$"


def test_bash_conditional_match_quoted():
    cands = extract_from_text('if [[ $x =~ "^a+$" ]]; then echo y; fi', "bash")
    assert cands[0].pattern == "^a+$"


def test_bash_conditional_match_bare():
    cands = extract_from_text("if [[ $x =~ ^a+$ ]]; then echo y; fi", "bash")
    assert cands[0].pattern == "^a+$"


def test_bash_grep_dash_e():
    cands = extract_from_text("grep -E '^a+$' file.txt", "bash")
    assert cands[0].pattern == "^a+$"


def test_bash_egrep():
    cands = extract_from_text('egrep "foo(bar)*" file.txt', "bash")
    assert cands[0].pattern == "foo(bar)*"
