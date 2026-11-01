import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from redoscan.cli import run

def test_pattern_flag_vulnerable_exits_nonzero(capsys):
    code = run(["--pattern", r"^(a+)+$", "--no-color", "--fail-on", "high"])
    out = capsys.readouterr().out
    assert code == 1
    assert "CRITICAL" in out or "critical" in out

def test_pattern_flag_safe_exits_zero(capsys):
    code = run(["--pattern", r"^\d{3}-\d{4}$", "--no-color"])
    assert code == 0

def test_json_output_is_valid(capsys):
    run(["--pattern", r"^(a+)+$", "--format", "json", "--fail-on", "never"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["results"][0]["severity"] == "critical"

def test_fail_on_never_always_zero(capsys):
    code = run(["--pattern", r"^(a+)+$", "--fail-on", "never", "--no-color"])
    assert code == 0

def test_min_severity_filters_output(capsys):
    run(["--pattern", r"^\d+\d+$", "--min-severity", "critical",
         "--fail-on", "never", "--format", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["results"] == [] or all(not r["findings"] for r in data["results"])

def test_scans_directory(tmp_path, capsys):
    f = tmp_path / "x.py"
    f.write_text('import re\nre.compile(r"^(a+)+$")\n')
    code = run([str(tmp_path), "--no-color", "--fail-on", "high"])
    out = capsys.readouterr().out
    assert code == 1
    assert "x.py" in out

def test_html_output_is_well_formed(tmp_path, capsys):
    out_file = tmp_path / "report.html"
    run(["--pattern", r"^(a+)+$", "--format", "html", "-o", str(out_file), "--fail-on", "never"])
    content = out_file.read_text()
    assert "<html" in content and "critical" in content.lower()


def test_list_categories(capsys):
    code = run(["--list-categories"])
    out = capsys.readouterr().out
    assert code == 0
    assert "sqli" in out and "idor" in out


def test_vulnscan_detects_sql_injection(tmp_path, capsys):
    f = tmp_path / "app.py"
    f.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n')
    code = run([str(tmp_path), "--no-color", "--fail-on", "high", "--no-html-report"])
    out = capsys.readouterr().out
    assert code == 1
    assert "SQLI" in out or "SQL" in out


def test_checks_redos_only_skips_vulnscan(tmp_path, capsys):
    f = tmp_path / "app.py"
    f.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n')
    run([str(tmp_path), "--no-color", "--fail-on", "never", "--checks", "redos", "--no-html-report"])
    out = capsys.readouterr().out
    assert "SQLI" not in out and "SQL Injection" not in out


def test_checks_vulns_only_skips_redos(tmp_path, capsys):
    f = tmp_path / "app.py"
    f.write_text('import re\nre.compile(r"^(a+)+$")\nos.system("rm " + x)\n')
    run([str(tmp_path), "--no-color", "--fail-on", "never", "--checks", "vulns", "--no-html-report"])
    out = capsys.readouterr().out
    assert "EDA" not in out
    assert "CMDI" in out

def test_category_filter_narrows_results(tmp_path, capsys):
    f = tmp_path / "app.py"
    f.write_text('os.system("rm " + x)\ncursor.execute(f"SELECT {x}")\n')
    run([str(tmp_path), "--no-color", "--fail-on", "never", "--category", "sqli", "--no-html-report"])
    out = capsys.readouterr().out
    assert "SQLI" in out and "CMDI" not in out


def test_unknown_category_errors(capsys):
    code = run(["--pattern", r"^a+$", "--category", "nonsense"])
    assert code == 2


def test_confidence_heuristic_hides_redos(tmp_path, capsys):
    f = tmp_path / "app.py"
    f.write_text('import re\nre.compile(r"^(a+)+$")\nos.system("rm " + x)\n')
    run([str(tmp_path), "--no-color", "--fail-on", "never", "--confidence", "heuristic", "--no-html-report"])
    out = capsys.readouterr().out
    assert "EDA" not in out
    assert "CMDI" in out


def test_html_report_auto_saved_by_default(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "app.py"
    f.write_text('import re\nre.compile(r"^(a+)+$")\n')
    run([str(tmp_path), "--no-color", "--fail-on", "never"])
    html_files = list(tmp_path.glob("redoscan-report-*.html"))
    assert len(html_files) == 1
    assert "<html" in html_files[0].read_text()


def test_no_html_report_flag_skips_autosave(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "app.py"
    f.write_text('import re\nre.compile(r"^(a+)+$")\n')
    run([str(tmp_path), "--no-color", "--fail-on", "never", "--no-html-report"])
    assert list(tmp_path.glob("redoscan-report-*.html")) == []


# ---- help layout & HTML report ------------------------------------------

def test_help_uses_unix_style_option_layout(capsys):
    import pytest
    with pytest.raises(SystemExit) as e:
        run(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    # long option first, alias next, value placeholder once at the end
    assert "--format, -f {terminal,json,html}" in out
    assert "--pattern, -e REGEX" in out
    assert "--help, -h" in out
    assert "{terminal,json,html}, -f" not in out


def test_html_report_is_searchable_and_linked(tmp_path, capsys):
    import re
    f = tmp_path / "app.py"
    f.write_text('import re, os\nre.compile(r"^(a+)+$")\nos.system("rm " + x)\n')
    out_file = tmp_path / "r.html"
    run([str(tmp_path), "--format", "html", "-o", str(out_file), "--fail-on", "never"])
    html = out_file.read_text()
    assert "https://github.com/MS-X01/redoscan" in html
    assert 'id="q"' in html and 'id="fCat"' in html and 'id="groupSeg"' in html
    blob = re.search(r'<script id="rs-data" type="application/json">(.*?)</script>', html, re.S).group(1)
    data = json.loads(blob)
    cats = {x["category"] for x in data["findings"]}
    assert {"redos", "cmdi"} <= cats
    assert all(x["file"] == "app.py" for x in data["findings"])   # relative to the scan root
    assert all(x["lang"] == "python" for x in data["findings"])


def test_html_report_escapes_script_breakout(tmp_path):
    f = tmp_path / "x.py"
    f.write_text('import os\nos.system("</script><script>alert(1)</script>" + x)\n')
    out_file = tmp_path / "r.html"
    run([str(tmp_path), "--format", "html", "-o", str(out_file), "--fail-on", "never"])
    html = out_file.read_text()
    assert "</script><script>alert(1)" not in html
