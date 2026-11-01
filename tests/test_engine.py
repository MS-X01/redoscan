import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import pytest
from redoscan.engine import analyse

VULNERABLE = [
    r"^(a+)+$",
    r"^(a|a)+$",
    r"^(a|a)*$",
    r"^([a-zA-Z0-9_.-]+)*@",
    r"<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)",
    r"^(([a-z])+.)+[A-Z]([a-z])+$",
    r"(x+x+)+y",
]

SAFE = [
    r"^\d{3}-\d{4}$",
    r"^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$",
    r"^[a-z]+\d+$",
    r"^(?>a+)+$",
    r"^a++b$",
    r"^(a+)++$",
    r"^a+b$",
    r"^[a-z]*$",
    r"^[a-z]+[0-9]+$",
    r"^(a+b+)+$",
    r"^(a+b)+$",
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
    r"^[a-zA-Z0-9_-]{3,16}$",
]

POLYNOMIAL_NOT_EXPONENTIAL = [
    r"^\d+\d+$",
    r"^.*.*=.*$",
    r"^\s*\s*\s*$",
]


@pytest.mark.parametrize("pattern", VULNERABLE)
def test_detects_exponential_patterns(pattern):
    r = analyse(pattern)
    assert r.worst_severity in ("critical", "high"), pattern
    assert any(f.kind == "EDA" for f in r.findings), pattern


@pytest.mark.parametrize("pattern", SAFE)
def test_clears_safe_patterns(pattern):
    r = analyse(pattern)
    assert r.worst_severity == "info", (pattern, [(f.kind, f.message) for f in r.findings])


@pytest.mark.parametrize("pattern", POLYNOMIAL_NOT_EXPONENTIAL)
def test_classifies_polynomial_not_exponential(pattern):
    r = analyse(pattern)
    assert all(f.kind != "EDA" for f in r.findings), pattern
    assert any(f.kind == "IDA" for f in r.findings), pattern


def test_backref_warning_present():
    r = analyse(r"(a)\1+")
    assert any("backreference" in w for w in r.warnings)


def test_unparseable_pattern_reports_info_not_crash():
    r = analyse(r"(unclosed")
    assert r.worst_severity == "info"
    assert r.findings


def test_finding_has_valid_attack_sample():
    r = analyse(r"^(a+)+$")
    f = r.findings[0]
    sample = f.pump(10)
    assert len(sample) > 0


def test_dedup_caps_findings_per_pattern():
    r = analyse(r"^(a|a)+$")
    assert len(r.findings) <= 5
