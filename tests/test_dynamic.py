import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import pytest
from redoscan.engine import analyse
from redoscan.dynamic import confirm

pytestmark = pytest.mark.slow

def test_confirms_exponential_pattern():
    r = analyse(r"^(a+)+$")
    f = r.findings[0]
    d = confirm(r"^(a+)+$", "", f, lengths=[10, 16, 20, 24], timeout=1.0)
    assert d.verdict == "confirmed-exponential"

def test_confirms_polynomial_not_exponential():
    r = analyse(r"^\d+\d+$")
    f = next(x for x in r.findings if x.kind == "IDA")
    d = confirm(r"^\d+\d+$", "", f, lengths=[1000, 2000, 4000, 8000], timeout=1.0)
    assert d.verdict in ("confirmed-polynomial", "inconclusive")

def test_safe_pattern_not_reproduced():
    from redoscan.engine import Finding
    f = Finding(kind="EDA", severity="critical", message="x", pump_group="a",
                pump_suffix="\x00", repeats_hint=20)
    d = confirm(r"^a+$", "", f, lengths=[10, 20, 30], timeout=1.0)
    assert d.verdict == "not-reproduced"
