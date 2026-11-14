import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from forensic_time import normalize_epoch_seconds as n, active_days, contiguous_bursts

def test_scales():
    s = 1_790_000_000.0
    assert n(s) == s
    assert n(s * 1e3) == s
    assert abs(n(s * 1e6) - s) < 1e-3
    assert abs(n(s * 1e9) - s) < 1e-3
    assert n(0) is None and n(5.0) is None and n(float("nan")) is None

def test_sparse_days_dropped_and_bursts():
    base = 1_790_000_000.0
    ep = [base + i for i in range(100)] + [base + 86400 + i for i in range(100)] + [base + 86400 * 40]
    kept, dropped = active_days(ep, 50)
    assert len(kept) == 2 and len(dropped) == 1
    assert len(contiguous_bursts(kept)) == 1
