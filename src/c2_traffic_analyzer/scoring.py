from __future__ import annotations

import statistics
from typing import Sequence


def _quartile(sorted_vals: Sequence[float]):
    n = len(sorted_vals)
    if n == 0:
        return 0.0, 0.0
    if n == 1:
        return sorted_vals[0], 0.0
    mid = n // 2
    lower = sorted_vals[:mid]
    upper = sorted_vals[mid:] if n % 2 == 0 else sorted_vals[mid + 1:]
    q1 = statistics.median(lower) if lower else sorted_vals[0]
    q3 = statistics.median(upper) if upper else sorted_vals[-1]
    return q1, q3


def iqr(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    ordered = sorted(values)
    q1, q3 = _quartile(ordered)
    return q3 - q1


def regularity_score(values: Sequence[float]) -> float:
    """RITA-style regularity score in [0, 1].

    1.0 means perfectly regular (low dispersion relative to range);
    0.0 means highly irregular. Uses IQR / range, robust to outliers.
    """
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return 0.0
    lo = min(vals)
    hi = max(vals)
    spread = hi - lo
    if spread <= 0:
        return 1.0
    score = 1.0 - (iqr(vals) / spread)
    return max(0.0, min(1.0, score))


def intervals(timestamps: Sequence[float]) -> list[float]:
    ts = sorted(float(t) for t in timestamps)
    if len(ts) < 2:
        return []
    return [b - a for a, b in zip(ts, ts[1:])]


def jitter_ratio(intervals_seq: Sequence[float]) -> float:
    if not intervals_seq:
        return 1.0
    mean = statistics.fmean(intervals_seq)
    if mean <= 0:
        return 1.0
    stdev = statistics.pstdev(intervals_seq) if len(intervals_seq) > 1 else 0.0
    return max(0.0, stdev / mean)
