import pytest

from c2_traffic_analyzer.scoring import (
    intervals,
    iqr,
    jitter_ratio,
    regularity_score,
)


def test_regularity_score_perfect():
    assert regularity_score([5.0, 5.0, 5.0, 5.0]) == 1.0


def test_regularity_score_single_value_is_zero():
    assert regularity_score([5.0]) == 0.0


def test_regularity_score_irregular_is_low():
    assert regularity_score([1.0, 2.0, 7.0, 50.0, 3.0]) < 0.5


def test_regularity_score_within_unit_range():
    for seq in ([1.0, 2.0], [1, 1, 2, 2, 3, 3], [10, 20, 30, 40]):
        score = regularity_score(seq)
        assert 0.0 <= score <= 1.0


def test_intervals_sorted_diffs():
    assert intervals([10.0, 7.0, 4.0, 1.0]) == [3.0, 3.0, 3.0]


def test_intervals_empty_for_single():
    assert intervals([1.0]) == []


def test_jitter_ratio_zero_for_constant_intervals():
    assert jitter_ratio([5.0, 5.0, 5.0]) == 0.0


def test_jitter_ratio_high_for_irregular():
    assert jitter_ratio([1.0, 1.0, 1.0, 100.0]) > 0.5


def test_iqr_basic():
    assert iqr([1.0, 2.0, 3.0, 4.0, 5.0]) == pytest.approx(3.0, rel=0.2)


def test_iqr_below_two_is_zero():
    assert iqr([5.0]) == 0.0
