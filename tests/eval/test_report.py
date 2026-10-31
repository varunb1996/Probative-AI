"""Report helpers. Synthetic numbers only."""

from eval.harness.run import _miss_bound


def test_rule_of_three_bound():
    assert _miss_bound({"closed": 30, "mal_closed": 0}) == "< 10%"


def test_rule_of_three_bound_never_exceeds_100_percent():
    assert _miss_bound({"closed": 2, "mal_closed": 0}) == "< 100% (too few closes)"


def test_observed_misses_are_reported_as_counts():
    assert _miss_bound({"closed": 18, "mal_closed": 2}) == "observed 2/18"
