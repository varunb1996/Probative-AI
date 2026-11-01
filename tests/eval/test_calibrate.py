"""Leave-one-out close thresholds. Synthetic rows only; never reads labels."""

from eval.harness.calibrate import Row, fit_thresholds, loo_thresholds


def _row(alert_id, label, verdict="benign", confidence=0.9, rule="Proc Access"):
    return Row(alert_id=alert_id, rule_title=rule, label=label, verdict=verdict, confidence=confidence)


def test_an_alert_never_calibrates_its_own_threshold():
    # Alone in its rule type: no other evidence, so it can never close.
    assert loo_thresholds([_row("a", "benign")]) == {"a": None}


def test_threshold_is_the_lowest_correctly_closed_benign_confidence():
    rows = [_row("a", "benign", confidence=0.8), _row("b", "benign", confidence=0.9),
            _row("c", "benign", confidence=0.95)]
    t = loo_thresholds(rows)
    assert (t["a"], t["b"], t["c"]) == (0.9, 0.8, 0.8)


def test_threshold_sits_above_any_malicious_alert_called_benign():
    rows = [_row("a", "benign", confidence=0.8), _row("m", "malicious", confidence=0.85),
            _row("x", "benign", confidence=0.95)]
    t = loo_thresholds(rows)["x"]
    assert t > 0.85
    assert t <= 0.85 + 1e-5


def test_malicious_called_benign_at_full_confidence_means_never_close():
    rows = [_row("a", "benign", confidence=0.9), _row("m", "malicious", confidence=1.0),
            _row("x", "benign", confidence=1.0)]
    assert loo_thresholds(rows)["x"] > 1.0


def test_other_rule_types_and_non_benign_verdicts_do_not_count():
    rows = [_row("a", "benign", rule="Net Conn", confidence=0.5),
            _row("b", "benign", verdict="malicious", confidence=0.5),
            _row("c", "benign", verdict=None, confidence=None),
            _row("x", "benign")]
    assert loo_thresholds(rows)["x"] is None


def test_no_benign_evidence_means_never_close_even_without_misses():
    rows = [_row("m", "malicious", verdict="malicious"), _row("x", "benign")]
    assert loo_thresholds(rows)["x"] is None


# fit_thresholds: the production policy, fitted on every labelled alert (the eval uses LOO).

def test_fit_uses_every_alert_of_the_rule_type():
    rows = [_row("a", "benign", confidence=0.8), _row("b", "benign", confidence=0.95)]
    assert fit_thresholds(rows) == {"Proc Access": 0.8}


def test_fit_sits_above_every_missed_malicious_alert():
    rows = [_row("a", "benign", confidence=0.8), _row("m", "malicious", confidence=0.85),
            _row("b", "benign", confidence=0.95)]
    assert 0.85 < fit_thresholds(rows)["Proc Access"] <= 0.85 + 1e-5


def test_fit_leaves_out_rule_types_with_no_correct_benign_call():
    rows = [_row("m", "malicious", verdict="malicious", rule="Net Conn"), _row("a", "benign")]
    assert fit_thresholds(rows) == {"Proc Access": 0.9}
