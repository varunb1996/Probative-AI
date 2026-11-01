"""Close thresholds per rule type from the labelled set.

The eval uses leave-one-out, so no alert calibrates its own threshold. The deployed system
uses thresholds fitted on every labelled alert (config/policy.json).
"""

from dataclasses import dataclass

_ABOVE = 1e-6


@dataclass(frozen=True)
class Row:
    alert_id: str
    rule_title: str
    label: str                  # ground truth: benign | malicious
    verdict: str | None         # the model's verdict; None if the judge failed
    confidence: float | None


def _threshold(rows: list[Row]) -> float | None:
    """The lowest confidence among benign alerts the model called benign, raised to just above the
    highest confidence of any malicious alert it called benign. None if no benign was called benign."""
    called_benign = [r for r in rows if r.verdict == "benign" and r.confidence is not None]
    benign = [r.confidence for r in called_benign if r.label == "benign"]
    missed = [r.confidence for r in called_benign if r.label == "malicious"]
    if not benign:
        return None
    threshold = min(benign)
    if missed:
        threshold = max(threshold, max(missed) + _ABOVE)
    return threshold


def loo_thresholds(rows: list[Row]) -> dict[str, float | None]:
    """alert_id -> minimum confidence to close it, from the *other* alerts of its rule type."""
    return {row.alert_id: _threshold([r for r in rows if r.alert_id != row.alert_id
                                      and r.rule_title == row.rule_title])
            for row in rows}


def fit_thresholds(rows: list[Row]) -> dict[str, float]:
    """rule_title -> minimum confidence to close, from every labelled alert. Rule types with no
    usable evidence are left out, so they can never close."""
    out = {}
    for rule in sorted({r.rule_title for r in rows}):
        threshold = _threshold([r for r in rows if r.rule_title == rule])
        if threshold is not None:
            out[rule] = threshold
    return out
