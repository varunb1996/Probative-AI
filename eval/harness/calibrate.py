"""Leave-one-out close thresholds per rule type, so no alert calibrates its own threshold."""

from dataclasses import dataclass

_ABOVE = 1e-6


@dataclass(frozen=True)
class Row:
    alert_id: str
    rule_title: str
    label: str                  # ground truth: benign | malicious
    verdict: str | None         # the model's verdict; None if the judge failed
    confidence: float | None


def loo_thresholds(rows: list[Row]) -> dict[str, float | None]:
    """alert_id -> minimum confidence to close it, from the other alerts of its rule type.

    The lowest confidence among other benign alerts the model called benign, raised to just
    above the highest confidence of any malicious alert the model called benign.
    None (never close) when no other alert of the rule type was correctly called benign.
    """
    out: dict[str, float | None] = {}
    for row in rows:
        called_benign = [r for r in rows if r.alert_id != row.alert_id and r.rule_title == row.rule_title
                         and r.verdict == "benign" and r.confidence is not None]
        benign = [r.confidence for r in called_benign if r.label == "benign"]
        missed = [r.confidence for r in called_benign if r.label == "malicious"]
        if not benign:
            out[row.alert_id] = None
            continue
        threshold = min(benign)
        if missed:
            threshold = max(threshold, max(missed) + _ABOVE)
        out[row.alert_id] = threshold
    return out
