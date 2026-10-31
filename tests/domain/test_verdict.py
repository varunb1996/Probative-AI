"""Verdict output contract, pinned against the golden fixtures. Never reads eval/labels."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from triage.domain import Alert, Verdict

_FIXTURES = sorted((Path(__file__).resolve().parents[1] / "fixtures").glob("*.json"))


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _verdict(alert, **overrides):
    fields = {
        "alert_id": alert["alert_id"],
        "verdict": "suspicious",
        "confidence": 0.5,
        "cited_event_ids": list(alert["event_ids"]),
        "summary": f"{alert['rule_title']} on {alert['host']}.",
        "missing_context": [],
    }
    fields.update(overrides)
    return Verdict(**fields)


@pytest.fixture(params=_FIXTURES, ids=lambda p: p.stem)
def alert(request):
    return _load(request.param)["alert"]


def test_fixtures_present():
    assert len(_FIXTURES) == 5


# Guard rails: valid input must keep passing once the constraints land.

def test_fixture_alert_loads(alert):
    assert Alert(**alert).alert_id == alert["alert_id"]


@pytest.mark.parametrize("value", ["benign", "suspicious", "malicious"])
def test_valid_verdict_accepted(alert, value):
    assert _verdict(alert, verdict=value).verdict == value


@pytest.mark.parametrize("confidence", [0.0, 1.0])
def test_confidence_bounds_accepted(alert, confidence):
    assert _verdict(alert, confidence=confidence).confidence == confidence


def test_summary_of_80_words_accepted(alert):
    assert _verdict(alert, summary=" ".join(["word"] * 80))


# The contract: each of these must be rejected.

@pytest.mark.parametrize("value", ["unknown", "Benign", ""])
def test_invalid_verdict_rejected(alert, value):
    with pytest.raises(ValidationError):
        _verdict(alert, verdict=value)


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_confidence_outside_unit_interval_rejected(alert, confidence):
    with pytest.raises(ValidationError):
        _verdict(alert, confidence=confidence)


def test_summary_over_80_words_rejected(alert):
    with pytest.raises(ValidationError):
        _verdict(alert, summary=" ".join(["word"] * 81))


def test_empty_alert_id_rejected(alert):
    with pytest.raises(ValidationError):
        _verdict(alert, alert_id="")
