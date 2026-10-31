"""JudgeResult: what the judge hands the verifier. A failure has no verdict and says why."""

import pytest
from pydantic import ValidationError

from triage.domain import Alert, JudgeResult, Verdict

_VERDICT = Verdict(alert_id="a1", verdict="benign", confidence=0.9, cited_event_ids=["ev:1"],
                   summary="Routine.", missing_context=[])


def test_success_carries_the_verdict():
    result = JudgeResult(alert_id="a1", verdict=_VERDICT, attempts=1, shown_event_ids=["ev:1"])
    assert result.ok and result.error is None


def test_failure_has_no_verdict_and_a_reason():
    result = JudgeResult(alert_id="a1", attempts=2, error="off-schema twice", shown_event_ids=["ev:1"])
    assert not result.ok


def test_failure_without_a_reason_is_rejected():
    with pytest.raises(ValidationError):
        JudgeResult(alert_id="a1", attempts=2, shown_event_ids=["ev:1"])


def test_verdict_for_another_alert_is_rejected():
    with pytest.raises(ValidationError):
        JudgeResult(alert_id="other", verdict=_VERDICT, attempts=1, shown_event_ids=["ev:1"])


def test_alert_dataset_defaults_to_untagged():
    alert = Alert(alert_id="a1", rule_title="t", rule_level="low", mitre_tags=[], host="h",
                  user=None, timestamp="2020-08-07T14:33:01+00:00", event_ids=["ev:1"])
    assert alert.dataset is None
