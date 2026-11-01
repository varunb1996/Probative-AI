"""Routing an investigator outcome: never back into investigation; anything unverified goes to a human."""

import pytest

from triage.domain import Investigation, JudgeResult, LoopState, RuleMode, Verdict
from triage.verify.router import Route, route_investigation


def _inv(verified=True, label="benign", reason="verified verdict"):
    v = Verdict(alert_id="a1", verdict=label, confidence=0.95, cited_event_ids=["ev:1"], summary="s",
                missing_context=["more"] if label == "suspicious" else [])
    result = JudgeResult(alert_id="a1", verdict=v, attempts=1, shown_event_ids=["ev:1"])
    return Investigation(alert_id="a1", verified=verified, stop_reason=reason, result=result, state=LoopState())


def test_unverified_investigation_escalates_with_its_reason():
    d = route_investigation(_inv(verified=False, reason="step cap"), RuleMode.AUTO)
    assert d.route == Route.ESCALATE and "step cap" in d.reasons[0]


def test_suspicious_after_investigation_escalates_instead_of_looping():
    assert route_investigation(_inv(label="suspicious"), RuleMode.AUTO).route == Route.ESCALATE


def test_malicious_escalates():
    assert route_investigation(_inv(label="malicious"), RuleMode.AUTO).route == Route.ESCALATE


@pytest.mark.parametrize("mode,expected", [(RuleMode.SHADOW, Route.SUGGEST_CLOSE),
                                           (RuleMode.ASSISTED, Route.SUGGEST_CLOSE),
                                           (RuleMode.AUTO, Route.AUTO_CLOSE)])
def test_verified_benign_follows_the_rule_mode(mode, expected):
    assert route_investigation(_inv(), mode).route == expected
