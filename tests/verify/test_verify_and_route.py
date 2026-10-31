"""Remaining checks and the router. The verifier guards only the close path."""

import pytest
from pydantic import ValidationError
from verify_support import LOW, POLICY, golden_bundle, result_for

from triage.domain import JudgeResult, RuleMode
from triage.verify.checks import VerifyPolicy, verify
from triage.verify.router import Route, route


def _decide(result, bundle, policy=POLICY, mode=RuleMode.AUTO, score=LOW):
    report = verify(result, bundle, score, policy)
    return report, route(result, report, mode)


def _failed(report):
    return {c.name for c in report.checks if not c.passed}


def test_clean_benign_verdict_passes_every_check():
    bundle = golden_bundle()
    report, _ = _decide(result_for(bundle), bundle)
    assert report.passed and len(report.checks) == 7


@pytest.mark.parametrize("mode,expected", [(RuleMode.SHADOW, Route.SUGGEST_CLOSE),
                                           (RuleMode.ASSISTED, Route.SUGGEST_CLOSE),
                                           (RuleMode.AUTO, Route.AUTO_CLOSE)])
def test_clean_benign_routes_by_rule_mode(mode, expected):
    bundle = golden_bundle()
    assert _decide(result_for(bundle), bundle, mode=mode)[1].route == expected


def test_failed_judge_result_escalates_and_never_closes():
    bundle = golden_bundle()
    failed = JudgeResult(alert_id=bundle.alert.alert_id, attempts=2, error="off-schema twice",
                         shown_event_ids=[bundle.events[0].event_id])
    report, decision = _decide(failed, bundle)
    assert "schema" in _failed(report) and not report.passed
    assert decision.route == Route.ESCALATE


def test_uncalibrated_rule_type_never_closes():
    bundle = golden_bundle()
    report, decision = _decide(result_for(bundle), bundle,
                               policy=POLICY.model_copy(update={"close_confidence": {}}))
    assert "calibrated_confidence" in _failed(report)
    assert decision.route == Route.ESCALATE


def test_confidence_below_the_rule_threshold_escalates():
    bundle = golden_bundle()
    report, decision = _decide(result_for(bundle, confidence=0.7), bundle)
    assert "calibrated_confidence" in _failed(report)
    assert decision.route == Route.ESCALATE


def test_critical_host_never_closes():
    bundle = golden_bundle()
    policy = POLICY.model_copy(update={"critical_hosts": frozenset({bundle.alert.host.upper()})})
    report, decision = _decide(result_for(bundle), bundle, policy=policy)
    assert "hard_override" in _failed(report)
    assert decision.route == Route.ESCALATE


def test_invented_quote_fails_grounding():
    bundle = golden_bundle()
    result = result_for(bundle, summary='svchost ran "mimikatz.exe sekurlsa::logonpasswords", routine.')
    assert "citation_grounding" in _failed(_decide(result, bundle)[0])


def test_real_quote_is_grounded():
    bundle = golden_bundle()
    result = result_for(bundle, summary='Source "C:\\windows\\system32\\svchost.exe" with `0x1000`.')
    assert _decide(result, bundle)[0].passed


def test_malicious_always_escalates():
    bundle = golden_bundle()
    report, decision = _decide(result_for(bundle, verdict="malicious"), bundle)
    assert report.passed and decision.route == Route.ESCALATE


def test_suspicious_with_missing_context_goes_to_the_investigator():
    bundle = golden_bundle()
    result = result_for(bundle, verdict="suspicious", missing_context=["parent process of svchost 452"])
    assert _decide(result, bundle)[1].route == Route.INVESTIGATE


def test_suspicious_without_missing_context_escalates():
    bundle = golden_bundle()
    assert _decide(result_for(bundle, verdict="suspicious"), bundle)[1].route == Route.ESCALATE


def test_close_policy_only_applies_to_benign():
    # A high score or an uncalibrated rule never blocks escalation of a non-benign verdict.
    bundle = golden_bundle()
    policy = POLICY.model_copy(update={"close_confidence": {}})
    report, _ = _decide(result_for(bundle, verdict="malicious", confidence=0.1), bundle, policy=policy)
    assert report.passed


def test_policy_has_no_default_thresholds():
    with pytest.raises(ValidationError):
        VerifyPolicy()


def test_escalation_reasons_name_the_failed_checks():
    bundle = golden_bundle()
    result = result_for(bundle, cited_event_ids=["Security:999999"])
    _, decision = _decide(result, bundle)
    assert {"citation_grounding", "trigger_anchoring"} <= set(decision.reasons)
