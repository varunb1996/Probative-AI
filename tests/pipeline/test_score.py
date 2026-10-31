"""Step 4b, evidence score: named weights, each signal tested on its own."""

from datetime import timedelta

import pytest
from conftest import golden

from triage.domain import EvidenceBundle, IntelHit, PriorAlert
from triage.pipeline.parse import parse_alert, parse_event
from triage.pipeline.score import CLOSE_BELOW, WEIGHTS, score


def _bundle(alert_id, *extra_ids, **alert_update):
    fx = golden(alert_id)
    trigger = parse_event(fx["event"])
    alert = parse_alert(fx["hayabusa"], trigger).model_copy(update=alert_update)
    return EvidenceBundle(alert=alert, events=[trigger] + [parse_event(golden(a)["event"]) for a in extra_ids])


def _fired(bundle):
    return set(score(bundle).contributions)


def test_every_weight_is_named_and_positive():
    assert WEIGHTS and all(w > 0 for w in WEIGHTS.values())


def test_total_is_the_sum_of_contributions():
    result = score(_bundle("44f255f374992221"))
    assert result.total == sum(result.contributions.values())
    assert all(result.contributions[k] == WEIGHTS[k] for k in result.contributions)


@pytest.mark.parametrize("level,signal", [("low", "level_low"), ("medium", "level_medium"),
                                          ("high", "level_high"), ("critical", "level_critical")])
def test_rule_level_signal(level, signal):
    assert signal in _fired(_bundle("27881e43475ab248", rule_level=level))


def test_info_level_adds_nothing():
    assert _fired(_bundle("27881e43475ab248", rule_level="info")) == set()


def test_routine_svchost_access_fires_only_its_level():
    assert _fired(_bundle("27881e43475ab248")) == {"level_low"}


def test_mitre_tagged():
    assert "mitre_tagged" in _fired(_bundle("27881e43475ab248", mitre_tags=["T1003.001"]))


def test_script_host_actor():
    assert "script_host_actor" in _fired(_bundle("3272105ca1ce8305"))   # Security: Application path


def test_lsass_target():
    assert "lsass_target" in _fired(_bundle("32a60c4fa80ff99c"))


def test_encoded_command_anywhere_in_the_bundle():
    assert "encoded_command" in _fired(_bundle("27881e43475ab248", "44f255f374992221"))


def test_actor_network_connection():
    assert "actor_network" in _fired(_bundle("32a60c4fa80ff99c", "3272105ca1ce8305"))


def test_unrelated_network_event_does_not_count():
    assert "actor_network" not in _fired(_bundle("27881e43475ab248", "3272105ca1ce8305"))


def test_intel_hit():
    bundle = _bundle("27881e43475ab248").model_copy(update={"intel_hits": [
        IntelHit(indicator="10.10.10.5", kind="ip", source="fake", detail="lab C2")]})
    assert "intel_hit" in _fired(bundle)


def test_only_confirmed_malicious_priors_count():
    bundle = _bundle("27881e43475ab248")
    prior_alert = bundle.alert.model_copy(update={
        "alert_id": "prior", "timestamp": bundle.alert.timestamp - timedelta(minutes=5)})
    unconfirmed = bundle.model_copy(update={"prior_alerts": [PriorAlert(alert=prior_alert)]})
    confirmed = bundle.model_copy(update={"prior_alerts": [
        PriorAlert(alert=prior_alert, verdict="malicious", human_confirmed=True)]})
    assert "prior_confirmed_malicious" not in _fired(unconfirmed)
    assert "prior_confirmed_malicious" in _fired(confirmed)


def test_an_intel_hit_alone_is_never_closable():
    assert WEIGHTS["intel_hit"] >= CLOSE_BELOW
