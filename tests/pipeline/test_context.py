"""Step 3, context: a process-scoped bundle, never a host time window."""

from datetime import timedelta

from conftest import GOLDEN_IDS, golden
from fakes import FakeEventSource

from triage.domain import PriorAlert
from triage.pipeline.context import build_bundle
from triage.pipeline.parse import parse_alert, parse_event


def _all_events():
    return [parse_event(golden(a)["event"]) for a in GOLDEN_IDS]


def _pair(alert_id):
    fx = golden(alert_id)
    event = parse_event(fx["event"])
    return parse_alert(fx["hayabusa"], event), event


def _ids(bundle):
    return [e.event_id for e in bundle.events]


def test_trigger_event_comes_first():
    alert, trigger = _pair("27881e43475ab248")
    bundle = build_bundle(alert, trigger, FakeEventSource(_all_events()), [])
    assert _ids(bundle)[0] == trigger.event_id


def test_security_pid_only_alert_reaches_the_sysmon_events_of_its_process():
    # 5156 has no GUID; host + PID 1648 must still pull in the attacker's Sysmon events.
    alert, trigger = _pair("3272105ca1ce8305")
    bundle = build_bundle(alert, trigger, FakeEventSource(_all_events()), [])
    lsass_access = golden("32a60c4fa80ff99c")["event"]["event_id"]
    assert lsass_access in _ids(bundle)


def test_children_are_included():
    # whoami (44f255...) is a child of the attacker powershell (PID 1648).
    alert, trigger = _pair("32a60c4fa80ff99c")
    bundle = build_bundle(alert, trigger, FakeEventSource(_all_events()), [])
    assert golden("44f255f374992221")["event"]["event_id"] in _ids(bundle)


def test_events_are_not_repeated():
    alert, trigger = _pair("32a60c4fa80ff99c")
    ids = _ids(build_bundle(alert, trigger, FakeEventSource(_all_events()), []))
    assert len(ids) == len(set(ids))


def test_unrelated_process_on_same_host_is_excluded():
    alert, trigger = _pair("27881e43475ab248")  # svchost 452 on WORKSTATION5
    bundle = build_bundle(alert, trigger, FakeEventSource(_all_events()), [])
    assert golden("32a60c4fa80ff99c")["event"]["event_id"] not in _ids(bundle)


def test_never_uses_a_host_time_window():
    source = FakeEventSource(_all_events())
    alert, trigger = _pair("32a60c4fa80ff99c")
    build_bundle(alert, trigger, source, [])
    assert source.window_calls == 0


def _prior(alert, verdict, confirmed, minutes_before=10, host=None):
    earlier = alert.model_copy(update={
        "alert_id": f"prior-{verdict}-{confirmed}-{host}",
        "timestamp": alert.timestamp - timedelta(minutes=minutes_before),
        "host": host or alert.host})
    return PriorAlert(alert=earlier, verdict=verdict, human_confirmed=confirmed)


def test_unconfirmed_prior_verdict_never_enters_the_bundle():
    alert, trigger = _pair("27881e43475ab248")
    bundle = build_bundle(alert, trigger, FakeEventSource([trigger]),
                          [_prior(alert, "benign", confirmed=False)])
    [prior] = bundle.prior_alerts
    assert prior.verdict is None
    assert prior.alert.rule_title == alert.rule_title  # the raw facts still enter


def test_confirmed_prior_verdict_enters_the_bundle():
    alert, trigger = _pair("27881e43475ab248")
    bundle = build_bundle(alert, trigger, FakeEventSource([trigger]),
                          [_prior(alert, "malicious", confirmed=True)])
    assert bundle.prior_alerts[0].verdict == "malicious"


def test_priors_from_other_hosts_or_the_future_are_excluded():
    alert, trigger = _pair("27881e43475ab248")
    priors = [_prior(alert, "malicious", True, host="MORDORDC.theshire.local"),
              _prior(alert, "malicious", True, minutes_before=-10)]
    assert build_bundle(alert, trigger, FakeEventSource([trigger]), priors).prior_alerts == []
