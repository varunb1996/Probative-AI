"""ProcessRef identity: GUID when both sides have one, otherwise host + PID."""

import pytest
from pydantic import ValidationError

from triage.domain import PriorAlert, ProcessRef

_HOST = "WORKSTATION5.theshire.local"
_GUID = "{297bc33e-65d0-5f2d-8207-000000000400}"


def test_same_guid_same_process():
    assert ProcessRef(host=_HOST, pid=1648, guid=_GUID).same_process(
        ProcessRef(host=_HOST, pid=1648, guid=_GUID))


def test_different_guid_same_pid_is_different_process():
    # PID reuse: two GUIDs mean two processes even if the PID matches.
    other = "{297bc33e-0000-0000-0000-000000000400}"
    assert not ProcessRef(host=_HOST, pid=1648, guid=_GUID).same_process(
        ProcessRef(host=_HOST, pid=1648, guid=other))


def test_pid_only_side_falls_back_to_host_and_pid():
    # Security events carry only a PID; they must still join the Sysmon process.
    assert ProcessRef(host=_HOST, pid=1648).same_process(
        ProcessRef(host=_HOST, pid=1648, guid=_GUID))


def test_different_host_is_different_process():
    assert not ProcessRef(host=_HOST, pid=1648).same_process(
        ProcessRef(host="MORDORDC.theshire.local", pid=1648))


def test_prior_alert_verdict_must_be_a_contract_value(alert_dict):
    with pytest.raises(ValidationError):
        PriorAlert(alert=alert_dict, verdict="probably fine", human_confirmed=True)


@pytest.fixture
def alert_dict():
    return {"alert_id": "a1", "rule_title": "Proc Access", "rule_level": "low",
            "mitre_tags": [], "host": _HOST, "user": None,
            "timestamp": "2020-08-07T14:33:01+00:00", "event_ids": ["ev:1"]}
