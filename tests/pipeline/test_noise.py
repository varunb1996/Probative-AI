"""Step 2, known noise: allowlist rules and dedup by rule, host, actor process and time window."""

from datetime import timedelta

import pytest
from conftest import golden

from triage.pipeline.noise import AllowRule, dedup, is_allowlisted, load_allowlist
from triage.pipeline.parse import parse_alert, parse_event

_SVCHOST_ACCESS = AllowRule(
    name="svchost-lsm-session",
    reason="svchost (lsm.dll) opening svchost with 0x1000 is routine session management",
    rule_title="Proc Access",
    fields={"SourceImage": r"C:\windows\system32\svchost.exe", "GrantedAccess": "0x1000"},
)


def _pair(alert_id):
    fx = golden(alert_id)
    event = parse_event(fx["event"])
    return parse_alert(fx["hayabusa"], event), event


def test_allowlist_matches_all_conditions_case_insensitively():
    alert, event = _pair("27881e43475ab248")
    assert is_allowlisted(alert, event, [_SVCHOST_ACCESS]) == _SVCHOST_ACCESS


def test_allowlist_needs_every_field_to_match():
    alert, event = _pair("760bf9479ecb02ec")  # svchost, but GrantedAccess 0x40
    assert is_allowlisted(alert, event, [_SVCHOST_ACCESS]) is None


def test_allowlist_never_matches_a_different_rule():
    alert, event = _pair("32a60c4fa80ff99c")
    rule = _SVCHOST_ACCESS.model_copy(update={"fields": {}})
    assert is_allowlisted(alert, event, [rule]) is None


def test_rule_without_conditions_is_rejected():
    with pytest.raises(ValueError):
        AllowRule(name="everything", reason="lazy")


def test_load_allowlist_reads_yaml(tmp_path):
    path = tmp_path / "allowlist.yaml"
    path.write_text(
        "- name: svchost-lsm-session\n"
        "  reason: routine session management\n"
        "  rule_title: Proc Access\n"
        "  fields:\n"
        "    SourceImage: 'C:\\windows\\system32\\svchost.exe'\n"
        "    GrantedAccess: '0x1000'\n",
        encoding="utf-8")
    [rule] = load_allowlist(path)
    assert rule.fields["SourceImage"] == r"C:\windows\system32\svchost.exe"


def _shifted(alert, event, seconds, suffix):
    return (alert.model_copy(update={"alert_id": alert.alert_id + suffix,
                                     "timestamp": alert.timestamp + timedelta(seconds=seconds)}),
            event)


def test_dedup_groups_same_rule_host_and_process_within_window():
    head = _pair("32a60c4fa80ff99c")
    later = _shifted(*head, 30, "-b")
    outside = _shifted(*head, 600, "-c")
    groups = dedup([outside, later, head], window=timedelta(minutes=5))
    assert groups == {later[0].alert_id: head[0].alert_id}


def test_dedup_keeps_different_processes_apart():
    a = _pair("27881e43475ab248")   # WORKSTATION5 svchost 452
    b = _pair("760bf9479ecb02ec")   # WORKSTATION6 svchost 380
    b = (b[0].model_copy(update={"rule_title": a[0].rule_title}), b[1])
    assert dedup([a, b], window=timedelta(hours=1)) == {}
