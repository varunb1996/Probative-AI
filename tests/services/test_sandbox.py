"""Sandbox pieces that need no database: EVTX conversion, formats, allow-list, ids, hashing."""

import json

import pytest

from triage.domain import ProcessRef
from triage.pipeline.parse import parse_event
from triage.pipeline.process import actor_process
from triage.services import sandbox

_SYSMON_10 = {"Event": {
    "System": {"Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}}, "EventID": 10,
               "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS5.lab.local",
               "EventRecordID": 725757, "TimeCreated": {"#attributes": {"SystemTime": "2020-08-07T14:32:57.589000Z"}},
               "Execution": {"#attributes": {"ProcessID": 3284, "ThreadID": 4364}}},
    "EventData": {"SourceProcessGUID": "{297bc33e-65d0-5f2d-8207-000000000400}", "SourceProcessId": 1648,
                  "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "TargetImage": "C:\\windows\\system32\\lsass.exe", "GrantedAccess": "0x1010"}}}

_SECURITY_5156 = {"Event": {
    "System": {"Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
               "EventID": {"#attributes": {"Qualifiers": ""}, "#text": 5156},
               "Channel": "Security", "Computer": "WS5.lab.local", "EventRecordID": 202260,
               "TimeCreated": {"#attributes": {"SystemTime": "2020-08-07T14:32:50.100000Z"}}},
    "EventData": {"ProcessID": 1648, "Application": "\\device\\harddiskvolume2\\windows\\system32\\powershell.exe",
                  "DestAddress": "10.10.10.5", "DestPort": 80}}}


def test_sysmon_record_becomes_a_flat_event_the_pipeline_reads():
    raw = sandbox.evtx_record_to_raw(_SYSMON_10)
    assert (raw["Channel"], raw["EventID"], raw["RecordNumber"], raw["Hostname"]) == (
        "Microsoft-Windows-Sysmon/Operational", 10, 725757, "WS5.lab.local")
    event = parse_event(raw)
    assert event.event_id == "Microsoft-Windows-Sysmon/Operational:725757"
    assert actor_process(event) == ProcessRef(host="WS5.lab.local", pid=1648,
                                              guid="{297bc33e-65d0-5f2d-8207-000000000400}")


def test_security_record_eventid_object_and_processid_spelling():
    raw = sandbox.evtx_record_to_raw(_SECURITY_5156)
    assert raw["EventID"] == 5156 and raw["ProcessId"] == 1648 and "ProcessID" not in raw
    assert actor_process(parse_event(raw)) == ProcessRef(host="WS5.lab.local", pid=1648)


def test_nested_event_data_values_are_kept_as_text():
    record = json.loads(json.dumps(_SYSMON_10))
    record["Event"]["EventData"]["Odd"] = {"#text": ["a", "b"]}
    assert isinstance(sandbox.evtx_record_to_raw(record)["Odd"], str)


def test_record_without_event_data_still_converts():
    record = json.loads(json.dumps(_SYSMON_10))
    record["Event"]["EventData"] = None
    assert sandbox.evtx_record_to_raw(record)["RecordNumber"] == 725757


@pytest.mark.parametrize("head,kind", [(b"ElfFile\x00rest", "evtx"), (b'{"Channel": "Security"}', "json"),
                                      (b"  \n{", "json"), (b"MZ\x90\x00", None), (b"", None)])
def test_format_is_sniffed_from_the_content(head, kind):
    assert sandbox.sniff_format(head) == kind


def test_json_lines_must_carry_the_fields_the_pipeline_needs(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"Channel": "Security", "RecordNumber": 1, "Hostname": "h", "EventID": 4624,
                                "@timestamp": "2020-08-07T14:32:50.100Z"}) + "\n", encoding="utf-8")
    assert len(sandbox.read_json_events(good)) == 1
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"winlog": {"event_id": 1}}) + "\n", encoding="utf-8")
    with pytest.raises(sandbox.SandboxError, match="Channel"):
        sandbox.read_json_events(bad)


def test_scenarios_are_an_allow_list_of_otrf_urls():
    assert sandbox.SCENARIOS
    for key, s in sandbox.SCENARIOS.items():
        assert s.url.startswith("https://raw.githubusercontent.com/OTRF/Security-Datasets/")
    with pytest.raises(sandbox.SandboxError):
        sandbox.scenario("../../etc/passwd")


def test_case_ids_are_unguessable_and_scope_event_ids():
    a, b = sandbox.new_case_id(), sandbox.new_case_id()
    assert a != b and len(a) >= 20
    assert sandbox.case_event_id(a, "Security:1") == f"{a}/Security:1"


def test_client_hash_never_stores_the_address():
    h = sandbox.client_hash("203.0.113.9")
    assert "203.0.113.9" not in h and h == sandbox.client_hash("203.0.113.9")
    assert h != sandbox.client_hash("203.0.113.10")
