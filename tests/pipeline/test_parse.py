"""Step 1, parse: Hayabusa JSONL record + its raw event -> Alert; raw event -> Event."""

import copy

import pytest

from triage.domain import Alert
from triage.pipeline.parse import parse_alert, parse_event


def test_parse_event_keeps_id_host_time_and_raw_fields(gold):
    event = parse_event(gold["event"])
    assert event.event_id == gold["event"]["event_id"]
    assert event.host == gold["event"]["Hostname"]
    assert event.timestamp.isoformat().startswith(gold["event"]["@timestamp"][:19])
    assert event.fields["RecordNumber"] == gold["event"]["RecordNumber"]


def test_parse_event_derives_id_when_absent(gold):
    raw = {k: v for k, v in gold["event"].items() if k != "event_id"}
    assert parse_event(raw).event_id == gold["event"]["event_id"]


def test_parse_alert_reproduces_golden_alert(gold):
    # Same alert_id hash as the Phase 0 export, so the labels still line up.
    event = parse_event(gold["event"])
    assert parse_alert(gold["hayabusa"], event) == Alert(**gold["alert"])


def test_parse_alert_rejects_record_for_another_event(gold):
    record = copy.deepcopy(gold["hayabusa"])
    record["RecordID"] += 1
    with pytest.raises(ValueError):
        parse_alert(record, parse_event(gold["event"]))


def test_parse_alert_rejects_unknown_level(gold):
    record = copy.deepcopy(gold["hayabusa"])
    record["Level"] = "severe"
    with pytest.raises(ValueError):
        parse_alert(record, parse_event(gold["event"]))
