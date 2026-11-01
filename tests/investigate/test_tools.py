"""Investigator tools: read-only, typed arguments, checked in code. No free-text queries."""

import pytest
from investigate_support import ATTACKER, WS5, Intel, Source, all_events, golden, start_bundle

from triage.investigate.tools import WINDOW_CAP, ToolError, run_tool

_ATTACKER_LSASS = "Microsoft-Windows-Sysmon/Operational:725757"


def _run(name, **args):
    return run_tool(name, args, start_bundle(), Source(all_events()), Intel({"10.10.10.5": "lab C2"}))


def test_process_tree_returns_the_process_and_its_children():
    ids = {e.event_id for e in _run("process_tree", **ATTACKER).events}
    whoami = golden("44f255f374992221")[1].event_id      # the attacker's child process
    assert _ATTACKER_LSASS in ids and whoami in ids


def test_process_tree_by_pid_alone_finds_the_same_process():
    assert _ATTACKER_LSASS in {e.event_id for e in _run("process_tree", host=WS5, pid=1648).events}


def test_network_connections_returns_only_network_events():
    events = _run("network_connections", **ATTACKER).events
    assert events and all(e.fields["EventID"] in (3, 5156) for e in events)


def test_host_timeline_within_the_cap():
    events = _run("host_timeline", host=WS5, start="2020-08-07T14:30:00+00:00", end="2020-08-07T14:40:00+00:00").events
    assert events and all(e.host == WS5 for e in events)


def test_host_timeline_wider_than_the_cap_is_rejected():
    with pytest.raises(ToolError, match="window"):
        _run("host_timeline", host=WS5, start="2020-08-07T00:00:00+00:00", end="2020-08-08T00:00:00+00:00")
    assert WINDOW_CAP.total_seconds() == 15 * 60


def test_host_timeline_end_before_start_is_rejected():
    with pytest.raises(ToolError):
        _run("host_timeline", host=WS5, start="2020-08-07T14:40:00+00:00", end="2020-08-07T14:30:00+00:00")


def test_entity_lookup_hits_and_misses():
    assert [h.indicator for h in _run("entity_lookup", kind="ip", value="10.10.10.5").hits] == ["10.10.10.5"]
    assert _run("entity_lookup", kind="ip", value="8.8.8.8").hits == []


@pytest.mark.parametrize("name,args", [
    ("process_tree", {"host": "DC01.evil.local", "pid": 1}),                     # host not in the evidence
    ("process_tree", {"host": WS5}),                                             # missing pid
    ("process_tree", {"host": WS5, "pid": "1648; drop table events"}),           # not an integer
    ("process_tree", {"host": WS5, "pid": 1648, "query": "anything"}),           # unexpected argument
    ("process_tree", {"host": WS5, "pid": 1648, "guid": "not-a-guid"}),
    ("entity_lookup", {"kind": "ip", "value": "10.10.10.5 or 1=1"}),             # free text
    ("entity_lookup", {"kind": "hash", "value": "zzzz"}),
    ("entity_lookup", {"kind": "domain", "value": "evil domain.com"}),
    ("entity_lookup", {"kind": "email", "value": "a@b.c"}),
    ("delete_files", {"path": "C:\\"}),                                          # no such tool, nothing writes
    ("host_timeline", {"host": WS5, "start": "yesterday", "end": "today"}),
])
def test_malformed_or_unknown_calls_are_rejected(name, args):
    with pytest.raises(ToolError):
        _run(name, **args)
