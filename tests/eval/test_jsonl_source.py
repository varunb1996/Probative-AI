"""The harness's JSONL event source answers the investigator's host_timeline query."""

import json
from datetime import datetime
from pathlib import Path

from eval.harness.jsonl_source import JsonlEventSource

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
WS5 = "WORKSTATION5.theshire.local"


def _source(tmp_path):
    rows = [json.loads(p.read_text(encoding="utf-8"))["event"] for p in sorted(FIXTURES.glob("*.json"))]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return JsonlEventSource(path)


def test_host_window_returns_that_host_inside_the_window(tmp_path):
    source = _source(tmp_path)
    start, end = datetime.fromisoformat("2020-08-07T14:32:00+00:00"), datetime.fromisoformat("2020-08-07T14:33:00+00:00")
    events = source.host_window(WS5, start, end)
    assert events and all(e.host == WS5 and start <= e.timestamp <= end for e in events)
    assert len(events) < len(source.events)


def test_host_window_is_empty_for_another_host(tmp_path):
    source = _source(tmp_path)
    start, end = datetime.fromisoformat("2020-08-07T00:00:00+00:00"), datetime.fromisoformat("2020-08-08T00:00:00+00:00")
    assert source.host_window("DC01.lab.local", start, end) == []
