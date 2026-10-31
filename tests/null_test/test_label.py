"""Tests for the pure parts of scripts/null_test/label.py. Never reads eval/labels."""

import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "null_test" / "label.py"
_spec = importlib.util.spec_from_file_location("label", _PATH)
label = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(label)


def _alert(i, level, title, host):
    return {"alert_id": f"a{i:04d}", "rule_level": level, "rule_title": title,
            "host": f"{host}.theshire.local", "event_ids": [f"ev:{i}"]}


def _dataset():
    rows, i = [], 0
    spec = [("medium", "Raw Access Read", "WORKSTATION5", 9),
            ("low", "Local Accounts Discovery", "WORKSTATION5", 2),
            ("low", "Network Connection Initiated By PowerShell Process", "WORKSTATION5", 70),
            ("low", "Proc Access", "WORKSTATION5", 181),
            ("low", "Proc Access", "MORDORDC", 21),
            ("low", "Proc Access", "WORKSTATION6", 70),
            ("info", "PwSh Pipeline Exec", "WORKSTATION5", 50)]
    for level, title, host, n in spec:
        for _ in range(n):
            rows.append(_alert(i, level, title, host))
            i += 1
    return rows


# --- pid_text ---------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    (1648, "1648 (0x670)"),
    ("1648", "1648 (0x670)"),
    ("0x670", "1648 (0x670)"),
    (None, "-"),
    ("n/a", "n/a"),
])
def test_pid_text_shows_decimal_and_hex(value, expected):
    assert label.pid_text(value) == expected


# --- draw_sample ------------------------------------------------------------

def test_sample_matches_rubric_split():
    sample = label.draw_sample(_dataset(), seed=42)
    groups = Counter(group for _, group in sample)
    assert groups == {"medium": 9, "discovery": 2, "network": 5,
                      "proc_access_ws5": 8, "proc_access_dc": 3, "proc_access_ws6": 3}
    assert len(sample) == 30
    assert len({alert_id for alert_id, _ in sample}) == 30


def test_sample_is_reproducible_and_seed_dependent():
    alerts = _dataset()
    assert label.draw_sample(alerts, seed=42) == label.draw_sample(list(reversed(alerts)), seed=42)
    assert label.draw_sample(alerts, seed=42) != label.draw_sample(alerts, seed=7)


def test_sample_takes_all_when_group_is_short():
    alerts = [a for a in _dataset() if not (a["host"].startswith("MORDORDC"))]
    alerts += [_alert(9000, "low", "Proc Access", "MORDORDC")]
    groups = Counter(group for _, group in label.draw_sample(alerts, seed=42))
    assert groups["proc_access_dc"] == 1


def test_sample_never_includes_info_alerts():
    by_id = {a["alert_id"]: a for a in _dataset()}
    assert all(by_id[i]["rule_level"] != "info" for i, _ in label.draw_sample(_dataset(), seed=42))


def test_sample_file_round_trip(tmp_path):
    sample = label.draw_sample(_dataset(), seed=42)
    path = tmp_path / "sample.txt"
    label.write_sample(path, sample, seed=42)
    assert label.read_sample(path) == sample


# --- host index and window --------------------------------------------------

def _event(n, host, ts):
    return {"event_id": f"Sec:{n}", "Hostname": host, "@timestamp": ts, "RecordNumber": n}


def test_index_by_host_separates_hosts_and_sorts_by_time_then_record():
    events = [_event(3, "A", "2020-01-01T00:00:02Z"), _event(1, "B", "2020-01-01T00:00:00Z"),
              _event(2, "A", "2020-01-01T00:00:02Z"), _event(4, "A", "2020-01-01T00:00:01Z")]
    index = label.index_by_host(events)
    assert [e["RecordNumber"] for e in index["A"]] == [4, 2, 3]
    assert [e["RecordNumber"] for e in index["B"]] == [1]


def _host_events(n):
    return [_event(i, "A", f"2020-01-01T00:{i // 60:02d}:{i % 60:02d}Z") for i in range(n)]


def test_window_has_ten_before_and_ten_after_in_the_middle():
    events = _host_events(50)
    before, trigger, after = label.window(events, "Sec:25")
    assert trigger["event_id"] == "Sec:25"
    assert [e["RecordNumber"] for e in before] == list(range(15, 25))
    assert [e["RecordNumber"] for e in after] == list(range(26, 36))


def test_window_fills_twenty_from_the_other_side_at_an_edge():
    before, trigger, after = label.window(_host_events(50), "Sec:2")
    assert (len(before), len(after)) == (2, 18)
    before, trigger, after = label.window(_host_events(50), "Sec:48")
    assert (len(before), len(after)) == (19, 1)


def test_window_on_a_small_host_returns_everything_else():
    before, trigger, after = label.window(_host_events(5), "Sec:1")
    assert len(before) + len(after) == 4


# --- resume -----------------------------------------------------------------

def test_labelled_ids_missing_file_is_empty(tmp_path):
    assert label.labelled_ids(tmp_path / "labels.jsonl") == set()


def test_append_then_resume_skips_done_alerts(tmp_path):
    path = tmp_path / "labels.jsonl"
    label.append_label(path, {"alert_id": "a2", "label": "benign", "rationale": "step 4", "seconds": 3.0})
    label.append_label(path, {"alert_id": "a1", "label": "malicious", "rationale": "step 1", "seconds": 5.0})
    assert label.labelled_ids(path) == {"a1", "a2"}
    assert label.pending(["a1", "a2", "a3", "a4"], label.labelled_ids(path)) == ["a3", "a4"]
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [r["alert_id"] for r in rows] == ["a2", "a1"]


# --- summary ----------------------------------------------------------------

def _row(alert_id, seconds, rationale="step 1"):
    return {"alert_id": alert_id, "label": "malicious", "rationale": rationale,
            "seconds": seconds, "labelled_at": None}


def test_summary_with_only_assisted_rows_does_not_crash():
    rows = [_row("a1", None), _row("a2", None, "UNSURE: thin evidence")]
    text = label.summarise(rows, ["a1", "a2", "a3"])
    assert "labelled 2/3" in text
    assert "time per label: not recorded (assisted labels)" in text
    assert "unsure 1" in text


def test_summary_averages_only_rows_with_seconds():
    rows = [_row("a1", 4.0), _row("a2", 8.0), _row("a3", None)]
    text = label.summarise(rows, ["a1", "a2", "a3"])
    assert "avg 6.0s per label over 2 timed" in text
    assert "1 not recorded (assisted labels)" in text


def test_summary_treats_a_missing_seconds_key_as_not_recorded():
    rows = [{"alert_id": "a1", "label": "benign", "rationale": "step 4"}]
    assert "not recorded (assisted labels)" in label.summarise(rows, ["a1"])


def test_summary_ignores_rows_outside_the_sample():
    text = label.summarise([_row("a1", 2.0), _row("zz", 100.0)], ["a1"])
    assert "labelled 1/1" in text and "avg 2.0s" in text


# --- key-field recap --------------------------------------------------------

def test_key_fields_lists_present_fields_with_pids_in_both_forms():
    e = {"event_id": "Sysmon:1", "Hostname": "WORKSTATION5.theshire.local", "SourceImage": "C:\\x\\svchost.exe",
         "SourceProcessId": "1784", "TargetImage": "C:\\x\\lsass.exe", "GrantedAccess": "0x1000",
         "Message": "not a key field"}
    lines = label.key_fields(e)
    assert "SourceImage          C:\\x\\svchost.exe" in lines
    assert "SourceProcessId      1784 (0x6f8)" in lines
    assert "GrantedAccess        0x1000" in lines
    assert not any("Message" in line or "Hostname" in line for line in lines)


def test_key_fields_truncates_long_values():
    lines = label.key_fields({"CommandLine": "x" * 500})
    assert len(lines) == 1 and len(lines[0]) < 200 and lines[0].endswith("...")


# --- spot check -------------------------------------------------------------

def test_spotcheck_draws_six_unsampled_alerts_across_groups():
    alerts = _dataset()
    sampled = {alert_id for alert_id, _ in label.draw_sample(alerts, seed=42)}
    spot = label.draw_spotcheck(alerts, exclude=sampled)
    assert len(spot) == 6
    assert not {alert_id for alert_id, _ in spot} & sampled
    assert Counter(group for _, group in spot) == label.SPOTCHECK_SPLIT


def test_spotcheck_is_reproducible_with_seed_seven():
    alerts = _dataset()
    sampled = {alert_id for alert_id, _ in label.draw_sample(alerts, seed=42)}
    assert label.draw_spotcheck(alerts, exclude=sampled) == label.draw_spotcheck(alerts, exclude=sampled, seed=7)
    assert label.draw_spotcheck(alerts, exclude=sampled) != label.draw_spotcheck(alerts, exclude=sampled, seed=8)


def test_spotcheck_takes_what_is_left_when_a_group_is_short():
    alerts = _dataset()
    exclude = {a["alert_id"] for a in alerts if a["host"].startswith("MORDORDC")}
    groups = Counter(group for _, group in label.draw_spotcheck(alerts, exclude=exclude))
    assert groups["proc_access_dc"] == 0
