"""Postgres store and queue against the Neon test branch."""

import json
import threading
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest

from triage.domain import JudgeResult, ProcessRef, RuleMode
from triage.pipeline.parse import parse_alert, parse_event
from triage.store import queue, repositories as repo
from triage.store.db import connect
from triage.store.event_source import PostgresEventSource

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
IDS = sorted(p.stem for p in FIXTURES.glob("*.json"))
_WS5 = "WORKSTATION5.theshire.local"
_ATTACKER = ProcessRef(host=_WS5, pid=1648, guid="{297bc33e-65d0-5f2d-8207-000000000400}")


def _golden(alert_id):
    fx = json.loads((FIXTURES / f"{alert_id}.json").read_text(encoding="utf-8"))
    record = json.loads((FIXTURES / "hayabusa" / f"{alert_id}.json").read_text(encoding="utf-8"))
    event = parse_event(fx["event"])
    return parse_alert(record, event, dataset="public"), event


@pytest.fixture
def loaded(conn):
    pairs = [_golden(a) for a in IDS]
    repo.upsert_events(conn, [event for _, event in pairs])
    for alert, event in pairs:
        repo.upsert_alert(conn, alert, event.event_id)
    return conn, pairs


# --- queue ------------------------------------------------------------------

def test_enqueue_is_idempotent(conn):
    assert queue.enqueue(conn, "raw", "a1", {"n": 1})
    assert not queue.enqueue(conn, "raw", "a1", {"n": 2})
    [msg] = queue.claim(conn, "raw")
    assert msg.payload == {"n": 1}


def test_claimed_message_is_not_claimed_twice_until_its_lease_expires(conn):
    queue.enqueue(conn, "raw", "a1", {})
    assert len(queue.claim(conn, "raw", lease=timedelta(minutes=5))) == 1
    assert queue.claim(conn, "raw") == []


def test_expired_lease_is_reclaimed(conn):
    queue.enqueue(conn, "raw", "a1", {})
    queue.claim(conn, "raw", lease=timedelta(seconds=-1))   # a worker that died mid-message
    [again] = queue.claim(conn, "raw")
    assert again.alert_id == "a1" and again.attempts == 2


def test_acked_message_is_never_redelivered(conn):
    queue.enqueue(conn, "raw", "a1", {})
    [msg] = queue.claim(conn, "raw", lease=timedelta(seconds=-1))
    queue.ack(conn, msg.id)
    assert queue.claim(conn, "raw") == []


def test_priority_lane_is_claimed_first(conn):
    queue.enqueue(conn, "raw", "normal", {})
    queue.enqueue(conn, "raw", "critical", {}, priority=1)
    assert queue.claim(conn, "raw")[0].alert_id == "critical"


def test_streams_are_separate(conn):
    queue.enqueue(conn, "raw", "a1", {})
    assert queue.claim(conn, "enriched") == []


def test_poison_message_stops_after_max_attempts(conn):
    queue.enqueue(conn, "raw", "a1", {})
    for _ in range(queue.MAX_ATTEMPTS):
        assert queue.claim(conn, "raw", lease=timedelta(seconds=-1))
    assert queue.claim(conn, "raw") == []


def test_two_workers_never_claim_the_same_message(conn, test_url):
    for i in range(40):
        queue.enqueue(conn, "raw", f"a{i}", {})
    claimed: list[str] = []
    lock = threading.Lock()

    def worker():
        with connect(test_url) as c:
            while batch := queue.claim(c, "raw", limit=3):
                with lock:
                    claimed.extend(m.alert_id for m in batch)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(claimed) == sorted(f"a{i}" for i in range(40))


def test_pending_counts(conn):
    queue.enqueue(conn, "raw", "a1", {})
    queue.enqueue(conn, "raw", "a2", {})
    queue.ack(conn, queue.claim(conn, "raw")[0].id)
    assert queue.pending(conn, "raw") == 1


# --- repositories ---------------------------------------------------------------

def test_alert_round_trips_with_its_trigger(loaded):
    conn, pairs = loaded
    alert, event = pairs[0]
    got_alert, got_trigger = repo.get_alert(conn, alert.alert_id)
    assert got_alert == alert and got_trigger == event


def test_upserts_are_idempotent(loaded):
    conn, pairs = loaded
    alert, event = pairs[0]
    repo.upsert_events(conn, [event])
    repo.upsert_alert(conn, alert, event.event_id)
    assert conn.execute("select count(*) as n from alerts").fetchone()["n"] == len(IDS)


def _result(alert, verdict=None):
    return JudgeResult(alert_id=alert.alert_id, attempts=2, error="no verdict",
                       shown_event_ids=alert.event_ids)


def test_verdict_upsert_replaces_the_previous_row(loaded):
    conn, pairs = loaded
    alert = pairs[0][0]
    repo.upsert_verdict(conn, alert.alert_id, _result(alert), {"total": 1}, {"checks": []}, "escalate", ["a"])
    repo.upsert_verdict(conn, alert.alert_id, _result(alert), {"total": 1}, {"checks": []}, "suggest_close", [])
    assert repo.get_verdict(conn, alert.alert_id)["route"] == "suggest_close"
    assert conn.execute("select count(*) as n from verdicts").fetchone()["n"] == 1


def test_human_decision_is_recorded_as_confirmed(loaded):
    conn, pairs = loaded
    alert = pairs[0][0]
    repo.record_decision(conn, alert.alert_id, "accept", "analyst-1")
    row = conn.execute("select * from human_decisions").fetchone()
    assert row["decision"] == "accept" and row["human_confirmed"] is True


def test_rule_mode_defaults_to_shadow(loaded):
    conn, _ = loaded
    assert repo.get_rule_mode(conn, "Proc Access") == RuleMode.SHADOW
    repo.set_rule_mode(conn, "Proc Access", RuleMode.ASSISTED)
    assert repo.get_rule_mode(conn, "Proc Access") == RuleMode.ASSISTED


def test_audit_log_is_append_only(loaded):
    conn, pairs = loaded
    repo.audit(conn, pairs[0][0].alert_id, "judge", {"tokens": 10})
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("update audit_log set kind = 'tampered'")
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("delete from audit_log")


def test_prior_alerts_carry_a_verdict_only_when_a_human_accepted(loaded):
    conn, pairs = loaded
    ws5 = sorted((a for a, _ in pairs if a.host == _WS5), key=lambda a: a.timestamp)
    earlier, later = ws5[0], ws5[-1]
    repo.record_decision(conn, earlier.alert_id, "accept", "analyst-1")
    priors = repo.prior_alerts(conn, later)
    by_id = {p.alert.alert_id: p for p in priors}
    assert by_id[earlier.alert_id].human_confirmed and by_id[earlier.alert_id].verdict == "benign"
    assert all(p.verdict is None for p in priors if p.alert.alert_id != earlier.alert_id)
    assert later.alert_id not in by_id


# --- event source ---------------------------------------------------------------

def test_event_source_finds_the_attacker_process_by_guid_and_by_pid(loaded):
    conn, pairs = loaded
    source = PostgresEventSource(conn)
    by_guid = {e.event_id for e in source.process_events(_ATTACKER)}
    by_pid = {e.event_id for e in source.process_events(ProcessRef(host=_WS5, pid=1648))}
    lsass_access = _golden("32a60c4fa80ff99c")[1].event_id
    security_conn = _golden("3272105ca1ce8305")[1].event_id
    assert lsass_access in by_guid and security_conn in by_guid   # PID-only Security event joins
    assert lsass_access in by_pid


def test_event_source_children_and_network(loaded):
    conn, _ = loaded
    source = PostgresEventSource(conn)
    whoami = _golden("44f255f374992221")[1].event_id
    assert whoami in {e.event_id for e in source.child_events(_ATTACKER)}
    assert {e.event_id for e in source.network_events(_ATTACKER)} == {_golden("3272105ca1ce8305")[1].event_id}


def test_event_source_matches_the_in_memory_fake(loaded):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline"))
    from fakes import FakeEventSource

    conn, pairs = loaded
    fake, real = FakeEventSource([e for _, e in pairs]), PostgresEventSource(conn)
    for proc in (_ATTACKER, ProcessRef(host=_WS5, pid=452), ProcessRef(host=_WS5, pid=1648)):
        for method in ("process_events", "parent_events", "child_events", "network_events"):
            assert [e.event_id for e in getattr(real, method)(proc)] == \
                   [e.event_id for e in getattr(fake, method)(proc)], (proc, method)
