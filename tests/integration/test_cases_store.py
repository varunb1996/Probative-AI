"""Sandbox cases in the store: isolation, scoped listing, deletion, audit retention."""

from datetime import timedelta

import psycopg
import pytest
from integration_support import ATTACK, golden_pairs

from triage.domain import JudgeResult, ProcessRef
from triage.store import queue, repositories as repo
from triage.store.event_source import PostgresEventSource

pytestmark = pytest.mark.integration
_WS5 = "WORKSTATION5.theshire.local"


def _scoped(case_id):
    """The golden pairs with event ids prefixed by the case, as the sandbox stores them."""
    out = []
    for alert, event in golden_pairs():
        e = event.model_copy(update={"event_id": f"{case_id}/{event.event_id}"})
        a = alert.model_copy(update={"alert_id": f"{case_id}-{alert.alert_id}", "event_ids": [e.event_id]})
        out.append((a, e))
    return out


def _load(conn, case_id):
    pairs = _scoped(case_id) if case_id else golden_pairs()
    if case_id:
        repo.create_case(conn, case_id, "scenario", "test", client="c", ttl=timedelta(hours=24))
    repo.upsert_events(conn, [e for _, e in pairs], case_id=case_id)
    for a, e in pairs:
        repo.upsert_alert(conn, a, e.event_id, case_id=case_id)
    return pairs


def test_case_round_trip_and_update(conn):
    repo.create_case(conn, "c1", "upload", "my.evtx", client="ip-hash", ttl=timedelta(hours=24))
    repo.update_case(conn, "c1", status="ready", n_events=10, n_alerts=2)
    case = repo.get_case(conn, "c1")
    assert (case["status"], case["n_events"], case["source"], case["name"]) == ("ready", 10, "upload", "my.evtx")
    assert repo.get_case(conn, "missing") is None


def test_event_source_never_crosses_cases(conn):
    _load(conn, None)
    _load(conn, "caseA")
    _load(conn, "caseB")
    attacker = ProcessRef(host=_WS5, pid=1648)
    for case_id in (None, "caseA", "caseB"):
        ids = {e.event_id for e in PostgresEventSource(conn, case_id).process_events(attacker)}
        assert ids
        if case_id:
            assert all(i.startswith(f"{case_id}/") for i in ids)
        else:
            assert not any(i.startswith(("caseA/", "caseB/")) for i in ids)


def test_alert_case_lookup(conn):
    pairs = _load(conn, "caseA")
    assert repo.alert_case(conn, pairs[0][0].alert_id) == "caseA"
    _load(conn, None)
    assert repo.alert_case(conn, ATTACK) is None


def test_listing_is_scoped_to_a_case(conn):
    for case_id in (None, "caseA"):
        for a, _ in _load(conn, case_id):
            result = JudgeResult(alert_id=a.alert_id, attempts=2, error="x", shown_event_ids=[])
            repo.upsert_verdict(conn, a.alert_id, result, {"total": 1, "contributions": {}}, {"checks": []},
                                "escalate", ["schema"])
    demo = {r["alert_id"] for r in repo.list_by_route(conn, ["escalate"])}
    case = {r["alert_id"] for r in repo.list_by_route(conn, ["escalate"], case_id="caseA")}
    assert demo and case and not demo & case
    assert all(i.startswith("caseA-") for i in case)


def test_prior_alerts_stay_inside_the_case(conn):
    _load(conn, None)
    pairs = _load(conn, "caseA")
    latest = max((a for a, _ in pairs if a.host == _WS5), key=lambda a: a.timestamp)
    assert all(p.alert.alert_id.startswith("caseA-") for p in repo.prior_alerts(conn, latest))


def test_delete_case_removes_only_that_case(conn):
    _load(conn, None)
    pairs = _load(conn, "caseA")
    queue.enqueue(conn, "enriched", pairs[0][0].alert_id, {})
    repo.audit(conn, pairs[0][0].alert_id, "judge", {}, case_id="caseA")
    repo.delete_case(conn, "caseA")
    n = lambda table: conn.execute(f"select count(*) as n from {table}").fetchone()["n"]  # noqa: E731
    assert repo.get_case(conn, "caseA") is None
    assert n("alerts") == n("events") == len(golden_pairs())     # the demo data is untouched
    assert n("queue") == 0


def test_expired_cases_are_listed(conn):
    repo.create_case(conn, "old", "scenario", "x", client="c", ttl=timedelta(seconds=-1))
    repo.create_case(conn, "new", "scenario", "x", client="c", ttl=timedelta(hours=24))
    assert repo.expired_cases(conn) == ["old"]


def test_audit_retention_only_for_old_case_rows(conn):
    repo.audit(conn, "a1", "judge", {}, case_id="caseA")
    repo.audit(conn, "a2", "judge", {})
    conn.execute("insert into audit_log (alert_id, case_id, kind, payload, at) "
                 "values ('a3', 'caseA', 'judge', '{}', now() - interval '25 hours')")
    conn.execute("delete from audit_log where alert_id = 'a3'")          # past retention: allowed
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("delete from audit_log where alert_id = 'a1'")      # case row, still recent
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("delete from audit_log where alert_id = 'a2'")      # never: not a case row
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("update audit_log set kind = 'x' where alert_id = 'a1'")


def test_llm_budget_is_taken_atomically_per_case(conn):
    repo.create_case(conn, "c1", "scenario", "x", client="c", ttl=timedelta(hours=24))
    taken = [repo.take_llm_slot(conn, "c1", per_case=2) for _ in range(4)]
    assert taken == [True, True, False, False]
    assert repo.get_case(conn, "c1")["llm_used"] == 2


def test_llm_calls_today_counts_real_judge_calls(conn):
    repo.audit(conn, "a1", "judge", {"tokens_used": 120})
    repo.audit(conn, "a2", "judge", {"tokens_used": 0})        # replayed or skipped: no model call
    repo.audit(conn, "a3", "verify", {"tokens_used": 50})
    assert repo.llm_calls_today(conn) == 1


def test_recent_cases_from_a_client(conn):
    for i in range(3):
        repo.create_case(conn, f"c{i}", "upload", "x", client="ip1", ttl=timedelta(hours=24))
    repo.create_case(conn, "other", "upload", "x", client="ip2", ttl=timedelta(hours=24))
    assert repo.cases_since(conn, "ip1", timedelta(hours=1)) == 3
