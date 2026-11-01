"""The investigate stream on the Neon test branch, with a scripted decide (no model)."""

import json
from datetime import timedelta

import pytest
from integration_support import ANSWERS, FIXTURES, IDS, POLICY, golden_pairs, scripted

from triage.domain import Investigation, LoopState, Verdict
from triage.investigate.loop import Decision
from triage.services import sandbox, workers
from triage.services.ingest import ingest
from triage.store import queue, repositories as repo

pytestmark = pytest.mark.integration
SUSPICIOUS = "3272105ca1ce8305"    # ANSWERS routes it to investigate (suspicious, missing context)
ATTACKER = {"host": "WORKSTATION5.theshire.local", "pid": 1648}


def _decide(final="malicious"):
    steps = []

    def decide(bundle, score, state):
        if not steps:
            steps.append(1)
            return Decision(tool="process_tree", args=ATTACKER, tokens=100)
        v = Verdict(alert_id=bundle.alert.alert_id, verdict=final, confidence=0.95,
                    cited_event_ids=[e.event_id for e in bundle.events], summary="Investigated.", missing_context=[])
        return Decision(verdict=v, tokens=100, shown_event_ids=[e.event_id for e in bundle.events])
    return decide


@pytest.fixture
def waiting(conn):
    pairs = golden_pairs()
    ingest(conn, [e for _, e in pairs], pairs)
    workers.drain(conn, scripted(ANSWERS), lambda alert: POLICY)
    [msg] = queue.claim(conn, workers.INVESTIGATE)
    return conn, msg


def test_investigation_updates_the_route_and_is_stored(waiting):
    conn, msg = waiting
    workers.investigate_step(conn, msg, _decide("malicious"), lambda alert: POLICY, daily_cap=5)
    v = repo.get_verdict(conn, SUSPICIOUS)
    assert v["route"] == "escalate" and "malicious" in v["reasons"][0]
    inv = repo.get_investigation(conn, SUSPICIOUS)
    assert inv["verified"] and inv["state"]["query_log"][0]["tool"] == "process_tree"
    assert queue.pending(conn, workers.INVESTIGATE) == 0
    kinds = {r["kind"] for r in conn.execute("select kind from audit_log where alert_id = %s", (SUSPICIOUS,)).fetchall()}
    assert "investigation" in kinds


def test_daily_cap_hands_the_alert_to_a_human(waiting):
    conn, msg = waiting
    for i in range(3):
        repo.audit(conn, f"x{i}", "investigation", {"steps": 1})
    workers.investigate_step(conn, msg, _decide(), lambda alert: POLICY, daily_cap=3)
    v = repo.get_verdict(conn, SUSPICIOUS)
    assert v["route"] == "escalate" and "budget" in v["reasons"][0]
    assert repo.get_investigation(conn, SUSPICIOUS) is None


def test_sandbox_alerts_are_not_investigated(conn):
    case_id = sandbox.new_case_id()
    repo.create_case(conn, case_id, "upload", "x", client="c", ttl=timedelta(hours=24))
    raw = [json.loads((FIXTURES / f"{a}.json").read_text(encoding="utf-8"))["event"] for a in IDS]
    dets = [json.loads((FIXTURES / "hayabusa" / f"{a}.json").read_text(encoding="utf-8")) for a in IDS]
    sandbox.build_case(conn, case_id, raw, dets)
    ids = [r["alert_id"] for r in conn.execute("select alert_id from alerts where case_id = %s", (case_id,)).fetchall()]
    answers = {alert_id: ("suspicious", 0.6, ["more"]) for alert_id in ids}
    workers.drain(conn, scripted(answers), lambda alert: POLICY)
    msg = queue.claim(conn, workers.INVESTIGATE)[0]
    workers.investigate_step(conn, msg, _decide(), lambda alert: POLICY, daily_cap=5)
    v = repo.get_verdict(conn, msg.alert_id)
    assert v["route"] == "escalate" and "sandbox" in v["reasons"][0]


def test_deleting_a_case_removes_its_investigations(conn):
    case_id = sandbox.new_case_id()
    repo.create_case(conn, case_id, "upload", "x", client="c", ttl=timedelta(hours=24))
    pairs = [(a.model_copy(update={"alert_id": f"{case_id}-{a.alert_id}"}), e.model_copy(
        update={"event_id": f"{case_id}/{e.event_id}"})) for a, e in golden_pairs()]
    repo.upsert_events(conn, [e for _, e in pairs], case_id=case_id)
    alert, event = pairs[0]
    repo.upsert_alert(conn, alert.model_copy(update={"event_ids": [event.event_id]}), event.event_id, case_id=case_id)
    repo.upsert_investigation(conn, Investigation(alert_id=alert.alert_id, verified=False, stop_reason="step cap",
                                                  state=LoopState()))
    repo.delete_case(conn, case_id)
    assert repo.get_investigation(conn, alert.alert_id) is None
