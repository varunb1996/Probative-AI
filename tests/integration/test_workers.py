"""Ingest and workers end to end on the Neon test branch, with a scripted judge (no model)."""

import json
from pathlib import Path

import pytest

from triage.domain import JudgeResult, Verdict
from triage.judge.client import CloudRefused
from triage.pipeline.parse import parse_alert, parse_event
from triage.services import workers
from triage.services.ingest import ingest
from triage.store import queue, repositories as repo
from triage.verify.checks import VerifyPolicy

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
IDS = sorted(p.stem for p in FIXTURES.glob("*.json"))
ATTACK, ROUTINE = "32a60c4fa80ff99c", "27881e43475ab248"
POLICY = VerifyPolicy(high_risk_score=5, close_confidence={"Proc Access": 0.9})


def _pairs():
    out = []
    for alert_id in IDS:
        fx = json.loads((FIXTURES / f"{alert_id}.json").read_text(encoding="utf-8"))
        record = json.loads((FIXTURES / "hayabusa" / f"{alert_id}.json").read_text(encoding="utf-8"))
        event = parse_event(fx["event"])
        out.append((parse_alert(record, event, dataset="public"), event))
    return out


def scripted(verdicts):
    """A judge that answers from a table: alert_id -> (verdict, confidence, missing_context)."""
    def judge_fn(bundle, evidence):
        alert_id = bundle.alert.alert_id
        verdict, confidence, missing = verdicts[alert_id]
        v = Verdict(alert_id=alert_id, verdict=verdict, confidence=confidence,
                    cited_event_ids=[bundle.events[0].event_id], summary="Scripted.", missing_context=missing)
        return JudgeResult(alert_id=alert_id, verdict=v, attempts=1,
                           shown_event_ids=[e.event_id for e in bundle.events])
    return judge_fn


ANSWERS = {a: ("suspicious", 0.6, []) for a in IDS} | {
    ATTACK: ("malicious", 0.9, []),
    ROUTINE: ("benign", 0.95, []),
    "3272105ca1ce8305": ("suspicious", 0.6, ["what 10.10.10.5 is"]),
}


@pytest.fixture
def ingested(conn):
    pairs = _pairs()
    assert ingest(conn, [e for _, e in pairs], pairs) == len(IDS)
    return conn


def test_ingest_is_idempotent(ingested):
    pairs = _pairs()
    assert ingest(ingested, [e for _, e in pairs], pairs) == 0


def test_drain_routes_every_alert_and_empties_both_streams(ingested):
    workers.drain(ingested, scripted(ANSWERS), lambda alert: POLICY)
    assert repo.get_verdict(ingested, ATTACK)["route"] == "escalate"
    assert repo.get_verdict(ingested, ROUTINE)["route"] == "suggest_close"
    assert queue.pending(ingested, workers.RAW) == queue.pending(ingested, workers.ENRICHED) == 0
    assert ingested.execute("select count(*) as n from verdicts").fetchone()["n"] == len(IDS)


def test_suspicious_with_missing_context_goes_to_the_investigate_stream(ingested):
    workers.drain(ingested, scripted(ANSWERS), lambda alert: POLICY)
    [msg] = queue.claim(ingested, workers.INVESTIGATE)
    assert msg.alert_id == "3272105ca1ce8305"


def test_every_step_is_audited(ingested):
    workers.drain(ingested, scripted(ANSWERS), lambda alert: POLICY)
    kinds = {r["kind"] for r in ingested.execute(
        "select kind from audit_log where alert_id = %s", (ATTACK,)).fetchall()}
    assert kinds == {"judge", "verify", "route"}


def test_the_bundle_comes_from_postgres_and_holds_the_attacker_process(ingested):
    workers.drain(ingested, scripted(ANSWERS), lambda alert: POLICY)
    verdict = repo.get_verdict(ingested, "3272105ca1ce8305")   # PID-only Security event
    shown = set(verdict["judge_result"]["shown_event_ids"])
    assert "Microsoft-Windows-Sysmon/Operational:725757" in shown   # its Sysmon lsass access


def test_a_failing_step_is_left_for_retry_and_never_writes_a_verdict(ingested):
    def broken(bundle, evidence):
        raise RuntimeError("inference host down")

    workers.drain(ingested, broken, lambda alert: POLICY)
    assert repo.get_verdict(ingested, ATTACK) is None
    assert queue.pending(ingested, workers.ENRICHED) == len(IDS)


def test_cloud_refusal_stops_the_worker(ingested):
    def refused(bundle, evidence):
        raise CloudRefused("not public")

    with pytest.raises(CloudRefused):
        workers.drain(ingested, refused, lambda alert: POLICY)


def test_critical_host_alerts_are_triaged_first(conn):
    pairs = _pairs()
    ingest(conn, [e for _, e in pairs], pairs, critical_hosts=frozenset({"workstation6.theshire.local"}))
    [first] = queue.claim(conn, workers.RAW)
    assert repo.get_alert(conn, first.alert_id)[0].host == "WORKSTATION6.theshire.local"


def test_an_accepted_close_becomes_a_confirmed_prior_for_later_alerts(ingested):
    workers.drain(ingested, scripted(ANSWERS), lambda alert: POLICY)
    ws5 = sorted((a for a, _ in _pairs() if a.host == "WORKSTATION5.theshire.local"), key=lambda a: a.timestamp)
    earliest, latest = ws5[0], ws5[-1]
    repo.record_decision(ingested, earliest.alert_id, "accept", "analyst-1")
    priors = {p.alert.alert_id: p for p in repo.prior_alerts(ingested, latest)}
    assert priors[earliest.alert_id].human_confirmed and priors[earliest.alert_id].verdict == "benign"
