"""Golden alerts and a scripted judge for integration tests. No model calls."""

import json
from pathlib import Path

from triage.domain import JudgeResult, Verdict
from triage.pipeline.parse import parse_alert, parse_event
from triage.verify.checks import VerifyPolicy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
IDS = sorted(p.stem for p in FIXTURES.glob("*.json"))
ATTACK, ROUTINE = "32a60c4fa80ff99c", "27881e43475ab248"
POLICY = VerifyPolicy(high_risk_score=5, close_confidence={"Proc Access": 0.9})


def golden_pairs():
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
