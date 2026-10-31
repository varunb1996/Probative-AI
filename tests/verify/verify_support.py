"""Golden bundles and judge results for verifier tests. Never imports triage.judge."""

import json
from pathlib import Path

from triage.domain import EvidenceBundle, EvidenceScore, JudgeResult, Verdict
from triage.pipeline.parse import parse_alert, parse_event
from triage.verify.checks import VerifyPolicy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ROUTINE = "27881e43475ab248"      # Proc Access: svchost opens svchost, labelled benign
POLICY = VerifyPolicy(high_risk_score=8, close_confidence={"Proc Access": 0.8})
LOW = EvidenceScore(total=1, contributions={"level_low": 1})
HIGH = EvidenceScore(total=13, contributions={"level_medium": 3, "lsass_target": 3, "encoded_command": 3,
                                              "script_host_actor": 2, "mitre_tagged": 1, "actor_network": 1})


def golden_bundle(alert_id: str = ROUTINE) -> EvidenceBundle:
    fx = json.loads((FIXTURES / f"{alert_id}.json").read_text(encoding="utf-8"))
    record = json.loads((FIXTURES / "hayabusa" / f"{alert_id}.json").read_text(encoding="utf-8"))
    trigger = parse_event(fx["event"])
    return EvidenceBundle(alert=parse_alert(record, trigger), events=[trigger])


def result_for(bundle: EvidenceBundle, **overrides) -> JudgeResult:
    """A clean benign verdict citing the trigger, with any field overridden."""
    trigger = bundle.events[0].event_id
    fields = {"alert_id": bundle.alert.alert_id, "verdict": "benign", "confidence": 0.95,
              "cited_event_ids": [trigger], "summary": "svchost opens svchost with 0x1000, routine.",
              "missing_context": []}
    fields.update(overrides)
    return JudgeResult(alert_id=bundle.alert.alert_id, verdict=Verdict(**fields), attempts=1,
                       shown_event_ids=[e.event_id for e in bundle.events])
