"""Golden bundles and a scripted fake chat client for judge tests. No network."""

import json
from pathlib import Path

from triage.domain import EvidenceBundle, EvidenceScore
from triage.judge.client import Completion, InferenceConfig
from triage.pipeline.parse import parse_alert, parse_event

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
LOCAL = InferenceConfig(base_url="http://localhost:11434/v1", model="small-local")
CLOUD = InferenceConfig(base_url="https://openrouter.ai/api/v1", model="cloud", allow_cloud=True)


def golden_bundle(alert_id: str, dataset: str | None = None) -> EvidenceBundle:
    fx = json.loads((FIXTURES / f"{alert_id}.json").read_text(encoding="utf-8"))
    record = json.loads((FIXTURES / "hayabusa" / f"{alert_id}.json").read_text(encoding="utf-8"))
    trigger = parse_event(fx["event"])
    return EvidenceBundle(alert=parse_alert(record, trigger, dataset=dataset), events=[trigger])


SCORE = EvidenceScore(total=4, contributions={"level_medium": 3, "mitre_tagged": 1})


def verdict_json(bundle: EvidenceBundle, **overrides) -> str:
    body = {"alert_id": bundle.alert.alert_id, "verdict": "malicious", "confidence": 0.9,
            "cited_event_ids": [bundle.events[0].event_id], "summary": "Attacker process reads lsass.",
            "missing_context": []}
    body.update(overrides)
    return json.dumps(body)


class FakeClient:
    """Returns scripted replies in order and records every request."""

    def __init__(self, *replies: str):
        self.replies = list(replies)
        self.calls: list[list[dict]] = []

    def complete(self, messages, schema):
        self.calls.append(messages)
        return Completion(text=self.replies.pop(0), tokens=100)

