"""Golden evidence and scripted decide functions for investigator tests. No model, no database."""

import json
from pathlib import Path

from triage.domain import EvidenceBundle, Event, IntelHit, ProcessRef, Verdict
from triage.investigate.loop import Decision, DecisionError
from triage.pipeline.parse import parse_alert, parse_event
from triage.pipeline.process import actor_process, parent_process
from triage.verify.checks import VerifyPolicy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
IDS = sorted(p.stem for p in FIXTURES.glob("*.json"))
WS5 = "WORKSTATION5.theshire.local"
ATTACKER = {"host": WS5, "pid": 1648, "guid": "{297bc33e-65d0-5f2d-8207-000000000400}"}
POLICY = VerifyPolicy(high_risk_score=5, close_confidence={"Network Connection Initiated By PowerShell Process": 0.9})


def golden(alert_id):
    fx = json.loads((FIXTURES / f"{alert_id}.json").read_text(encoding="utf-8"))
    record = json.loads((FIXTURES / "hayabusa" / f"{alert_id}.json").read_text(encoding="utf-8"))
    event = parse_event(fx["event"])
    return parse_alert(record, event, dataset="public"), event


def start_bundle(alert_id="3272105ca1ce8305"):
    """Only the triggering event: the investigator has to go and find the rest."""
    alert, trigger = golden(alert_id)
    return EvidenceBundle(alert=alert, events=[trigger])


def all_events():
    return [golden(a)[1] for a in IDS]


class Source:
    """In-memory EventSource over the golden events; counts window queries."""

    def __init__(self, events: list[Event]):
        self.events = events

    def _is(self, ref, process):
        return ref is not None and ref.same_process(process)

    def process_events(self, process: ProcessRef):
        return [e for e in self.events if self._is(actor_process(e), process)]

    def parent_events(self, process):
        parents = [parent_process(e) for e in self.process_events(process)]
        return [e for e in self.events if any(self._is(actor_process(e), p) for p in parents if p)]

    def child_events(self, process):
        return [e for e in self.events if self._is(parent_process(e), process)]

    def network_events(self, process):
        return [e for e in self.process_events(process)
                if (e.fields.get("Channel"), e.fields.get("EventID")) in
                {("Microsoft-Windows-Sysmon/Operational", 3), ("Security", 5156)}]

    def host_window(self, host, start, end):
        return [e for e in self.events if e.host == host and start <= e.timestamp <= end]


class Intel:
    def __init__(self, bad=None):
        self.bad = {k.lower(): v for k, v in (bad or {}).items()}

    def _hit(self, value, kind):
        detail = self.bad.get(value.lower())
        return IntelHit(indicator=value, kind=kind, source="test", detail=detail) if detail else None

    def lookup_hash(self, value):
        return self._hit(value, "hash")

    def lookup_ip(self, value):
        return self._hit(value, "ip")

    def lookup_domain(self, value):
        return self._hit(value, "domain")


def tool(name, tokens=100, **args):
    return Decision(tool=name, args=args, tokens=tokens)


def verdict(bundle, label="malicious", confidence=0.9, cite_all=True, tokens=100, missing=None):
    ids = [e.event_id for e in bundle.events] if cite_all else [bundle.events[0].event_id]
    v = Verdict(alert_id=bundle.alert.alert_id, verdict=label, confidence=confidence, cited_event_ids=ids,
                summary="Scripted investigator verdict.", missing_context=missing or [])
    return Decision(verdict=v, tokens=tokens, shown_event_ids=[e.event_id for e in bundle.events])


class Script:
    """decide() that plays a list of steps. A step is a Decision, a DecisionError, or a callable(bundle)."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.seen_states = []

    def __call__(self, bundle, score, state):
        self.seen_states.append(state)
        step = self.steps.pop(0)
        if isinstance(step, DecisionError):
            raise step
        return step(bundle) if callable(step) else step
