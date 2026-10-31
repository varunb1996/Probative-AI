"""In-memory fakes of the domain ports. No database, no network."""

from datetime import datetime

from triage.domain import Event, IntelHit, ProcessRef
from triage.pipeline.process import actor_process, parent_process

_NETWORK = {("Microsoft-Windows-Sysmon/Operational", 3), ("Security", 5156)}


class FakeEventSource:
    def __init__(self, events: list[Event]):
        self.events = events
        self.window_calls = 0

    def process_events(self, process: ProcessRef) -> list[Event]:
        return [e for e in self.events if _is(actor_process(e), process)]

    def parent_events(self, process: ProcessRef) -> list[Event]:
        parents = [parent_process(e) for e in self.process_events(process)]
        return [e for e in self.events if any(_is(actor_process(e), p) for p in parents if p)]

    def child_events(self, process: ProcessRef) -> list[Event]:
        return [e for e in self.events if _is(parent_process(e), process)]

    def network_events(self, process: ProcessRef) -> list[Event]:
        return [e for e in self.process_events(process)
                if (e.fields.get("Channel"), e.fields.get("EventID")) in _NETWORK]

    def host_window(self, host: str, start: datetime, end: datetime) -> list[Event]:
        self.window_calls += 1
        return [e for e in self.events if e.host == host and start <= e.timestamp <= end]


class FakeIntelLookup:
    def __init__(self, bad: dict[str, str]):
        self.bad = {k.lower(): v for k, v in bad.items()}
        self.seen: list[str] = []

    def _hit(self, value: str, kind: str) -> IntelHit | None:
        self.seen.append(value)
        detail = self.bad.get(value.lower())
        return IntelHit(indicator=value, kind=kind, source="fake", detail=detail) if detail else None

    def lookup_hash(self, value: str) -> IntelHit | None:
        return self._hit(value, "hash")

    def lookup_ip(self, value: str) -> IntelHit | None:
        return self._hit(value, "ip")

    def lookup_domain(self, value: str) -> IntelHit | None:
        return self._hit(value, "domain")


def _is(ref: ProcessRef | None, process: ProcessRef) -> bool:
    return ref is not None and ref.same_process(process)
