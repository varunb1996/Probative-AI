"""EventSource over data/events.jsonl. I/O, so it lives here and not in triage/."""

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from triage.domain import Event, IntelHit, ProcessRef
from triage.pipeline.parse import parse_event
from triage.pipeline.process import actor_process, parent_process

_NETWORK = {("Microsoft-Windows-Sysmon/Operational", 3), ("Security", 5156)}


class JsonlEventSource:
    def __init__(self, path: Path):
        with path.open(encoding="utf-8") as f:
            self.events = [parse_event(json.loads(line)) for line in f if line.strip()]
        self._by_host: dict[str, list[tuple[Event, ProcessRef | None, ProcessRef | None]]] = defaultdict(list)
        for e in self.events:
            self._by_host[e.host].append((e, actor_process(e), parent_process(e)))

    def process_events(self, process: ProcessRef) -> list[Event]:
        return [e for e, actor, _ in self._by_host[process.host] if _is(actor, process)]

    def parent_events(self, process: ProcessRef) -> list[Event]:
        parents = [p for e, actor, p in self._by_host[process.host] if p and _is(actor, process)]
        return [e for e, actor, _ in self._by_host[process.host]
                if any(_is(actor, p) for p in parents)]

    def child_events(self, process: ProcessRef) -> list[Event]:
        children = [actor for _, actor, parent in self._by_host[process.host]
                    if actor and _is(parent, process)]
        return [e for e, actor, _ in self._by_host[process.host]
                if any(_is(actor, c) for c in children)]

    def network_events(self, process: ProcessRef) -> list[Event]:
        return [e for e in self.process_events(process)
                if (e.fields.get("Channel"), e.fields.get("EventID")) in _NETWORK]

    def host_window(self, host: str, start: datetime, end: datetime) -> list[Event]:
        """The investigator's capped time-window query (the cap is enforced by its tool)."""
        return [e for e, _, _ in self._by_host[host] if start <= e.timestamp <= end]


class NoIntel:
    """No local threat-intel feed is synced yet, so every lookup misses."""

    def lookup_hash(self, value: str) -> IntelHit | None:
        return None

    def lookup_ip(self, value: str) -> IntelHit | None:
        return None

    def lookup_domain(self, value: str) -> IntelHit | None:
        return None


def _is(ref: ProcessRef | None, process: ProcessRef) -> bool:
    return ref is not None and ref.same_process(process)
