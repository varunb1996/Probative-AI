"""Read-only ports the pure core depends on. Implementations live at the edges."""

from datetime import datetime
from typing import Protocol

from triage.domain.models import Event, IntelHit


class EventSource(Protocol):
    def process_events(self, host: str, process_guid: str) -> list[Event]:
        """Events emitted by this process."""
        ...

    def parent_events(self, host: str, process_guid: str) -> list[Event]:
        """Events emitted by this process's parent."""
        ...

    def child_events(self, host: str, process_guid: str) -> list[Event]:
        """Events emitted by this process's children."""
        ...

    def network_events(self, host: str, process_guid: str) -> list[Event]:
        """Network events attributed to this process."""
        ...

    def host_window(self, host: str, start: datetime, end: datetime) -> list[Event]:
        """All events on a host in [start, end].

        Investigator only. The caller validates the host and caps the window;
        the context step builds process-scoped bundles and never calls this.
        """
        ...


class IntelLookup(Protocol):
    def lookup_hash(self, value: str) -> IntelHit | None: ...

    def lookup_ip(self, value: str) -> IntelHit | None: ...

    def lookup_domain(self, value: str) -> IntelHit | None: ...
