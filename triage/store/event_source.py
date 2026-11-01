"""EventSource over the events table, with the same semantics as the in-memory sources:
a GUID matches a GUID; a side without one falls back to host + PID (ProcessRef.same_process).

Each source sees one case only (None: the demo data), so two uploads never share evidence.
"""

from datetime import datetime

import psycopg

from triage.domain import Event, ProcessRef
from triage.store.repositories import row_to_event

_COLUMNS = "event_id, host, ts, fields"
_SCOPE = "host = %s and case_id is not distinct from %s"
_NETWORK = "((channel = 'Microsoft-Windows-Sysmon/Operational' and event_code = 3) " \
           "or (channel = 'Security' and event_code = 5156))"


def _match(prefix: str, process: ProcessRef) -> tuple[str, list]:
    """SQL condition: the {prefix}_pid/{prefix}_guid columns name the same process."""
    if process.guid:
        return (f"({prefix}_pid is not null and ((({prefix}_guid is not null and lower({prefix}_guid) = lower(%s)) "
                f"or ({prefix}_guid is null and {prefix}_pid = %s))))", [process.guid, process.pid])
    return f"{prefix}_pid = %s", [process.pid]


class PostgresEventSource:
    def __init__(self, conn: psycopg.Connection, case_id: str | None = None):
        self.conn = conn
        self.case_id = case_id

    def _where(self, host: str, conditions: list[tuple[str, list]], extra: str = "") -> list[Event]:
        if not conditions:
            return []
        sql = " or ".join(c for c, _ in conditions)
        params = [host, self.case_id] + [p for _, ps in conditions for p in ps]
        rows = self.conn.execute(f"select {_COLUMNS} from events where {_SCOPE} and ({sql}) {extra} "
                                 "order by seq", params).fetchall()
        return [row_to_event(r) for r in rows]

    def process_events(self, process: ProcessRef) -> list[Event]:
        return self._where(process.host, [_match("actor", process)])

    def parent_events(self, process: ProcessRef) -> list[Event]:
        cond, params = _match("actor", process)
        parents = self.conn.execute(
            f"select distinct parent_pid, parent_guid from events where {_SCOPE} and parent_pid is not null "
            f"and {cond}", [process.host, self.case_id, *params]).fetchall()
        refs = [ProcessRef(host=process.host, pid=r["parent_pid"], guid=r["parent_guid"]) for r in parents]
        return self._where(process.host, [_match("actor", p) for p in refs])

    def child_events(self, process: ProcessRef) -> list[Event]:
        cond, params = _match("parent", process)
        children = self.conn.execute(
            f"select distinct actor_pid, actor_guid from events where {_SCOPE} and actor_pid is not null "
            f"and {cond}", [process.host, self.case_id, *params]).fetchall()
        refs = [ProcessRef(host=process.host, pid=r["actor_pid"], guid=r["actor_guid"]) for r in children]
        return self._where(process.host, [_match("actor", c) for c in refs])

    def network_events(self, process: ProcessRef) -> list[Event]:
        return self._where(process.host, [_match("actor", process)], extra=f"and {_NETWORK}")

    def host_window(self, host: str, start: datetime, end: datetime) -> list[Event]:
        rows = self.conn.execute(f"select {_COLUMNS} from events where {_SCOPE} and ts between %s and %s "
                                 "order by seq", (host, self.case_id, start, end)).fetchall()
        return [row_to_event(r) for r in rows]
