"""Investigator tools. Read-only by construction: each one only calls a read method of an
EventSource or IntelLookup. Arguments are typed fields checked here; there are no free-text queries.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from triage.domain import Event, EventSource, EvidenceBundle, IntelHit, IntelLookup, ProcessRef

WINDOW_CAP = timedelta(minutes=15)
_GUID = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")
_HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_ARGS = {
    "process_tree": ({"host", "pid"}, {"guid"}),
    "network_connections": ({"host", "pid"}, {"guid"}),
    "host_timeline": ({"host", "start", "end"}, set()),
    "entity_lookup": ({"kind", "value"}, set()),
}
TOOLS = tuple(_ARGS)


class ToolError(ValueError):
    """A malformed or out-of-bounds tool call. Rejected and logged; never executed."""


@dataclass
class ToolOutput:
    events: list[Event] = field(default_factory=list)
    hits: list[IntelHit] = field(default_factory=list)


def run_tool(name: str, args: dict[str, Any], bundle: EvidenceBundle, source: EventSource,
             intel: IntelLookup) -> ToolOutput:
    if name not in _ARGS:
        raise ToolError(f"unknown tool {name!r}; the tools are {', '.join(TOOLS)}")
    required, optional = _ARGS[name]
    if not isinstance(args, dict):
        raise ToolError("arguments must be an object")
    missing, extra = required - set(args), set(args) - required - optional
    if missing or extra:
        raise ToolError(f"{name} needs {sorted(required)}" + (f", optionally {sorted(optional)}" if optional else "")
                        + (f"; missing {sorted(missing)}" if missing else "") + (f"; unexpected {sorted(extra)}" if extra else ""))

    if name == "entity_lookup":
        return ToolOutput(hits=_lookup(args["kind"], args["value"], intel))
    host = _host(args["host"], bundle)
    if name == "host_timeline":
        start, end = _time(args["start"]), _time(args["end"])
        if end <= start:
            raise ToolError("end must be after start")
        if end - start > WINDOW_CAP:
            raise ToolError(f"time window {end - start} is wider than the {WINDOW_CAP} cap")
        return ToolOutput(events=source.host_window(host, start, end))
    process = ProcessRef(host=host, pid=_pid(args["pid"]), guid=_guid(args.get("guid")))
    if name == "network_connections":
        return ToolOutput(events=source.network_events(process))
    return ToolOutput(events=source.process_events(process) + source.parent_events(process)
                      + source.child_events(process))


def _host(value: Any, bundle: EvidenceBundle) -> str:
    known = {bundle.alert.host} | {e.host for e in bundle.events}
    if not isinstance(value, str) or value not in known:
        raise ToolError(f"host must be one already in the evidence: {sorted(known)}")
    return value


def _pid(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ToolError("pid must be a non-negative integer")
    return value


def _guid(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _GUID.match(value):
        raise ToolError("guid must be a process GUID like {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}")
    return value


def _time(value: Any) -> datetime:
    try:
        t = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        t = None
    if t is None or t.tzinfo is None:
        raise ToolError("start and end must be ISO 8601 timestamps with a timezone")
    return t


def _lookup(kind: Any, value: Any, intel: IntelLookup) -> list[IntelHit]:
    if not isinstance(value, str):
        raise ToolError("value must be a string")
    if kind == "hash" and _HASH.match(value):
        hit = intel.lookup_hash(value)
    elif kind == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ToolError("value is not an IP address") from None
        hit = intel.lookup_ip(value)
    elif kind == "domain" and _DOMAIN.match(value):
        hit = intel.lookup_domain(value)
    elif kind in ("hash", "domain"):
        raise ToolError(f"value is not a valid {kind}")
    else:
        raise ToolError("kind must be hash, ip or domain")
    return [hit] if hit else []
