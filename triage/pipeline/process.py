"""Which process an event is about. One table per channel; Security events carry only PIDs."""

from typing import Any

from triage.domain import Event, ProcessRef

_SYSMON = "Microsoft-Windows-Sysmon/Operational"
_SECURITY = "Security"

# (channel, EventID) -> (pid field, guid field) of the acting process, where the default does not fit.
_ACTOR_FIELDS = {
    (_SYSMON, 8): ("SourceProcessId", "SourceProcessGuid"),
    (_SYSMON, 10): ("SourceProcessId", "SourceProcessGUID"),
    (_SECURITY, 4688): ("NewProcessId", None),
}
_DEFAULT_ACTOR = {_SYSMON: ("ProcessId", "ProcessGuid"), _SECURITY: ("ProcessId", None)}

# Process-create events name the parent; 4688's ProcessId is the creator.
_PARENT_FIELDS = {
    (_SYSMON, 1): ("ParentProcessId", "ParentProcessGuid"),
    (_SECURITY, 4688): ("ProcessId", None),
}


def actor_process(event: Event) -> ProcessRef | None:
    channel = event.fields.get("Channel")
    fields = _ACTOR_FIELDS.get((channel, event.fields.get("EventID")), _DEFAULT_ACTOR.get(channel))
    return _ref(event, fields)


def parent_process(event: Event) -> ProcessRef | None:
    return _ref(event, _PARENT_FIELDS.get((event.fields.get("Channel"), event.fields.get("EventID"))))


def _ref(event: Event, fields: tuple[str, str | None] | None) -> ProcessRef | None:
    if fields is None:
        return None
    pid = _pid(event.fields.get(fields[0]))
    if pid is None:
        return None
    guid = event.fields.get(fields[1]) if fields[1] else None
    return ProcessRef(host=event.host, pid=pid, guid=guid or None)


def _pid(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)
