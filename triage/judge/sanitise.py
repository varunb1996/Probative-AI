"""Log text is hostile data. Clean it, cap it, and pick what the model sees."""

import re
from typing import Any

from triage.domain import Event, EvidenceBundle

MAX_VALUE = 2000
MAX_NEIGHBOURS = 40
# Message repeats the other fields as prose; the rest is collector boilerplate.
DROP_FIELDS = {"Message", "tags", "@version", "Keywords", "host", "port",
               "SourceModuleName", "SourceModuleType", "EventReceivedTime"}

# C0/C1 controls except tab and newline, plus Unicode bidi overrides and isolates.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")
_DELIMITER = re.compile(r"<\s*/?\s*untrusted_logs\s*>", re.IGNORECASE)


def clean(value: str) -> str:
    text = _DELIMITER.sub("[delimiter removed]", _CONTROL.sub("", value))
    if len(text) > MAX_VALUE:
        text = text[:MAX_VALUE] + " [truncated]"
    return text


def select_events(bundle: EvidenceBundle, n: int = MAX_NEIGHBOURS) -> list[Event]:
    """The triggering event plus the n bundle events closest to it in time, in time order."""
    trigger, rest = bundle.events[0], bundle.events[1:]
    nearest = sorted(rest, key=lambda e: (abs(e.timestamp - trigger.timestamp), e.event_id))[:n]
    return sorted([trigger, *nearest], key=lambda e: (e.timestamp, e.event_id))


def render_event(event: Event) -> dict[str, Any]:
    out: dict[str, Any] = {"event_id": event.event_id}
    for key, value in event.fields.items():
        if key in DROP_FIELDS or key == "event_id":
            continue
        out[clean(key)] = clean(value) if isinstance(value, str) else value
    return out
