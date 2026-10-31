"""Step 1, read the alert: Hayabusa JSONL detections and raw NXLog events to domain objects.

Ported from scripts/null_test/detect.py so alert_ids match the Phase 0 labels.
"""

import hashlib
from datetime import datetime
from typing import Any

from triage.domain import Alert, Event

LEVELS = {"info": "info", "low": "low", "med": "medium", "high": "high", "crit": "critical"}
_USER_FIELDS = ("User", "TgtUser", "SrcUser")


def parse_event(raw: dict[str, Any]) -> Event:
    """Raw event -> Event. The id is the full channel plus record number."""
    fields = {k: v for k, v in raw.items() if k != "event_id"}
    return Event(
        event_id=f"{fields['Channel']}:{fields['RecordNumber']}",
        host=fields["Hostname"],
        timestamp=datetime.fromisoformat(fields["@timestamp"]),
        fields=fields,
    )


def parse_alert(record: dict[str, Any], event: Event, dataset: str | None = None) -> Alert:
    """Hayabusa detection + the raw event it fired on -> Alert, tagged with its dataset.

    Raises ValueError if the record does not belong to the event or its level is unknown.
    """
    raw = event.fields
    if (record["Computer"], record["RecordID"], record["EventID"]) != (
            raw["Hostname"], raw["RecordNumber"], raw["EventID"]):
        raise ValueError(f"record {record['RuleTitle']!r} does not match event {event.event_id}")
    if record["Level"] not in LEVELS:
        raise ValueError(f"unknown Hayabusa level {record['Level']!r}")

    return Alert(
        alert_id=hashlib.sha1(f"{record['RuleID']}|{event.event_id}".encode()).hexdigest()[:16],
        rule_title=record["RuleTitle"],
        rule_level=LEVELS[record["Level"]],
        mitre_tags=record.get("MitreTags") or [],
        host=record["Computer"],
        user=_pick_user(record, raw),
        timestamp=datetime.strptime(record["Timestamp"], "%Y-%m-%d %H:%M:%S.%f %z"),
        event_ids=[event.event_id],
        dataset=dataset,
    )


def _pick_user(record: dict[str, Any], raw: dict[str, Any]) -> str | None:
    for field in _USER_FIELDS:
        value = record["Details"].get(field)
        if value and value != "n/a":
            return value
    if raw.get("AccountName"):
        domain = raw.get("Domain")
        return f"{domain}\\{raw['AccountName']}" if domain else raw["AccountName"]
    return None
