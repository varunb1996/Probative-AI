"""Step 2, known noise: allowlist rules and dedup.

A duplicate is not closed on its own: it maps to the first alert of its group and
takes that alert's disposition, so a burst from an attacker process stays escalated.
"""

from datetime import timedelta
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from triage.domain import Alert, Event
from triage.pipeline.process import actor_process


class AllowRule(BaseModel):
    """Every condition given must match (case-insensitive). `reason` is mandatory documentation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    reason: str
    rule_title: str | None = None
    host: str | None = None
    fields: dict[str, str] = {}

    @model_validator(mode="after")
    def _has_a_condition(self) -> "AllowRule":
        if not (self.rule_title or self.host or self.fields):
            raise ValueError(f"allow rule {self.name!r} has no conditions and would match everything")
        return self


def load_allowlist(path: Path) -> list[AllowRule]:
    rows = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [AllowRule(**row) for row in rows]


def is_allowlisted(alert: Alert, trigger: Event, rules: list[AllowRule]) -> AllowRule | None:
    """The first rule matching this alert and its triggering event, or None."""
    for rule in rules:
        if rule.rule_title and not _eq(rule.rule_title, alert.rule_title):
            continue
        if rule.host and not _eq(rule.host, alert.host):
            continue
        if all(_eq(want, trigger.fields.get(name)) for name, want in rule.fields.items()):
            return rule
    return None


def dedup(alerts: list[tuple[Alert, Event]], window: timedelta) -> dict[str, str]:
    """Map each duplicate alert_id to the alert_id heading its group.

    Same group: same rule title, host and acting process, within `window` of the group's head.
    Alerts with no identifiable process are never grouped.
    """
    heads: dict[tuple, Alert] = {}
    duplicates: dict[str, str] = {}
    for alert, trigger in sorted(alerts, key=lambda pair: (pair[0].timestamp, pair[0].alert_id)):
        actor = actor_process(trigger)
        if actor is None:
            continue
        key = (alert.rule_title, alert.host, (actor.guid or "").lower() or actor.pid)
        head = heads.get(key)
        if head is not None and alert.timestamp - head.timestamp <= window:
            duplicates[alert.alert_id] = head.alert_id
        else:
            heads[key] = alert
    return duplicates


def _eq(want: str, got: object) -> bool:
    return got is not None and str(got).lower() == want.lower()
