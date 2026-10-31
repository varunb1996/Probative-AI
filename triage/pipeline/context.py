"""Step 3, gather context: fixed, process-scoped queries. Never a host time window.

The bundle holds the triggering event, the acting process's own events, its parent's and
children's, and its network events; plus earlier alerts on the host. A prior verdict enters
only if a human confirmed it (compounding-error rule); otherwise only the alert facts do.
"""

from triage.domain import Alert, Event, EventSource, EvidenceBundle, PriorAlert
from triage.pipeline.process import actor_process


def build_bundle(alert: Alert, trigger: Event, source: EventSource,
                 prior_alerts: list[PriorAlert]) -> EvidenceBundle:
    events = [trigger]
    actor = actor_process(trigger)
    if actor is not None:
        events += source.process_events(actor)
        events += source.parent_events(actor)
        events += source.child_events(actor)
        events += source.network_events(actor)

    return EvidenceBundle(
        alert=alert,
        events=_unique(events),
        prior_alerts=[_admit(p) for p in prior_alerts
                      if p.alert.host == alert.host and p.alert.timestamp < alert.timestamp
                      and p.alert.alert_id != alert.alert_id],
    )


def _admit(prior: PriorAlert) -> PriorAlert:
    return prior if prior.human_confirmed else prior.model_copy(update={"verdict": None})


def _unique(events: list[Event]) -> list[Event]:
    seen: set[str] = set()
    out = []
    for e in events:
        if e.event_id not in seen:
            seen.add(e.event_id)
            out.append(e)
    return out
