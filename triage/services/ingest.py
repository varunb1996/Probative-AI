"""Load a scenario into Postgres and queue its alerts.

    python -m triage.services.ingest [--data data] [--only ID ...]

Reads data/events.jsonl and data/alerts_raw.jsonl (written by scripts/null_test/detect.py),
keeps low+ detections, tags them dataset=public (OTRF), and enqueues each on the raw stream.
"""

import argparse
import json
import os
from pathlib import Path

import psycopg

from triage.domain import Alert, Event
from triage.pipeline.parse import parse_alert, parse_event
from triage.services.config import load_dotenv, load_policy
from triage.store import queue, repositories as repo
from triage.store.db import apply_schema, connect

RAW = "raw"
DATASET = "public"


def read_scenario(data: Path) -> tuple[list[Event], list[tuple[Alert, Event]]]:
    with (data / "events.jsonl").open(encoding="utf-8") as f:
        events = [parse_event(json.loads(line)) for line in f if line.strip()]
    by_key = {(e.host, e.fields["RecordNumber"], e.fields["EventID"]): e for e in events}
    pairs = []
    with (data / "alerts_raw.jsonl").open(encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record["Level"] == "info":
                continue
            trigger = by_key[(record["Computer"], record["RecordID"], record["EventID"])]
            pairs.append((parse_alert(record, trigger, dataset=DATASET), trigger))
    return events, pairs


def ingest(conn: psycopg.Connection, events: list[Event], pairs: list[tuple[Alert, Event]],
           critical_hosts: frozenset[str] = frozenset()) -> int:
    """Store events and alerts, enqueue alerts (critical hosts first). Returns the number queued."""
    apply_schema(conn)
    repo.upsert_events(conn, events)
    critical = {h.lower() for h in critical_hosts}
    queued = 0
    for alert, trigger in pairs:
        repo.upsert_alert(conn, alert, trigger.event_id)
        queued += queue.enqueue(conn, RAW, alert.alert_id, {},
                                priority=1 if alert.host.lower() in critical else 0)
    return queued


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--data", type=Path, default=Path("data"))
    p.add_argument("--only", nargs="*", help="alert_ids to queue (default: all low+ alerts)")
    args = p.parse_args()
    load_dotenv()
    events, pairs = read_scenario(args.data)
    if args.only:
        pairs = [(a, t) for a, t in pairs if a.alert_id in set(args.only)]
    with connect(os.environ["DATABASE_URL"]) as conn:
        queued = ingest(conn, events, pairs, load_policy(os.environ).critical_hosts)
    print(f"events: {len(events)}  alerts: {len(pairs)}  newly queued: {queued}")


if __name__ == "__main__":
    main()
