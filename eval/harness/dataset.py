"""Loading the Phase 0 scenario and its labels. Labels are read, never written."""

import json
from pathlib import Path

from eval.harness.jsonl_source import JsonlEventSource
from triage.domain import Alert, Event
from triage.pipeline.parse import parse_alert

DATA = Path("data")
LABELS = Path("eval") / "labels" / "labels.jsonl"
SPOTCHECK = Path("eval") / "labels" / "spotcheck.jsonl"
# Phase 0 decision (docs/null-test-results.md): a tool display bug hid this alert's details.
EXCLUDED = {"985211e48cc2f591": "invalid measurement: triggering event details were hidden by a tool bug"}
DATASET = "public"   # OTRF Security-Datasets


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_pairs() -> tuple[JsonlEventSource, list[tuple[Alert, Event]]]:
    """Every low+ alert with its triggering event, tagged dataset=public."""
    source = JsonlEventSource(DATA / "events.jsonl")
    by_key = {(e.host, e.fields["RecordNumber"], e.fields["EventID"]): e for e in source.events}
    pairs = []
    for record in read_jsonl(DATA / "alerts_raw.jsonl"):
        if record["Level"] == "info":
            continue
        trigger = by_key[(record["Computer"], record["RecordID"], record["EventID"])]
        pairs.append((parse_alert(record, trigger, dataset=DATASET), trigger))
    return source, pairs


def load_labels(include_spotcheck: bool) -> dict[str, tuple[str, str]]:
    """alert_id -> (label, set name). Spot-check rows listed in EXCLUDED are left out."""
    labels = {row["alert_id"]: (row["label"], "assisted") for row in read_jsonl(LABELS)}
    if include_spotcheck:
        labels |= {row["alert_id"]: (row["label"], "spotcheck") for row in read_jsonl(SPOTCHECK)
                   if row["alert_id"] not in EXCLUDED}
    return labels
