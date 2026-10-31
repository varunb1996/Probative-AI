"""Phase 0a null test: run Hayabusa over one OTRF scenario and export alerts and events.

Throwaway script, not part of the triage package. No model calls.

    python scripts/null_test/detect.py data/raw/<scenario>.json

Writes data/alerts_raw.jsonl (Hayabusa output), data/events.jsonl (every raw event plus an
event_id) and data/alerts.jsonl (one normalised alert per detection), then prints counts.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

DEFAULT_HAYABUSA = Path("tools/hayabusa/hayabusa-4.3.1-win-x64.exe")
LEVELS = {"info": "info", "low": "low", "med": "medium", "high": "high", "crit": "critical"}
LEVEL_ORDER = ["critical", "high", "medium", "low", "info"]


def run_hayabusa(hayabusa: Path, dataset: Path, out: Path) -> None:
    # Command from docs/design.md, plus -p verbose so the output carries MitreTags.
    cmd = [str(hayabusa), "dfir-timeline", "-f", str(dataset), "-J", "-w", "-q", "-K", "-U",
           "-t", "jsonl", "-p", "verbose", "-o", str(out), "-C"]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def event_key(host: str, record: int, event_code: int) -> tuple:
    return (host, record, event_code)


def build_events(raw: list[dict]) -> tuple[list[dict], dict]:
    """Give every raw event an event_id (full channel + record number) and index it."""
    events, index = [], {}
    for e in raw:
        event_id = f"{e['Channel']}:{e['RecordNumber']}"
        events.append({"event_id": event_id, **e})
        key = event_key(e["Hostname"], e["RecordNumber"], e["EventID"])
        if key in index:
            sys.exit(f"duplicate raw event key {key}; cannot map alerts to events")
        index[key] = event_id
    return events, index


def pick_user(det: dict, raw_event: dict) -> str | None:
    for field in ("User", "TgtUser", "SrcUser"):
        value = det["Details"].get(field)
        if value and value != "n/a":
            return value
    if raw_event.get("AccountName"):
        domain = raw_event.get("Domain")
        return f"{domain}\\{raw_event['AccountName']}" if domain else raw_event["AccountName"]
    return None


def build_alert(det: dict, event_id: str, raw_event: dict) -> dict:
    ts = datetime.strptime(det["Timestamp"], "%Y-%m-%d %H:%M:%S.%f %z")
    return {
        "alert_id": hashlib.sha1(f"{det['RuleID']}|{event_id}".encode()).hexdigest()[:16],
        "rule_title": det["RuleTitle"],
        "rule_level": LEVELS[det["Level"]],
        "mitre_tags": det.get("MitreTags") or [],
        "host": det["Computer"],
        "user": pick_user(det, raw_event),
        "timestamp": ts.isoformat(),
        "event_ids": [event_id],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("dataset", type=Path, help="OTRF JSON-lines file")
    p.add_argument("--hayabusa", type=Path, default=DEFAULT_HAYABUSA)
    p.add_argument("--out", type=Path, default=Path("data"))
    args = p.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    raw_out = args.out / "alerts_raw.jsonl"
    run_hayabusa(args.hayabusa, args.dataset, raw_out)

    raw = read_jsonl(args.dataset)
    events, index = build_events(raw)
    by_id = {e["event_id"]: e for e in events}

    alerts = []
    for det in read_jsonl(raw_out):
        key = event_key(det["Computer"], det["RecordID"], det["EventID"])
        if key not in index:
            sys.exit(f"detection {det['RuleTitle']} at {key} has no matching raw event")
        event_id = index[key]
        alerts.append(build_alert(det, event_id, by_id[event_id]))

    if len({a["alert_id"] for a in alerts}) != len(alerts):
        sys.exit("alert_id collision")

    write_jsonl(args.out / "events.jsonl", events)
    write_jsonl(args.out / "alerts.jsonl", alerts)

    print(f"events: {len(events)}  alerts: {len(alerts)}\n")
    levels = Counter(a["rule_level"] for a in alerts)
    print("per level:")
    for level in LEVEL_ORDER:
        print(f"  {level:<9}{levels.get(level, 0):>6}")
    print("\nper rule:")
    per_rule = Counter((a["rule_level"], a["rule_title"]) for a in alerts)
    for (level, title), n in sorted(per_rule.items(), key=lambda kv: (LEVEL_ORDER.index(kv[0][0]), -kv[1])):
        print(f"  {n:>6}  {level:<8}  {title}")


if __name__ == "__main__":
    main()
