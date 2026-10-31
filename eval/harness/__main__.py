"""python -m eval.harness baseline [--allowlist FILE] [--dedup-minutes N]

Scores the deterministic baseline (evidence score) and the severity-only baseline over the
low+ alerts, and reports them on the labelled subset. Reads labels read-only.
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

from eval.harness.jsonl_source import JsonlEventSource, NoIntel
from triage.pipeline.context import build_bundle
from triage.pipeline.enrich import enrich
from triage.pipeline.noise import dedup, is_allowlisted, load_allowlist
from triage.pipeline.parse import parse_alert
from triage.pipeline.score import CLOSE_BELOW, score

LABELS = Path("eval") / "labels" / "labels.jsonl"
DATA = Path("data")


def _read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def baseline(allowlist: Path | None, dedup_window: timedelta) -> None:
    source = JsonlEventSource(DATA / "events.jsonl")
    by_key = {(e.host, e.fields["RecordNumber"], e.fields["EventID"]): e for e in source.events}
    rules = load_allowlist(allowlist) if allowlist else []

    pairs = []
    for record in _read_jsonl(DATA / "alerts_raw.jsonl"):
        if record["Level"] == "info":
            continue
        trigger = by_key[(record["Computer"], record["RecordID"], record["EventID"])]
        pairs.append((parse_alert(record, trigger), trigger))

    heads = dedup(pairs, dedup_window)
    rows = {}
    for alert, trigger in pairs:
        noise = is_allowlisted(alert, trigger, rules)
        bundle = enrich(build_bundle(alert, trigger, source, prior_alerts=[]), NoIntel())
        result = score(bundle)
        rows[alert.alert_id] = {
            "alert": alert, "score": result, "noise": noise.name if noise else None,
            "closed": bool(noise) or result.total < CLOSE_BELOW,
            "severity_closed": alert.rule_level not in ("high", "critical"),
        }
    for dup, head in heads.items():  # a duplicate keeps its own score but takes its head's disposition
        rows[dup].update(closed=rows[head]["closed"], head=head)

    labels = {row["alert_id"]: row["label"] for row in _read_jsonl(LABELS)}
    missing = sorted(set(labels) - set(rows))
    if missing:
        raise SystemExit(f"labelled alerts not produced by the pipeline: {missing}")

    _report(rows, labels, len(pairs), len(heads), len(rules), dedup_window)


def _metrics(rows, labels, closed_key):
    mal = [a for a, l in labels.items() if l == "malicious"]
    closed = [a for a in labels if rows[a][closed_key]]
    caught = sum(1 for a in mal if not rows[a][closed_key])
    return {
        "recall": f"{caught}/{len(mal)} = {caught / len(mal):.0%}",
        "close": f"{len(closed)}/{len(labels)} = {len(closed) / len(labels):.0%}",
        "mal_closed": sum(1 for a in closed if labels[a] == "malicious"),
        "all_close": f"{sum(r[closed_key] for r in rows.values())}/{len(rows)}",
    }


def _report(rows, labels, n_alerts, n_dups, n_rules, window):
    print(f"Alerts (low and above): {n_alerts}; dedup duplicates: {n_dups} "
          f"(window {window}); allowlist rules: {n_rules}; intel: none synced; "
          f"CLOSE_BELOW = {CLOSE_BELOW}\n")
    print("| Method | Recall on malicious | Close rate (labelled) | Malicious among closes "
          "| Close rate (all low+) |")
    print("| --- | --- | --- | --- | --- |")
    for name, key in (("Evidence score", "closed"), ("Severity only", "severity_closed")):
        m = _metrics(rows, labels, key)
        print(f"| {name} | {m['recall']} | {m['close']} | {m['mal_closed']} | {m['all_close']} |")

    print("\nPer rule type (evidence score, labelled):\n")
    print("| Rule | Labelled | Malicious | Closed | Malicious closed |")
    print("| --- | --- | --- | --- | --- |")
    per = defaultdict(Counter)
    for a, label in labels.items():
        c = per[rows[a]["alert"].rule_title]
        c["n"] += 1
        c["mal"] += label == "malicious"
        c["closed"] += rows[a]["closed"]
        c["mal_closed"] += rows[a]["closed"] and label == "malicious"
    for title, c in sorted(per.items(), key=lambda kv: -kv[1]["n"]):
        print(f"| {title} | {c['n']} | {c['mal']} | {c['closed']} | {c['mal_closed']} |")

    print("\nLabelled alerts:\n")
    print("| alert_id | label | score | closed | signals |")
    print("| --- | --- | --- | --- | --- |")
    for a, label in sorted(labels.items(), key=lambda kv: (kv[1], -rows[kv[0]]["score"].total)):
        r = rows[a]
        via = f" (dup of {r['head']})" if "head" in r else ""
        print(f"| {a} | {label} | {r['score'].total:g} | {'yes' if r['closed'] else 'no'}{via} "
              f"| {', '.join(r['score'].contributions)} |")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)
    b = sub.add_parser("baseline", help="score the deterministic baselines over the labels")
    b.add_argument("--allowlist", type=Path)
    b.add_argument("--dedup-minutes", type=float, default=5)
    args = p.parse_args()
    baseline(args.allowlist, timedelta(minutes=args.dedup_minutes))


if __name__ == "__main__":
    main()
