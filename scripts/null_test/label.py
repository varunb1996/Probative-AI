"""Phase 0b labelling tool. The human labels; this script only shows evidence and records answers.

    python scripts/null_test/label.py sample     # draw the 30-alert sample into eval/sample.txt
    python scripts/null_test/label.py label      # label the sample into eval/labels/labels.jsonl
    python scripts/null_test/label.py spotcheck  # label 6 unsampled alerts from scratch into eval/labels/spotcheck.jsonl

Sample split and attacker facts come from docs/labelling-rubric.md. Throwaway script, no model calls.
"""

import argparse
import json
import random
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DATA = Path("data")
SAMPLE = Path("eval/sample.txt")
LABELS = Path("eval/labels/labels.jsonl")
SPOTCHECK = Path("eval/labels/spotcheck.jsonl")
SEED = 42
SPOTCHECK_SEED = 7
NEIGHBOURS = 20

# From docs/labelling-rubric.md, "What the scenario tells me". Used only to highlight, never to label.
ATTACKER_HOST = "WORKSTATION5"
ATTACKER_PID = 1648
ATTACKER_GUID = "{297bc33e-65d0-5f2d-8207-000000000400}"


def _short_host(alert: dict) -> str:
    return alert["host"].split(".")[0]


# (group, predicate, count); count None means take every match.
GROUPS = [
    ("medium", lambda a: a["rule_level"] == "medium", None),
    ("discovery", lambda a: a["rule_title"] == "Local Accounts Discovery", None),
    ("network", lambda a: a["rule_title"] == "Network Connection Initiated By PowerShell Process", 5),
    ("proc_access_ws5", lambda a: a["rule_title"] == "Proc Access" and _short_host(a) == "WORKSTATION5", 8),
    ("proc_access_dc", lambda a: a["rule_title"] == "Proc Access" and _short_host(a) == "MORDORDC", 3),
    ("proc_access_ws6", lambda a: a["rule_title"] == "Proc Access" and _short_host(a) == "WORKSTATION6", 3),
]

# Spot check: 6 alerts outside the sample. The sample already holds every medium and
# discovery alert, so only these groups have alerts left; weighted toward Proc Access.
SPOTCHECK_SPLIT = {"network": 1, "proc_access_ws5": 3, "proc_access_dc": 1, "proc_access_ws6": 1}


# --- pure helpers (tested) --------------------------------------------------

def pid_text(value) -> str:
    """Show a PID as decimal and hex, since Sysmon logs decimal and Security logs hex."""
    if value is None:
        return "-"
    if isinstance(value, int):
        n = value
    else:
        s = str(value).strip()
        if s.lower().startswith("0x"):
            n = int(s, 16)
        elif s.isdigit():
            n = int(s)
        else:
            return s
    return f"{n} ({hex(n)})"


def draw_sample(alerts: list[dict], seed: int = SEED) -> list[tuple[str, str]]:
    """Pick the rubric's sample: list of (alert_id, group). Same alerts and seed, same picks."""
    rng = random.Random(seed)
    ordered = sorted(alerts, key=lambda a: a["alert_id"])
    sample = []
    for group, matches, count in GROUPS:
        candidates = [a for a in ordered if matches(a)]
        picks = candidates if count is None or count >= len(candidates) else rng.sample(candidates, count)
        sample += [(a["alert_id"], group) for a in picks]
    return sample


def draw_spotcheck(alerts: list[dict], exclude: set[str], seed: int = SPOTCHECK_SEED) -> list[tuple[str, str]]:
    """Pick the spot-check alerts, never one in `exclude` (the labelled sample)."""
    rng = random.Random(seed)
    ordered = sorted((a for a in alerts if a["alert_id"] not in exclude), key=lambda a: a["alert_id"])
    picks = []
    for group, matches, _ in GROUPS:
        count = SPOTCHECK_SPLIT.get(group, 0)
        if not count:
            continue
        candidates = [a for a in ordered if matches(a)]
        chosen = candidates if count >= len(candidates) else rng.sample(candidates, count)
        picks += [(a["alert_id"], group) for a in chosen]
    return picks


def write_sample(path: Path, sample: list[tuple[str, str]], seed: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# seed {seed}; split from docs/labelling-rubric.md", "# alert_id\tgroup"]
    lines += [f"{alert_id}\t{group}" for alert_id, group in sample]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_sample(path: Path) -> list[tuple[str, str]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            alert_id, group = line.split("\t")
            rows.append((alert_id, group))
    return rows


def index_by_host(events: list[dict]) -> dict[str, list[dict]]:
    index = defaultdict(list)
    for e in events:
        index[e["Hostname"]].append(e)
    for host_events in index.values():
        host_events.sort(key=lambda e: (e["@timestamp"], e["RecordNumber"]))
    return dict(index)


def window(host_events: list[dict], event_id: str, n: int = NEIGHBOURS):
    """Return (before, trigger, after): n neighbours, centred, topped up from the other side at an edge."""
    i = next(k for k, e in enumerate(host_events) if e["event_id"] == event_id)
    half = n // 2
    n_before, n_after = min(half, i), min(half, len(host_events) - 1 - i)
    if n_before < half:
        n_after = min(len(host_events) - 1 - i, n - n_before)
    if n_after < half:
        n_before = min(i, n - n_after)
    return host_events[i - n_before:i], host_events[i], host_events[i + 1:i + 1 + n_after]


def labelled_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open(encoding="utf-8") as f:
        return {json.loads(line)["alert_id"] for line in f if line.strip()}


def pending(sample_ids: list[str], done: set[str]) -> list[str]:
    return [i for i in sample_ids if i not in done]


def append_label(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def summarise(rows: list[dict], sample_ids: list[str]) -> str:
    """Progress line. Assisted labels have no seconds; averages use only timed rows."""
    wanted = set(sample_ids)
    rows = [r for r in rows if r["alert_id"] in wanted]
    timed = [r["seconds"] for r in rows if isinstance(r.get("seconds"), (int, float))]
    untimed = len(rows) - len(timed)
    if timed:
        timing = f"avg {sum(timed) / len(timed):.1f}s per label over {len(timed)} timed"
        if untimed:
            timing += f", {untimed} not recorded (assisted labels)"
    elif untimed:
        timing = "time per label: not recorded (assisted labels)"
    else:
        timing = "time per label: -"
    unsure = sum(1 for r in rows if r["rationale"].upper().startswith("UNSURE:"))
    return f"labelled {len(rows)}/{len(sample_ids)}  {timing}  unsure {unsure}"


# --- display ----------------------------------------------------------------

def _is_pid_field(key: str) -> bool:
    return "processid" in key.lower() and key != "ExecutionProcessID"


def _pid_values(e: dict) -> set[int]:
    out = set()
    for key, value in e.items():
        if _is_pid_field(key):
            text = pid_text(value)
            if text[:1].isdigit():
                out.add(int(text.split()[0]))
    return out


def attacker_mark(e: dict) -> str:
    if any(ATTACKER_GUID.lower() == str(v).lower() for k, v in e.items() if "guid" in k.lower()):
        return "  <<< attacker GUID"
    if e["Hostname"].split(".")[0] == ATTACKER_HOST and ATTACKER_PID in _pid_values(e):
        return "  <<< attacker PID"
    return ""


def summary(e: dict) -> str:
    image = e.get("Image") or e.get("SourceImage") or e.get("NewProcessName") or e.get("ProcessName") or e.get("Application")
    pid = next((e[k] for k in ("ProcessId", "SourceProcessId", "NewProcessId", "ProcessID") if k in e), None)
    parts = [e["@timestamp"][11:23], e["Channel"].split("/")[0].replace("Microsoft-Windows-", ""), str(e["EventID"])]
    if image:
        parts.append(f"{Path(str(image).replace(chr(92), '/')).name} pid {pid_text(pid)}")
    if e.get("TargetImage"):
        parts.append(f"-> {Path(e['TargetImage'].replace(chr(92), '/')).name} pid {pid_text(e.get('TargetProcessId'))}")
    dest = e.get("DestinationIp") or e.get("DestAddress")
    if dest:
        parts.append(f"-> {dest}:{e.get('DestinationPort') or e.get('DestPort')}")
    access = e.get("GrantedAccess") or e.get("AccessMask")
    if access:
        parts.append(f"access {access}")
    first = (e.get("Message") or "").splitlines()[0][:70] if e.get("Message") else ""
    return "  ".join(parts) + (f"  | {first}" if first else "") + attacker_mark(e)


KEY_FIELDS = ["Image", "ProcessName", "NewProcessName", "ProcessId", "NewProcessId", "ProcessGuid",
              "SourceImage", "SourceProcessId", "SourceProcessGUID", "TargetImage", "TargetProcessId",
              "TargetProcessGUID", "GrantedAccess", "ObjectName", "AccessMask", "ParentImage", "ParentProcessId",
              "CommandLine", "ParentCommandLine", "DestinationIp", "DestAddress", "DestinationPort", "DestPort",
              "User", "SubjectUserName", "TargetUserName"]
MAX_VALUE = 150


def key_fields(e: dict) -> list[str]:
    """The fields that usually decide a label, one per line, for the recap above the prompt."""
    lines = []
    for key in KEY_FIELDS:
        if key in e and e[key] not in (None, "", "-"):
            value = pid_text(e[key]) if _is_pid_field(key) else " ".join(str(e[key]).split())
            if len(value) > MAX_VALUE:
                value = value[:MAX_VALUE] + "..."
            lines.append(f"{key:<20} {value}")
    return lines


def show_recap(alert: dict, trigger: dict) -> None:
    print(f"\n  --- {alert['rule_title']} on {alert['host'].split('.')[0]}: triggering event "
          f"{trigger['event_id']}{attacker_mark(trigger)}")
    for line in key_fields(trigger):
        print(f"    {line}")


def show_event(e: dict) -> None:
    for key in sorted(e):
        if key in ("Message", "tags", "@version", "Keywords"):
            continue
        value = pid_text(e[key]) if _is_pid_field(key) else " ".join(str(e[key]).split())
        print(f"    {key:<22} {value}")
    if e.get("Message"):
        print("    Message:")
        for line in e["Message"].splitlines():
            print(f"      {line}")


def show_alert(n: int, total: int, alert: dict, group: str, before, trigger, after) -> None:
    print("\n" + "=" * 100)
    print(f"[{n}/{total}] {alert['rule_title']}  ({alert['rule_level']}, group {group})")
    print(f"  host {alert['host']}  user {alert['user']}  time {alert['timestamp']}")
    print(f"  mitre {', '.join(alert['mitre_tags']) or '-'}  alert_id {alert['alert_id']}")
    print(f"\n  Triggering event {trigger['event_id']}{attacker_mark(trigger)}")
    show_event(trigger)
    print(f"\n  {len(before) + len(after)} surrounding events on the same host:")
    for k, e in enumerate(before, 1):
        print(f"   {k:>2}  {summary(e)}")
    print(f"   >>  {summary(trigger)}")
    for k, e in enumerate(after, len(before) + 1):
        print(f"   {k:>2}  {summary(e)}")


def report(labels_path: Path, sample_ids: list[str]) -> None:
    rows = []
    if labels_path.exists():
        with labels_path.open(encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
    print("\n" + summarise(rows, sample_ids))


# --- commands ---------------------------------------------------------------

def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def cmd_sample(args) -> None:
    sample = draw_sample(read_jsonl(args.data / "alerts.jsonl"), seed=args.seed)
    write_sample(args.sample, sample, seed=args.seed)
    counts = defaultdict(int)
    for _, group in sample:
        counts[group] += 1
    print(f"wrote {len(sample)} alerts to {args.sample}")
    for group, *_ in GROUPS:
        print(f"  {group:<18}{counts[group]:>3}")


def ask(prompt: str, valid=None) -> str:
    while True:
        answer = input(prompt).strip()
        if answer and (valid is None or answer.lower() in valid):
            return answer


def cmd_label(args) -> None:
    run_labelling(args, read_sample(args.sample))


def cmd_spotcheck(args) -> None:
    sampled = {alert_id for alert_id, _ in read_sample(args.sample)}
    spot = draw_spotcheck(read_jsonl(args.data / "alerts.jsonl"), exclude=sampled)
    print(f"spot check: {len(spot)} alerts outside the sample, labelled from scratch")
    run_labelling(args, spot)


def run_labelling(args, sample: list[tuple[str, str]]) -> None:
    """Walk `sample`, show evidence, record answers. Reads labels only to skip done alert IDs."""
    groups = dict(sample)
    sample_ids = [alert_id for alert_id, _ in sample]
    alerts = {a["alert_id"]: a for a in read_jsonl(args.data / "alerts.jsonl")}
    events = read_jsonl(args.data / "events.jsonl")
    hosts = index_by_host(events)

    todo = pending(sample_ids, labelled_ids(args.labels))
    print(f"{len(sample_ids) - len(todo)} already labelled, {len(todo)} to go. Labels go to {args.labels}")
    for alert_id in todo:
        alert = alerts[alert_id]
        before, trigger, after = window(hosts[alert["host"]], alert["event_ids"][0])
        show_alert(sample_ids.index(alert_id) + 1, len(sample_ids), alert, groups[alert_id], before, trigger, after)
        started = time.monotonic()
        while True:
            show_recap(alert, trigger)
            choice = ask("\n  label [m]alicious / [b]enign, [?] full neighbour messages, [q]uit: ",
                         {"m", "b", "?", "q"}).lower()
            if choice == "?":
                for k, e in enumerate(before + [trigger] + after, 1):
                    print(f"\n   {k:>2} {e['event_id']}{attacker_mark(e)}\n      " +
                          (e.get("Message") or "").replace("\n", "\n      "))
                continue
            break
        if choice == "q":
            break
        rationale = ask("  rationale (one line, name the rubric step): ")
        append_label(args.labels, {
            "alert_id": alert_id,
            "label": "malicious" if choice == "m" else "benign",
            "rationale": rationale,
            "seconds": round(time.monotonic() - started, 1),
            "labelled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
    report(args.labels, sample_ids)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--data", type=Path, default=DATA)
    p.add_argument("--sample", type=Path, default=SAMPLE)
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sample", help="draw the sample into eval/sample.txt")
    s.add_argument("--seed", type=int, default=SEED)
    s.set_defaults(func=cmd_sample)
    lab = sub.add_parser("label", help="label the sample")
    lab.add_argument("--labels", type=Path, default=LABELS)
    lab.set_defaults(func=cmd_label)
    spot = sub.add_parser("spotcheck", help="label 6 unsampled alerts from scratch (human baseline)")
    spot.add_argument("--labels", type=Path, default=SPOTCHECK)
    spot.set_defaults(func=cmd_spotcheck)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
