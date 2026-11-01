"""Try-it sandbox: a visitor's public scenario or declared-public upload becomes a case.

    file (.evtx or JSON lines) -> events -> Hayabusa detections -> case-scoped alerts
    -> context + score for every alert -> queued by score -> the normal triage worker

Only the highest-scoring alerts of a case get an LLM verdict (free-tier budget); the rest
escalate as "AI not run". Cases expire after CASE_TTL and are deleted with their events.
"""

import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
from evtx import PyEvtxParser

from triage.domain import Event
from triage.pipeline.context import build_bundle
from triage.pipeline.enrich import enrich
from triage.pipeline.parse import parse_alert, parse_event
from triage.pipeline.score import score
from triage.services import workers
from triage.store import queue, repositories as repo
from triage.store.db import connect
from triage.store.event_source import PostgresEventSource

log = logging.getLogger("triage.sandbox")

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 50_000
MAX_ALERTS = 150          # each alert's evidence bundle is stored; the free Neon tier is small
PER_CASE_LLM = 5
DAILY_LLM_CAP = 30
CASE_TTL = timedelta(hours=24)
CASES_PER_HOUR = 3
CASES = "cases"                     # queue stream of cases waiting to be processed
UPLOADS = Path(tempfile.gettempdir()) / "probative-uploads"
_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_REQUIRED = ("Channel", "RecordNumber", "Hostname", "EventID", "@timestamp")
_OTRF = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"


class SandboxError(Exception):
    """A visitor-facing reason a case cannot be processed."""


@dataclass(frozen=True)
class Scenario:
    title: str
    blurb: str
    url: str


SCENARIOS = {
    "empire_launcher_vbs": Scenario(
        "Empire agent launched from a VBScript",
        "A VBScript launcher starts an Empire PowerShell agent that calls back to its server.",
        _OTRF + "execution/host/empire_launcher_vbs.zip"),
    "empire_shell_net_localgroup_administrators": Scenario(
        "Attacker lists the local administrators",
        "Through an Empire shell, the attacker runs net localgroup administrators to find accounts worth taking.",
        _OTRF + "discovery/host/empire_shell_net_localgroup_administrators.zip"),
}


# --- ids and hashing ----------------------------------------------------------

def new_case_id() -> str:
    return secrets.token_urlsafe(18)


def case_event_id(case_id: str, event_id: str) -> str:
    return f"{case_id}/{event_id}"


def client_address(headers: dict[str, str], peer: str | None) -> tuple[str, str]:
    """The visitor's address and where it came from. On Render, Cloudflare sits in front and sets
    CF-Connecting-IP, which a visitor cannot forge; the direct peer is only a proxy there."""
    cf = (headers.get("cf-connecting-ip") or "").strip()
    if cf:
        return cf, "cf-connecting-ip"
    forwarded = (headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded, "x-forwarded-for"
    return peer or "unknown", "peer"


def client_hash(address: str) -> str:
    """Rate limiting needs to recognise a client, not to know its address."""
    return hashlib.sha256(f"probative-ai:{address}".encode()).hexdigest()[:24]


def scenario(key: str) -> Scenario:
    if key not in SCENARIOS:
        raise SandboxError("unknown scenario")
    return SCENARIOS[key]


# --- reading files ----------------------------------------------------------

def sniff_format(head: bytes) -> str | None:
    if head.startswith(b"ElfFile\x00"):
        return "evtx"
    if head.lstrip()[:1] == b"{":
        return "json"
    return None


def evtx_record_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """One record from the evtx package -> the flat event shape the pipeline reads (as in OTRF)."""
    event = record["Event"]
    system = event["System"]
    event_id = system["EventID"]
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    raw: dict[str, Any] = {
        "Channel": system.get("Channel"),
        "Hostname": system.get("Computer"),
        "EventID": int(event_id),
        "RecordNumber": int(system["EventRecordID"]),
        "@timestamp": system["TimeCreated"]["#attributes"]["SystemTime"],
        "SourceName": (system.get("Provider") or {}).get("#attributes", {}).get("Name"),
    }
    execution = (system.get("Execution") or {}).get("#attributes") or {}
    if "ProcessID" in execution:
        raw["ExecutionProcessID"] = execution["ProcessID"]
    for key, value in (event.get("EventData") or {}).items():
        if key == "#attributes":
            continue
        key = "ProcessId" if key == "ProcessID" else key   # Security spells it ProcessID; the pipeline reads ProcessId
        raw[key] = value if isinstance(value, (str, int, float, bool)) or value is None else json.dumps(value)
    return raw


def read_evtx_events(path: Path) -> list[dict[str, Any]]:
    try:
        return [evtx_record_to_raw(json.loads(r["data"])) for r in PyEvtxParser(str(path)).records_json()]
    except (KeyError, TypeError, ValueError, RuntimeError) as e:
        raise SandboxError(f"could not read this .evtx file ({type(e).__name__})") from e


def read_json_events(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise SandboxError(f"line {n} is not JSON") from e
            missing = [k for k in _REQUIRED if k not in row]
            if missing:
                raise SandboxError(f"line {n} lacks {', '.join(missing)}: JSON uploads must be OTRF/NXLog-style "
                                   "Windows events (or upload the .evtx file instead)")
            events.append(row)
    return events


# --- Hayabusa ---------------------------------------------------------------

EXTRA_PROVEN = Path("config") / "hayabusa_extra_proven_rules.txt"


def read_rule_ids(path: Path) -> list[str]:
    """Rule ids, one per line; '#' starts a comment."""
    ids = []
    for line in path.read_text(encoding="utf-8").splitlines():
        rule_id = line.split("#", 1)[0].strip()
        if rule_id:
            ids.append(rule_id)
    return ids


def ensure_proven(proven: Path, extra: Path = EXTRA_PROVEN) -> None:
    """Add our extra rule ids to Hayabusa's proven list (used by -P). Idempotent."""
    have = set(read_rule_ids(proven))
    missing = [r for r in read_rule_ids(extra) if r not in have]
    if missing:
        text = proven.read_text(encoding="utf-8")
        proven.write_text(text + ("" if text.endswith("\n") else "\n") + "\n".join(missing) + "\n", encoding="utf-8")


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def engine_reason(output: str) -> str:
    """The last non-blank line of Hayabusa's output, colour codes stripped, for the visitor."""
    lines = [line.strip() for line in _ANSI.sub("", output).splitlines() if line.strip()]
    return lines[-1][:160] if lines else "no output"


def default_hayabusa() -> Path | None:
    candidates = [os.environ.get("HAYABUSA_PATH", ""), "tools/hayabusa/hayabusa-4.3.1-win-x64.exe",
                  "tools/hayabusa-linux/hayabusa-4.3.1-lin-x64-musl"]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c).resolve()
    return None


def run_hayabusa(path: Path, fmt: str, binary: Path | None = None, timeout: int = 240) -> list[dict]:
    """Sigma detections for one file. Runs from the binary's folder so it finds its rules."""
    binary = binary or default_hayabusa()
    if binary is None:
        raise SandboxError("the detection engine is not installed on this server")
    proven = binary.parent / "rules" / "config" / "proven_rules.txt"
    if proven.is_file():
        ensure_proven(proven)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "detections.jsonl"
        cmd = [str(binary), "dfir-timeline", "-f", str(path.resolve()), "-w", "-q", "-K", "-U",
               "-t", "jsonl", "-p", "verbose", "-m", "low", "-o", str(out), "-C",
               # Proven rules on one thread: peak memory 583 MB -> 193 MB, inside the free 512 MB instance.
               "-P", "--threads", "1"]
        if fmt == "json":
            cmd.insert(4, "-J")
        try:
            subprocess.run(cmd, cwd=binary.parent, check=True, timeout=timeout, capture_output=True,
                           text=True, errors="replace")
        except subprocess.TimeoutExpired as e:
            raise SandboxError("detection took too long for the sandbox; try a smaller file") from e
        except subprocess.CalledProcessError as e:
            output = f"{e.stdout or ''}\n{e.stderr or ''}"
            log.error("hayabusa exited %s: %s", e.returncode, output[-2000:])
            raise SandboxError(f"the detection engine could not read this file ({engine_reason(output)})") from e
        if not out.exists():
            return []
        with out.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]


# --- scenarios --------------------------------------------------------------

def fetch_scenario(key: str, dest: Path) -> Path:
    """Download an allow-listed OTRF scenario and extract its JSON file into dest."""
    url = scenario(key).url
    request = urllib.request.Request(url, headers={"User-Agent": "probative-ai"})
    archive = dest / f"{key}.zip"
    with urllib.request.urlopen(request, timeout=60) as response, archive.open("wb") as f:
        shutil.copyfileobj(response, f, length=1 << 20)
    with zipfile.ZipFile(archive) as z:
        members = [m for m in z.infolist() if m.filename.endswith(".json") and not m.is_dir()]
        if len(members) != 1 or members[0].file_size > 20 * MAX_UPLOAD_BYTES:
            raise SandboxError("this scenario's archive is not in the expected shape")
        target = dest / f"{key}.json"
        with z.open(members[0]) as src, target.open("wb") as out:
            shutil.copyfileobj(src, out)
    archive.unlink()
    return target


# --- cases ------------------------------------------------------------------

def build_case(conn: psycopg.Connection, case_id: str, raw_events: list[dict], detections: list[dict]) -> None:
    """Store the case's events and alerts, score every alert, and queue them highest score first."""
    if len(raw_events) > MAX_EVENTS:
        raise SandboxError(f"{len(raw_events):,} events is more than the sandbox's {MAX_EVENTS:,}")
    events: list[Event] = []
    by_key: dict[tuple, Event] = {}
    for raw in raw_events:
        raw.pop("Message", None)   # prose copy of the other fields; never read, doubles memory and storage
        e = parse_event(raw)
        e = e.model_copy(update={"event_id": case_event_id(case_id, e.event_id)})
        events.append(e)
        by_key[(e.host, e.fields["RecordNumber"], e.fields["EventID"])] = e
    pairs = []
    for det in detections:
        if det.get("Level") == "info":
            continue
        trigger = by_key.get((det["Computer"], det["RecordID"], det["EventID"]))
        if trigger is None:
            continue
        alert = parse_alert(det, trigger, dataset="public")
        pairs.append((alert.model_copy(update={"alert_id": f"{case_id}-{alert.alert_id}"}), trigger))
    note = ""
    if len(pairs) > MAX_ALERTS:   # keep the most severe, earliest first; say what was set aside
        pairs.sort(key=lambda p: (-_SEVERITY.get(p[0].rule_level, 0), p[0].timestamp, p[0].alert_id))
        note = f"triaged the {MAX_ALERTS} most severe of {len(pairs)} alerts; the rest were set aside"
        pairs = pairs[:MAX_ALERTS]

    repo.upsert_events(conn, events, case_id=case_id)
    for alert, trigger in pairs:
        repo.upsert_alert(conn, alert, trigger.event_id, case_id=case_id)
    source = PostgresEventSource(conn, case_id)
    for alert, trigger in pairs:
        bundle = enrich(build_bundle(alert, trigger, source, repo.prior_alerts(conn, alert)), workers.NoIntel())
        evidence = score(bundle)
        queue.enqueue(conn, workers.ENRICHED, alert.alert_id,
                      {"bundle": bundle.model_dump(mode="json"), "score": evidence.model_dump(mode="json")},
                      priority=int(evidence.total * 10))
    repo.update_case(conn, case_id, status="ready", n_events=len(events), n_alerts=len(pairs), detail=note)


def process_case(conn: psycopg.Connection, case_id: str, path: Path, fmt: str) -> None:
    """Read, detect and build one case. Any failure is recorded on the case for the visitor."""
    repo.update_case(conn, case_id, status="processing")
    try:
        detections = run_hayabusa(path, fmt)   # first, so its memory peak never overlaps the events'
        raw = read_evtx_events(path) if fmt == "evtx" else read_json_events(path)
        build_case(conn, case_id, raw, detections)
    except SandboxError as e:
        repo.update_case(conn, case_id, status="failed", detail=str(e))
    except Exception:   # noqa: BLE001 - logged and shown as a failed case; never a verdict
        log.exception("case %s failed", case_id)
        repo.update_case(conn, case_id, status="failed", detail="unexpected error while processing this file")
    finally:
        path.unlink(missing_ok=True)


def budget_gate(conn: psycopg.Connection, case_id: str | None, per_case: int = PER_CASE_LLM) -> str | None:
    """Why this alert must not reach the LLM, or None. Demo alerts (no case) are never gated."""
    if case_id is None:
        return None
    if repo.llm_calls_today(conn) >= DAILY_LLM_CAP:
        return "the site's daily AI budget is used up; AI verdicts are paused until tomorrow (UTC)"
    if not repo.take_llm_slot(conn, case_id, per_case):
        return f"only the {per_case} highest-scoring alerts of a case get an AI verdict"
    return None


def sweep_expired(conn: psycopg.Connection) -> int:
    expired = repo.expired_cases(conn)
    for case_id in expired:
        repo.delete_case(conn, case_id)
    return len(expired)


def enqueue_upload(conn: psycopg.Connection, case_id: str, path: Path, fmt: str) -> None:
    queue.enqueue(conn, CASES, case_id, {"path": str(path), "format": fmt})


def enqueue_scenario(conn: psycopg.Connection, case_id: str, key: str) -> None:
    scenario(key)
    queue.enqueue(conn, CASES, case_id, {"scenario": key, "format": "json"})


def run_case_message(conn: psycopg.Connection, case_id: str, payload: dict[str, Any], attempts: int = 1) -> None:
    """A queued case: download its scenario if it has one, then process the file.

    A second attempt means the first one died with the process (most likely out of memory),
    so the case is failed rather than retried into the same crash.
    """
    if attempts > 1:
        repo.update_case(conn, case_id, status="failed",
                         detail="the file was too large for the sandbox's free server; try a smaller one")
        if "path" in payload:
            Path(payload["path"]).unlink(missing_ok=True)
        return
    if "scenario" in payload:
        UPLOADS.mkdir(parents=True, exist_ok=True)
        repo.update_case(conn, case_id, status="processing", detail="downloading the scenario")
        try:
            path = fetch_scenario(payload["scenario"], Path(tempfile.mkdtemp(dir=UPLOADS)))
        except (SandboxError, OSError, zipfile.BadZipFile) as e:
            repo.update_case(conn, case_id, status="failed", detail=f"could not download the scenario ({e})")
            return
    else:
        path = Path(payload["path"])
    process_case(conn, case_id, path, payload["format"])


def start_case_worker(url: str, stop: threading.Event, poll_seconds: float) -> threading.Thread:
    """One thread processes queued cases, one at a time."""
    def loop():
        with connect(url) as conn:
            while not stop.is_set():
                batch = queue.claim(conn, CASES, lease=timedelta(minutes=15))
                for msg in batch:
                    run_case_message(conn, msg.alert_id, msg.payload, msg.attempts)
                    queue.ack(conn, msg.id)
                if not batch:
                    stop.wait(poll_seconds)

    thread = threading.Thread(target=loop, name="cases", daemon=True)
    thread.start()
    return thread
