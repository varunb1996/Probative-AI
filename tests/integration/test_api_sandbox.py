"""The sandbox over HTTP: try page, uploads, scenarios, limits, case pages. Workers are off."""

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from integration_support import FIXTURES, IDS, POLICY, golden_pairs, scripted

from triage.api.app import create_app
from triage.services import sandbox, workers
from triage.services.config import Settings
from triage.services.ingest import ingest
from triage.store import queue, repositories as repo

pytestmark = pytest.mark.integration
DECLARED = {"X-Declared-Public": "yes", "X-Filename": "events.json"}


def _jsonl() -> bytes:
    rows = [json.loads((FIXTURES / f"{a}.json").read_text(encoding="utf-8"))["event"] for a in IDS]
    return ("\n".join(json.dumps(r) for r in rows) + "\n").encode()


@pytest.fixture
def client(conn, test_url):
    app = create_app(Settings(database_url=test_url, api_token="t", run_workers=False, poll_seconds=5))
    with TestClient(app) as c:
        yield c


def test_try_page_offers_scenarios_and_warns_about_private_data(client):
    page = client.get("/try").text
    for s in sandbox.SCENARIOS.values():
        assert s.title in page
    assert "company" in page.lower() and "private" in page.lower()


def test_home_page_links_to_the_sandbox(client):
    assert "/try" in client.get("/").text


def test_upload_needs_the_declaration(client):
    r = client.post("/api/cases/upload", content=_jsonl(), headers={"X-Filename": "events.json"})
    assert r.status_code == 400


def test_upload_creates_a_queued_case(client, conn):
    r = client.post("/api/cases/upload", content=_jsonl(), headers=DECLARED)
    assert r.status_code == 202
    case_id = r.json()["case_id"]
    assert r.json()["url"] == f"/cases/{case_id}"
    case = repo.get_case(conn, case_id)
    assert (case["status"], case["source"], case["name"]) == ("queued", "upload", "events.json")
    [msg] = queue.claim(conn, sandbox.CASES)
    assert msg.alert_id == case_id and msg.payload["format"] == "json"
    assert msg.payload["path"].endswith(".json")     # Hayabusa selects input files by extension


def test_oversized_upload_is_refused(client, monkeypatch):
    monkeypatch.setattr(sandbox, "MAX_UPLOAD_BYTES", 100)
    assert client.post("/api/cases/upload", content=_jsonl(), headers=DECLARED).status_code == 413


def test_unsupported_file_is_refused(client):
    r = client.post("/api/cases/upload", content=b"MZ\x90\x00 not a log", headers=DECLARED)
    assert r.status_code == 415


def test_uploads_are_rate_limited_per_client(client, monkeypatch):
    monkeypatch.setattr(sandbox, "CASES_PER_HOUR", 1)
    assert client.post("/api/cases/upload", content=_jsonl(), headers=DECLARED).status_code == 202
    assert client.post("/api/cases/upload", content=_jsonl(), headers=DECLARED).status_code == 429


def test_known_scenario_is_queued_for_the_worker_to_download(client, conn):
    key = next(iter(sandbox.SCENARIOS))
    r = client.post(f"/api/cases/scenario/{key}")
    assert r.status_code == 202
    [msg] = queue.claim(conn, sandbox.CASES)
    assert msg.payload == {"scenario": key, "format": "json"}


def test_unknown_scenario_is_404(client):
    assert client.post("/api/cases/scenario/not-a-scenario").status_code == 404


def test_case_page_and_json(client, conn):
    case_id = client.post("/api/cases/upload", content=_jsonl(), headers=DECLARED).json()["case_id"]
    page = client.get(f"/cases/{case_id}").text
    assert "events.json" in page and "http-equiv='refresh'" in page     # still processing: refreshes
    body = client.get(f"/api/cases/{case_id}").json()
    assert body["case"]["status"] == "queued" and body["analyst_queue"] == []


def test_unknown_case_is_404(client):
    assert client.get("/cases/nope").status_code == 404
    assert client.get("/api/cases/nope").status_code == 404


def test_ready_case_lists_its_own_alerts_and_the_demo_does_not(client, conn):
    pairs = golden_pairs()
    ingest(conn, [e for _, e in pairs], pairs)           # demo data
    case_id = sandbox.new_case_id()
    repo.create_case(conn, case_id, "scenario", "golden", client="c", ttl=timedelta(hours=24))
    raw = [json.loads((FIXTURES / f"{a}.json").read_text(encoding="utf-8"))["event"] for a in IDS]
    dets = [json.loads((FIXTURES / "hayabusa" / f"{a}.json").read_text(encoding="utf-8")) for a in IDS]
    sandbox.build_case(conn, case_id, raw, dets)
    workers.drain(conn, lambda b, e: scripted({b.alert.alert_id: ("malicious", 0.9, [])})(b, e),
                  lambda alert: POLICY, gate=lambda c, cid: sandbox.budget_gate(c, cid, per_case=1))
    case_page = client.get(f"/cases/{case_id}").text
    assert f"{case_id}-" in case_page and "AI not run" in case_page
    assert "http-equiv='refresh'" not in case_page                 # done: no more refreshing
    assert f"{case_id}-" not in client.get("/").text               # the demo docket never shows cases


def test_creating_a_case_sweeps_expired_ones(client, conn):
    old = sandbox.new_case_id()
    repo.create_case(conn, old, "upload", "x", client="other", ttl=timedelta(seconds=-1))
    client.post("/api/cases/upload", content=_jsonl(), headers=DECLARED)
    assert repo.get_case(conn, old) is None
