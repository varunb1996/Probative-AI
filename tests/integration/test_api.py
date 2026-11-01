"""The API and the analyst pages, on the Neon test branch. Workers are drained with a scripted judge."""

import pytest
from fastapi.testclient import TestClient
from integration_support import ANSWERS, ATTACK, IDS, POLICY, ROUTINE, golden_pairs, scripted

from triage.api.app import create_app
from triage.services import workers
from triage.services.config import Settings
from triage.services.ingest import ingest
from triage.store import repositories as repo

pytestmark = pytest.mark.integration
TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def client(conn, test_url):
    pairs = golden_pairs()
    ingest(conn, [e for _, e in pairs], pairs)
    workers.drain(conn, scripted(ANSWERS), lambda alert: POLICY)
    app = create_app(Settings(database_url=test_url, api_token=TOKEN, run_workers=False, poll_seconds=5))
    with TestClient(app) as c:
        yield c


def test_health_reports_the_database_and_queue(client):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["pending"] == {"raw": 0, "enriched": 0, "investigate": 1}


def test_analyst_queue_holds_escalations_and_investigations(client):
    ids = {row["alert_id"] for row in client.get("/api/queue").json()}
    assert ATTACK in ids and "3272105ca1ce8305" in ids and ROUTINE not in ids


def test_suggestions_hold_the_suggested_closes(client):
    assert [row["alert_id"] for row in client.get("/api/suggestions").json()] == [ROUTINE]


def test_alert_detail_has_verdict_evidence_and_checks(client):
    body = client.get(f"/api/alerts/{ATTACK}").json()
    assert body["alert"]["alert_id"] == ATTACK
    assert body["verdict"]["route"] == "escalate"
    assert body["trigger_event"]["event_id"] == body["alert"]["event_ids"][0]


def test_unknown_alert_is_404(client):
    assert client.get("/api/alerts/0000000000000000").status_code == 404


def test_accepting_a_suggestion_records_a_confirmed_human_decision(client, conn):
    r = client.post(f"/api/alerts/{ROUTINE}/decision", json={"decision": "accept", "analyst": "varun"}, headers=AUTH)
    assert r.status_code == 200
    row = conn.execute("select * from human_decisions where alert_id = %s", (ROUTINE,)).fetchone()
    assert row["human_confirmed"] is True and row["analyst"] == "varun"
    assert client.get("/api/suggestions").json() == []
    assert conn.execute("select count(*) as n from audit_log where alert_id = %s and kind = 'human_decision'",
                        (ROUTINE,)).fetchone()["n"] == 1


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}])
def test_decisions_need_the_token(client, headers):
    r = client.post(f"/api/alerts/{ROUTINE}/decision", json={"decision": "accept", "analyst": "x"}, headers=headers)
    assert r.status_code == 401


def test_only_suggested_closes_can_be_decided(client):
    r = client.post(f"/api/alerts/{ATTACK}/decision", json={"decision": "accept", "analyst": "x"}, headers=AUTH)
    assert r.status_code == 409


def test_bad_decision_value_is_rejected(client):
    r = client.post(f"/api/alerts/{ROUTINE}/decision", json={"decision": "close it", "analyst": "x"}, headers=AUTH)
    assert r.status_code == 422


def test_writes_are_refused_when_no_token_is_configured(conn, test_url):
    pairs = golden_pairs()
    ingest(conn, [e for _, e in pairs], pairs)
    workers.drain(conn, scripted(ANSWERS), lambda alert: POLICY)
    app = create_app(Settings(database_url=test_url, api_token="", run_workers=False, poll_seconds=5))
    with TestClient(app) as c:
        r = c.post(f"/api/alerts/{ROUTINE}/decision", json={"decision": "accept", "analyst": "x"},
                   headers={"Authorization": "Bearer "})
        assert r.status_code == 503


def test_home_page_lists_the_queues(client):
    page = client.get("/").text
    assert "Analyst queue" in page and "Suggested closes" in page and ATTACK in page


def test_alert_page_escapes_log_text(client, conn):
    # Log text is hostile: a field containing markup must render as text, never as HTML.
    alert, trigger = repo.get_alert(conn, ATTACK)
    conn.execute("update events set fields = jsonb_set(fields, '{CommandLine}', to_jsonb(%s::text)) "
                 "where event_id = %s", ("<script>alert(1)</script>", trigger.event_id))
    page = client.get(f"/alerts/{ATTACK}").text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_every_golden_alert_has_a_page(client):
    for alert_id in IDS:
        assert client.get(f"/alerts/{alert_id}").status_code == 200
