"""The sandbox end to end on the Neon test branch: case build, budget gate, expiry, Hayabusa."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
from integration_support import FIXTURES, IDS, POLICY, scripted

from triage.services import sandbox, workers
from triage.store import queue, repositories as repo

pytestmark = pytest.mark.integration
HAYABUSA = sandbox.default_hayabusa()


def _raw_events():
    return [json.loads((FIXTURES / f"{a}.json").read_text(encoding="utf-8"))["event"] for a in IDS]


def _detections():
    return [json.loads((FIXTURES / "hayabusa" / f"{a}.json").read_text(encoding="utf-8")) for a in IDS]


@pytest.fixture
def case(conn):
    case_id = sandbox.new_case_id()
    repo.create_case(conn, case_id, "scenario", "golden", client="c", ttl=timedelta(hours=24))
    sandbox.build_case(conn, case_id, _raw_events(), _detections())
    return case_id


def test_build_case_stores_case_scoped_alerts_and_queues_them_by_score(conn, case):
    c = repo.get_case(conn, case)
    assert (c["status"], c["n_events"], c["n_alerts"]) == ("ready", len(IDS), len(IDS))
    claimed = queue.claim(conn, workers.ENRICHED, limit=len(IDS))
    scores = [m.payload["score"]["total"] for m in claimed]
    assert all(m.alert_id.startswith(f"{case}-") for m in claimed)
    assert scores == sorted(scores, reverse=True)  # highest score is claimed first
    assert scores[0] == 13                         # the LSASS credential dump


def test_only_the_top_alerts_get_the_llm_and_the_rest_escalate(conn, case):
    judged = []

    def judge_fn(bundle, evidence):
        judged.append(bundle.alert.alert_id)
        return scripted({bundle.alert.alert_id: ("benign", 0.95, [])})(bundle, evidence)

    workers.drain(conn, judge_fn, lambda alert: POLICY, gate=lambda c, a: sandbox.budget_gate(c, a, per_case=2))
    assert len(judged) == 2
    rows = conn.execute("select v.alert_id, v.route, v.judge_result from verdicts v join alerts a "
                        "on a.alert_id = v.alert_id where a.case_id = %s", (case,)).fetchall()
    assert len(rows) == len(IDS)
    skipped = [r for r in rows if r["alert_id"] not in judged]
    assert all(r["route"] == "escalate" and r["judge_result"]["error"].startswith("AI not run")
               for r in skipped)


def test_demo_alerts_are_never_budget_gated(conn):
    assert sandbox.budget_gate(conn, None) is None


def test_daily_cap_pauses_the_llm(conn, case):
    for i in range(sandbox.DAILY_LLM_CAP):
        repo.audit(conn, f"x{i}", "judge", {"tokens_used": 100})
    assert "paused" in sandbox.budget_gate(conn, case)


def test_sweep_deletes_expired_cases(conn):
    old = sandbox.new_case_id()
    repo.create_case(conn, old, "upload", "x", client="c", ttl=timedelta(seconds=-1))
    sandbox.build_case(conn, old, _raw_events(), _detections())
    assert sandbox.sweep_expired(conn) == 1
    assert repo.get_case(conn, old) is None
    assert conn.execute("select count(*) as n from events where case_id = %s", (old,)).fetchone()["n"] == 0


def test_too_many_alerts_fails_the_case_with_a_reason(conn, monkeypatch):
    monkeypatch.setattr(sandbox, "MAX_ALERTS", 2)
    case_id = sandbox.new_case_id()
    repo.create_case(conn, case_id, "upload", "x", client="c", ttl=timedelta(hours=24))
    with pytest.raises(sandbox.SandboxError, match="alerts"):
        sandbox.build_case(conn, case_id, _raw_events(), _detections())


def test_hayabusa_finds_the_golden_detections_in_a_json_file(tmp_path):
    if HAYABUSA is None:
        pytest.fail("Hayabusa is required for the sandbox; install it (scripts/install_hayabusa.py)")
    path = tmp_path / "events.json"
    path.write_text("\n".join(json.dumps(e) for e in _raw_events()) + "\n", encoding="utf-8")
    found = {(d["Computer"], d["RecordID"], d["RuleTitle"]) for d in sandbox.run_hayabusa(path, "json")}
    for d in _detections():
        assert (d["Computer"], d["RecordID"], d["RuleTitle"]) in found


def test_process_upload_end_to_end(conn, tmp_path):
    if HAYABUSA is None:
        pytest.fail("Hayabusa is required for the sandbox; install it (scripts/install_hayabusa.py)")
    path = tmp_path / "upload.json"
    path.write_text("\n".join(json.dumps(e) for e in _raw_events()) + "\n", encoding="utf-8")
    case_id = sandbox.new_case_id()
    repo.create_case(conn, case_id, "upload", "upload.json", client="c", ttl=timedelta(hours=24))
    sandbox.process_case(conn, case_id, path, "json")
    c = repo.get_case(conn, case_id)
    assert c["status"] == "ready" and c["n_alerts"] >= len(IDS)
    assert not path.exists()     # uploads are deleted once parsed
