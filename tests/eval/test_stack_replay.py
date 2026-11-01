"""The stack gate replays recorded judge results; no model is called."""

from eval.harness.stack import replay_judge
from triage.domain import EvidenceBundle, EvidenceScore, JudgeResult, Verdict


def _bundle(alert_id):
    from datetime import datetime, timezone
    from triage.domain import Alert, Event
    ts = datetime(2020, 8, 7, tzinfo=timezone.utc)
    event = Event(event_id="ev:1", host="h", timestamp=ts, fields={})
    alert = Alert(alert_id=alert_id, rule_title="r", rule_level="low", mitre_tags=[], host="h", user=None,
                  timestamp=ts, event_ids=["ev:1"])
    return EvidenceBundle(alert=alert, events=[event])


def test_recorded_result_is_returned_unchanged(tmp_path):
    v = Verdict(alert_id="a1", verdict="benign", confidence=0.9, cited_event_ids=["ev:1"], summary="s",
                missing_context=[])
    recorded = JudgeResult(alert_id="a1", verdict=v, attempts=1, shown_event_ids=["ev:1"], tokens_used=5)
    (tmp_path / "a1.json").write_text(recorded.model_dump_json(), encoding="utf-8")
    assert replay_judge(tmp_path)(_bundle("a1"), EvidenceScore(total=1, contributions={})) == recorded


def test_alert_with_no_recorded_result_replays_as_a_failure(tmp_path):
    result = replay_judge(tmp_path)(_bundle("a2"), EvidenceScore(total=1, contributions={}))
    assert not result.ok and "no recorded result" in result.error
