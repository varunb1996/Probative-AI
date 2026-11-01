"""The exhibit page shows an investigation's steps and how it ended. Pure rendering, no database."""

from triage.api import pages

_ALERT = {"alert_id": "a1", "rule_title": "Network Connection Initiated By PowerShell Process", "host": "WS5",
          "timestamp": "2020-08-07T14:32:50Z", "rule_level": "low", "user": None}
_TRIGGER = {"event_id": "Security:202260", "fields": {"Channel": "Security"}}
_VERDICT = {"route": "escalate", "reasons": ["malicious after investigation"],
            "score": {"total": 8, "contributions": {"level_low": 1}},
            "report": {"checks": []},
            "judge_result": {"verdict": {"verdict": "suspicious", "confidence": 0.6, "summary": "s",
                                         "cited_event_ids": ["Security:202260"], "missing_context": ["more"]}}}


def _investigation(verified=True):
    return {"verified": verified, "stop_reason": "verified verdict" if verified else "step cap",
            "result": {"verdict": {"verdict": "malicious", "confidence": 0.95, "summary": "<b>beacons</b> to C2",
                                   "cited_event_ids": [], "missing_context": []}} if verified else None,
            "state": {"step_count": 2, "tokens_used": 900, "query_log": [
                {"tool": "process_tree", "arguments": {"host": "WS5", "pid": 1648}, "result_event_ids": ["e1", "e2"],
                 "intel": [], "error": None},
                {"tool": "host_timeline", "arguments": {"host": "WS5"}, "result_event_ids": [], "intel": [],
                 "error": "time window is wider than the cap"}]}}


def _page(investigation):
    return pages.alert({"alert": _ALERT, "verdict": _VERDICT, "trigger_event": _TRIGGER, "decision": None,
                        "case_id": None, "investigation": investigation})


def test_investigation_steps_and_outcome_are_shown():
    page = _page(_investigation())
    assert "Investigation" in page and "process_tree" in page and "+2 events" in page
    assert "time window is wider than the cap" in page and "verified verdict" in page
    assert "&lt;b&gt;beacons&lt;/b&gt;" in page          # the model's summary is escaped


def test_unverified_investigation_says_it_went_to_a_human():
    page = _page(_investigation(verified=False))
    assert "step cap" in page and "analyst" in page.lower()


def test_no_investigation_no_panel():
    assert "Investigation ·" not in _page(None)
