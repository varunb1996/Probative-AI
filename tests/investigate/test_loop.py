"""The investigator loop contract: read-only, at most 6 steps, ends in a verified verdict or a human."""

from investigate_support import ATTACKER, POLICY, Intel, Script, Source, all_events, start_bundle, tool, verdict

from triage.investigate.loop import Budget, DecisionError, ModelUnavailable, run_investigation
from triage.pipeline.score import score


def _run(script, bundle=None, budget=None, intel=None):
    bundle = bundle or start_bundle()
    return run_investigation(bundle, score(bundle), script, Source(all_events()), intel or Intel(), POLICY,
                             budget or Budget())


def test_stops_on_a_verdict_that_passes_verify():
    result = _run(Script(tool("process_tree", **ATTACKER), lambda b: verdict(b)))
    assert result.verified and result.stop_reason == "verified verdict"
    assert result.result.verdict.verdict == "malicious"
    assert result.state.step_count == 2


def test_the_gathered_evidence_reaches_the_verdict():
    result = _run(Script(tool("process_tree", **ATTACKER), lambda b: verdict(b)))
    gathered = result.state.query_log[0].result_event_ids
    assert gathered and set(gathered) <= set(result.result.shown_event_ids)


class FreshSource(Source):
    """Every query finds one event nobody has seen, so every step makes progress."""

    def __init__(self):
        super().__init__(all_events())
        self.n = 0

    def process_events(self, process):
        self.n += 1
        e = self.events[0]
        return [e.model_copy(update={"event_id": f"fresh:{self.n}"})]


def test_escalates_at_six_steps_even_when_every_step_makes_progress():
    steps = [tool("process_tree", **ATTACKER) for _ in range(10)]
    bundle = start_bundle()
    result = run_investigation(bundle, score(bundle), Script(*steps), FreshSource(), Intel(), POLICY,
                               Budget(max_steps=6, max_tokens=10**9))
    assert not result.verified and result.stop_reason == "step cap"
    assert result.state.step_count == 6


def test_escalates_after_two_steps_that_add_nothing_new():
    same = tool("process_tree", **ATTACKER)
    result = _run(Script(same, tool("process_tree", **ATTACKER), tool("process_tree", **ATTACKER), lambda b: verdict(b)))
    assert not result.verified and result.stop_reason == "no progress"
    assert result.state.step_count == 3


def test_escalates_on_token_budget():
    result = _run(Script(tool("process_tree", tokens=5000, **ATTACKER), lambda b: verdict(b)),
                  budget=Budget(max_steps=6, max_tokens=4000))
    assert not result.verified and result.stop_reason == "token budget"


def test_rejects_a_tool_call_for_an_unknown_host():
    result = _run(Script(tool("process_tree", host="DC01.evil.local", pid=1), lambda b: verdict(b)))
    first = result.state.query_log[0]
    assert first.error and "host" in first.error and first.result_event_ids == []


def test_a_malformed_call_is_retried_once_then_escalates():
    result = _run(Script(tool("process_tree", host="nope", pid=1), tool("delete_files", path="C:\\")))
    assert not result.verified and result.stop_reason == "malformed tool calls"
    assert result.state.step_count == 2


def test_one_malformed_decision_then_a_good_one_continues():
    result = _run(Script(DecisionError("not JSON"), tool("process_tree", **ATTACKER), lambda b: verdict(b)))
    assert result.verified


def test_logs_every_query_in_loop_state():
    result = _run(Script(tool("process_tree", **ATTACKER), tool("network_connections", **ATTACKER),
                         lambda b: verdict(b)))
    assert [q.tool for q in result.state.query_log] == ["process_tree", "network_connections"]
    assert result.state.query_log[0].arguments == ATTACKER
    assert result.state.tokens_used == 300


def test_a_verdict_the_verifier_rejects_escalates():
    # Cites only an event that is not the trigger: trigger anchoring fails.
    def bad(b):
        d = verdict(b, cite_all=False)
        other = [e.event_id for e in b.events if e.event_id != b.events[0].event_id]
        return d.model_copy(update={"verdict": d.verdict.model_copy(update={"cited_event_ids": other[:1]})})
    result = _run(Script(tool("process_tree", **ATTACKER), bad))
    assert not result.verified and result.stop_reason.startswith("verdict failed verify")
    assert "trigger_anchoring" in result.stop_reason


def test_entity_lookup_hit_counts_as_progress_and_reaches_the_bundle():
    intel = Intel({"10.10.10.5": "lab C2"})
    result = _run(Script(tool("entity_lookup", kind="ip", value="10.10.10.5"), lambda b: verdict(b)), intel=intel)
    assert result.verified
    assert result.state.query_log[0].intel == ["ip:10.10.10.5"]


def test_the_investigator_is_read_only():
    events = all_events()
    before = [e.model_dump() for e in events]
    run_investigation(start_bundle(), score(start_bundle()),
                      Script(tool("process_tree", **ATTACKER), lambda b: verdict(b)),
                      Source(events), Intel(), POLICY, Budget())
    assert [e.model_dump() for e in events] == before


def test_an_unavailable_model_stops_at_once_and_says_so():
    result = _run(Script(tool("process_tree", **ATTACKER), ModelUnavailable("HTTP 429: tokens per day")))
    assert not result.verified and result.stop_reason.startswith("model unavailable")
    assert result.state.step_count == 1      # the refused call is not a step the model took
