"""decide() in json mode, for models without function calling: one strict JSON object per step."""

import json

import pytest
from investigate_support import ATTACKER, start_bundle

from triage.domain import LoopState
from triage.investigate.decide import model_decide
from triage.investigate.loop import DecisionError
from triage.judge.client import Completion, InferenceConfig
from triage.pipeline.score import score

LOCAL = InferenceConfig(base_url="http://localhost:11434/v1", model="m")
_NO_ARGS = {"host": None, "pid": None, "guid": None, "start": None, "end": None, "kind": None, "value": None}


class Fake:
    def __init__(self, text):
        self.text, self.calls, self.tools = text, [], []

    def complete(self, messages, schema, tools=None):
        self.calls.append(messages)
        self.tools.append(tools)
        return Completion(text=self.text, tokens=7)


def _decide(reply, bundle=None):
    bundle = bundle or start_bundle()
    client = Fake(reply if isinstance(reply, str) else json.dumps(reply))
    return model_decide(client, LOCAL, mode="json")(bundle, score(bundle), LoopState()), client


def tool_reply(name, **args):
    return {"action": "tool", "tool": name, "args": {**_NO_ARGS, **args}, "verdict": None}


def verdict_reply(bundle, **over):
    v = {"alert_id": bundle.alert.alert_id, "verdict": "malicious", "confidence": 0.9,
         "cited_event_ids": [bundle.events[0].event_id], "summary": "s", "missing_context": []}
    return {"action": "verdict", "tool": None, "args": None, "verdict": {**v, **over}}


def test_a_query_reply_becomes_a_decision_without_null_arguments():
    d, client = _decide(tool_reply("process_tree", **ATTACKER))
    assert (d.tool, d.args) == ("process_tree", ATTACKER)
    assert client.tools == [None]                         # no function definitions in json mode


def test_a_verdict_reply_becomes_a_decision():
    bundle = start_bundle()
    d, _ = _decide(verdict_reply(bundle), bundle)
    assert d.verdict.verdict == "malicious" and d.shown_event_ids == [bundle.events[0].event_id]


def test_the_prompt_spells_out_the_reply_shape():
    _, client = _decide(tool_reply("process_tree", **ATTACKER))
    system = client.calls[0][0]["content"]
    for word in ("action", "tool", "args", "verdict", "process_tree", "entity_lookup"):
        assert word in system


@pytest.mark.parametrize("reply", [
    "We need to decide verdict.",                                                    # prose
    "```json\n{}\n```",                                                              # fenced
    {"action": "tool", "tool": "process_tree", "args": None, "verdict": None},      # a query needs args
    {**tool_reply("process_tree", host="h", pid=1), "note": "x"},                   # extra key
    {"action": "close", "tool": None, "args": None, "verdict": None},               # no such action
    {**tool_reply("process_tree", host="h", pid=1), "verdict": {"verdict": "benign"}},  # both at once
])
def test_off_shape_replies_are_decision_errors(reply):
    with pytest.raises(DecisionError):
        _decide(reply)


def test_a_verdict_for_another_alert_is_a_decision_error():
    bundle = start_bundle()
    with pytest.raises(DecisionError):
        _decide(verdict_reply(bundle, alert_id="0000000000000000"), bundle)


def test_unknown_mode_is_refused():
    with pytest.raises(ValueError):
        model_decide(Fake("{}"), LOCAL, mode="xml")
