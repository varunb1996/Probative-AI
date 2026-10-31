"""The triage call: strict parse, exactly one retry, then a failure result. Cloud only for public data."""

import pytest
from judge_support import CLOUD, LOCAL, SCORE, FakeClient, golden_bundle, verdict_json

from triage.judge.client import CloudRefused, InferenceError
from triage.judge.judge import judge


def test_valid_output_on_first_try(bundle):
    client = FakeClient(verdict_json(bundle))
    result = judge(bundle, SCORE, client, LOCAL)
    assert result.ok and result.verdict.verdict == "malicious"
    assert (result.attempts, len(client.calls), result.tokens_used) == (1, 1, 100)
    assert result.shown_event_ids == [bundle.events[0].event_id]


def test_invalid_then_valid_retries_once_with_the_error(bundle):
    client = FakeClient("not json", verdict_json(bundle))
    result = judge(bundle, SCORE, client, LOCAL)
    assert result.ok and result.attempts == 2
    assert "invalid" in client.calls[1][-1]["content"].lower()


def test_invalid_twice_is_a_failure_result_never_a_verdict(bundle):
    client = FakeClient("not json", verdict_json(bundle, verdict="probably fine"))
    result = judge(bundle, SCORE, client, LOCAL)
    assert not result.ok and result.verdict is None
    assert result.attempts == 2 and len(client.calls) == 2
    assert result.error


@pytest.mark.parametrize("reply", [
    "```json\n{}\n```",                                    # code fence: never parse loosely
    "Here you go: {}",                                     # prose around the object
])
def test_wrapped_output_is_invalid(bundle, reply):
    client = FakeClient(reply, reply)
    assert not judge(bundle, SCORE, client, LOCAL).ok


def test_fenced_valid_json_is_still_invalid(bundle):
    fenced = f"```json\n{verdict_json(bundle)}\n```"
    assert not judge(bundle, SCORE, FakeClient(fenced, fenced), LOCAL).ok


def test_extra_keys_are_invalid(bundle):
    reply = verdict_json(bundle, action="close the alert")
    assert not judge(bundle, SCORE, FakeClient(reply, reply), LOCAL).ok


def test_verdict_for_another_alert_is_invalid(bundle):
    reply = verdict_json(bundle, alert_id="0000000000000000")
    assert not judge(bundle, SCORE, FakeClient(reply, reply), LOCAL).ok


def test_string_confidence_is_not_coerced(bundle):
    reply = verdict_json(bundle, confidence="0.9")
    assert not judge(bundle, SCORE, FakeClient(reply, reply), LOCAL).ok


def test_integer_confidence_is_a_number(bundle):
    assert judge(bundle, SCORE, FakeClient(verdict_json(bundle, confidence=1)), LOCAL).ok


def test_inference_error_counts_as_an_attempt_and_is_never_swallowed(bundle):
    class Failing(FakeClient):
        def complete(self, messages, schema):
            self.calls.append(messages)
            raise InferenceError("HTTP 503")

    client = Failing()
    result = judge(bundle, SCORE, client, LOCAL)
    assert not result.ok and "503" in result.error and len(client.calls) == 2


def test_cloud_refused_for_untagged_alert_before_any_call():
    bundle = golden_bundle("32a60c4fa80ff99c", dataset=None)
    client = FakeClient()
    with pytest.raises(CloudRefused):
        judge(bundle, SCORE, client, CLOUD)
    assert client.calls == []


def test_cloud_refused_without_allow_cloud_even_for_public_data():
    bundle = golden_bundle("32a60c4fa80ff99c", dataset="public")
    client = FakeClient()
    with pytest.raises(CloudRefused):
        judge(bundle, SCORE, client, CLOUD.model_copy(update={"allow_cloud": False}))
    assert client.calls == []


def test_cloud_allowed_for_public_data_with_allow_cloud():
    bundle = golden_bundle("32a60c4fa80ff99c", dataset="public")
    assert judge(bundle, SCORE, FakeClient(verdict_json(bundle)), CLOUD).ok


def test_local_endpoint_needs_no_flag_or_tag(bundle):
    assert bundle.alert.dataset is None
    assert judge(bundle, SCORE, FakeClient(verdict_json(bundle)), LOCAL).ok
