"""The HTTP client maps transport failures to InferenceError; a 429 is a RateLimited."""

import io
import json
import urllib.error

import pytest
from judge_support import CLOUD

from triage.judge import client as client_module
from triage.judge.client import InferenceConfig, InferenceError, OpenAICompatibleClient, RateLimited


def _raise(code):
    def urlopen(request, timeout):
        raise urllib.error.HTTPError(request.full_url, code, "error", {}, io.BytesIO(b"slow down"))
    return urlopen


def test_429_is_rate_limited(monkeypatch):
    monkeypatch.setattr(client_module.urllib.request, "urlopen", _raise(429))
    with pytest.raises(RateLimited):
        OpenAICompatibleClient(CLOUD).complete([], {})


def test_rate_limited_is_an_inference_error():
    assert issubclass(RateLimited, InferenceError)


_ENV = {"OPENAI_BASE_URL": "https://api.groq.com/openai/v1", "OPENAI_MODEL": "m"}


def test_structured_output_is_on_by_default():
    assert InferenceConfig.from_env(_ENV).structured_output


def test_structured_output_can_be_switched_off_in_env():
    assert not InferenceConfig.from_env({**_ENV, "STRUCTURED_OUTPUT": "false"}).structured_output


def _capture(sent):
    def urlopen(request, timeout):
        sent.append(json.loads(request.data))
        return io.BytesIO(json.dumps({"choices": [{"message": {"content": "{}"}}],
                                      "usage": {"total_tokens": 7}}).encode())
    return urlopen


def test_schema_is_sent_only_when_structured_output_is_on(monkeypatch):
    sent = []
    monkeypatch.setattr(client_module.urllib.request, "urlopen", _capture(sent))
    OpenAICompatibleClient(CLOUD).complete([], {"type": "object"})
    OpenAICompatibleClient(CLOUD.model_copy(update={"structured_output": False})).complete([], {})
    assert "response_format" in sent[0] and "response_format" not in sent[1]


def test_other_http_errors_are_plain_inference_errors(monkeypatch):
    monkeypatch.setattr(client_module.urllib.request, "urlopen", _raise(503))
    with pytest.raises(InferenceError) as info:
        OpenAICompatibleClient(CLOUD).complete([], {})
    assert not isinstance(info.value, RateLimited)
