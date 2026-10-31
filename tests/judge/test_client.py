"""The HTTP client maps transport failures to InferenceError; a 429 is a RateLimited."""

import io
import urllib.error

import pytest
from judge_support import CLOUD

from triage.judge import client as client_module
from triage.judge.client import InferenceError, OpenAICompatibleClient, RateLimited


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


def test_other_http_errors_are_plain_inference_errors(monkeypatch):
    monkeypatch.setattr(client_module.urllib.request, "urlopen", _raise(503))
    with pytest.raises(InferenceError) as info:
        OpenAICompatibleClient(CLOUD).complete([], {})
    assert not isinstance(info.value, RateLimited)
