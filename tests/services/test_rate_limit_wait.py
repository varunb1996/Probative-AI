"""Deployed workers wait and resend on HTTP 429; this is not the judge's retry on invalid output."""

import pytest

from triage.judge.client import Completion, InferenceError, RateLimited
from triage.services import workers


class Flaky:
    def __init__(self, failures, error=RateLimited):
        self.failures, self.error, self.calls = failures, error, 0

    def complete(self, messages, schema, tools=None):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error("HTTP 429")
        return Completion(text="{}", tokens=1)


def test_rate_limits_are_waited_out(monkeypatch):
    waits = []
    monkeypatch.setattr(workers.time, "sleep", waits.append)
    inner = Flaky(failures=2)
    assert workers.PatientClient(inner).complete([], {}).text == "{}"
    assert inner.calls == 3 and waits == list(workers.RATE_LIMIT_WAITS[:2])


def test_gives_up_after_the_last_wait(monkeypatch):
    monkeypatch.setattr(workers.time, "sleep", lambda s: None)
    inner = Flaky(failures=99)
    with pytest.raises(RateLimited):
        workers.PatientClient(inner).complete([], {})
    assert inner.calls == len(workers.RATE_LIMIT_WAITS) + 1


def test_other_errors_are_not_retried(monkeypatch):
    monkeypatch.setattr(workers.time, "sleep", lambda s: None)
    inner = Flaky(failures=1, error=InferenceError)
    with pytest.raises(InferenceError):
        workers.PatientClient(inner).complete([], {})
    assert inner.calls == 1
