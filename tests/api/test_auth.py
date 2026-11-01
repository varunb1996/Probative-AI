"""The static demo token check, without a database."""

from triage.api.auth import token_ok


def test_matching_bearer_token():
    assert token_ok("Bearer s3cret", "s3cret")


def test_wrong_missing_or_malformed_tokens():
    assert not token_ok("Bearer nope", "s3cret")
    assert not token_ok(None, "s3cret")
    assert not token_ok("s3cret", "s3cret")


def test_an_empty_configured_token_never_matches():
    assert not token_ok("Bearer ", "")
