"""--provider NAME picks NAME_* settings from one .env. Made-up values only."""

import pytest

from eval.harness.run import provider_env

_ENV = {
    "GROQ_BASE_URL": "https://api.groq.com/openai/v1", "GROQ_MODEL": "g-model", "GROQ_API_KEY": "g-key",
    "OPENROUTER_BASE_URL": "https://openrouter.ai/api/v1", "OPENROUTER_MODEL": "o-model",
    "OPENROUTER_API_KEY": "o-key", "ALLOW_CLOUD": "true", "STRUCTURED_OUTPUT": "true",
}


def test_provider_selects_its_prefixed_settings():
    env = provider_env(_ENV, "groq")
    assert (env["OPENAI_BASE_URL"], env["OPENAI_MODEL"], env["OPENAI_API_KEY"]) == (
        "https://api.groq.com/openai/v1", "g-model", "g-key")


def test_the_other_providers_key_is_never_used():
    assert provider_env(_ENV, "openrouter")["OPENAI_API_KEY"] == "o-key"
    assert provider_env(_ENV, "groq")["OPENAI_API_KEY"] == "g-key"


def test_prefixed_flags_override_the_shared_ones():
    env = provider_env({**_ENV, "GROQ_STRUCTURED_OUTPUT": "false"}, "groq")
    assert env["STRUCTURED_OUTPUT"] == "false" and env["ALLOW_CLOUD"] == "true"


def test_shared_flags_apply_when_no_prefixed_one_is_set():
    assert provider_env(_ENV, "openrouter")["STRUCTURED_OUTPUT"] == "true"


def test_no_provider_leaves_the_plain_openai_settings():
    env = {"OPENAI_BASE_URL": "http://localhost:11434/v1", "OPENAI_MODEL": "m"}
    assert provider_env(env, None) == env


def test_unknown_provider_is_refused():
    with pytest.raises(ValueError, match="MISTRAL_BASE_URL"):
        provider_env(_ENV, "mistral")
