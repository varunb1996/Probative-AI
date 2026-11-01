"""Service settings come from the environment only. Made-up values."""

import json

import pytest

from triage.services.config import Settings, inference_config, load_policy

_GROQ = {"LLM_PROVIDER": "groq", "GROQ_BASE_URL": "https://api.groq.com/openai/v1", "GROQ_MODEL": "g",
         "GROQ_API_KEY": "k", "ALLOW_CLOUD": "true"}


def test_llm_provider_selects_the_prefixed_endpoint():
    config = inference_config(_GROQ)
    assert (config.base_url, config.model, config.api_key, config.allow_cloud) == (
        "https://api.groq.com/openai/v1", "g", "k", True)


def test_without_a_provider_the_openai_names_apply():
    assert inference_config({"OPENAI_BASE_URL": "http://localhost:11434/v1", "OPENAI_MODEL": "m"}).model == "m"


def test_a_provider_without_settings_is_refused():
    with pytest.raises(ValueError):
        inference_config({"LLM_PROVIDER": "mistral"})


def test_no_policy_file_means_nothing_can_close(tmp_path):
    assert load_policy({}, tmp_path / "missing.json").close_confidence == {}


def test_policy_file_and_critical_hosts(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"close_confidence": {"Proc Access": 0.9}}), encoding="utf-8")
    policy = load_policy({"CRITICAL_HOSTS": "dc1, dc2 ,"}, path)
    assert policy.close_confidence == {"Proc Access": 0.9}
    assert policy.critical_hosts == frozenset({"dc1", "dc2"})
    assert policy.high_risk_score == 5


def test_database_url_is_required():
    with pytest.raises(ValueError):
        Settings.from_env({})


def test_workers_run_only_when_asked():
    assert not Settings.from_env({"DATABASE_URL": "postgresql://x"}).run_workers
    assert Settings.from_env({"DATABASE_URL": "postgresql://x", "RUN_WORKERS": "true"}).run_workers
