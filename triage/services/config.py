"""Service settings, from environment variables only (Render dashboard or a local .env)."""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from triage.judge.client import InferenceConfig
from triage.pipeline.score import CLOSE_BELOW
from triage.verify.checks import VerifyPolicy

ENV_FILE = Path(".env")
POLICY_FILE = Path("config") / "policy.json"


def load_dotenv(path: Path = ENV_FILE) -> None:
    """KEY=VALUE lines; values already in the environment win. No-op on a host without .env."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def inference_config(env: Mapping[str, str]) -> InferenceConfig:
    """OPENAI_* settings, or NAME_* when LLM_PROVIDER=NAME (e.g. groq) is set."""
    provider = env.get("LLM_PROVIDER", "").strip()
    if not provider:
        return InferenceConfig.from_env(env)
    prefix = provider.upper() + "_"
    mapped = dict(env)
    for key in ("BASE_URL", "MODEL", "API_KEY"):
        mapped["OPENAI_" + key] = env.get(prefix + key, "")
    for flag in ("ALLOW_CLOUD", "STRUCTURED_OUTPUT"):
        if prefix + flag in env:
            mapped[flag] = env[prefix + flag]
    if not mapped["OPENAI_BASE_URL"] or not mapped["OPENAI_MODEL"]:
        raise ValueError(f"LLM_PROVIDER={provider} but {prefix}BASE_URL or {prefix}MODEL is not set")
    return InferenceConfig.from_env(mapped)


def load_policy(env: Mapping[str, str], path: Path = POLICY_FILE) -> VerifyPolicy:
    """Close thresholds per rule type from config/policy.json (calibrated on the labels).

    No file means no thresholds, so nothing can close: the safe default.
    """
    thresholds = json.loads(path.read_text(encoding="utf-8"))["close_confidence"] if path.exists() else {}
    hosts = frozenset(h.strip() for h in env.get("CRITICAL_HOSTS", "").split(",") if h.strip())
    return VerifyPolicy(high_risk_score=CLOSE_BELOW, close_confidence=thresholds, critical_hosts=hosts)


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_token: str
    run_workers: bool
    poll_seconds: float

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Settings":
        url = env.get("DATABASE_URL", "")
        if not url:
            raise ValueError("DATABASE_URL is not set")
        return cls(database_url=url, api_token=env.get("API_TOKEN", ""),
                   run_workers=env.get("RUN_WORKERS", "").strip().lower() == "true",
                   poll_seconds=float(env.get("POLL_SECONDS", "5")))
