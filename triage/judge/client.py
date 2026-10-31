"""One OpenAI-compatible chat client (Ollama, vLLM, OpenRouter). No tools, no side effects.

Data locality: a cloud endpoint is refused unless allow_cloud is true AND every alert is
tagged dataset=public. The check runs before any request is sent.
"""

import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from triage.domain import Alert

PUBLIC = "public"


class CloudRefused(Exception):
    """Sending these alerts to this endpoint is not allowed. Raised before any request."""


class InferenceError(Exception):
    """The endpoint could not be reached or returned no usable completion."""


class RateLimited(InferenceError):
    """HTTP 429. A caller may wait and resend; this is not a retry on invalid output."""


class InferenceConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    base_url: str
    model: str
    api_key: str = ""
    allow_cloud: bool = False
    timeout: float = 120.0
    structured_output: bool = True   # send the Verdict JSON schema as response_format

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "InferenceConfig":
        return cls(base_url=env["OPENAI_BASE_URL"], model=env["OPENAI_MODEL"],
                   api_key=env.get("OPENAI_API_KEY", ""),
                   allow_cloud=env.get("ALLOW_CLOUD", "").strip().lower() == "true")


@dataclass(frozen=True)
class Completion:
    text: str
    tokens: int


class ChatClient(Protocol):
    def complete(self, messages: list[dict], schema: dict[str, Any]) -> Completion: ...


def is_local(base_url: str) -> bool:
    host = (urlsplit(base_url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")


def check_allowed(config: InferenceConfig, alerts: list[Alert]) -> None:
    if is_local(config.base_url):
        return
    if not config.allow_cloud:
        raise CloudRefused(f"{config.base_url} is a cloud endpoint and allow_cloud is not true")
    untagged = [a.alert_id for a in alerts if a.dataset != PUBLIC]
    if untagged:
        raise CloudRefused(f"alerts not tagged dataset={PUBLIC}: {', '.join(untagged[:5])}")


class OpenAICompatibleClient:
    def __init__(self, config: InferenceConfig):
        self.config = config

    def complete(self, messages: list[dict], schema: dict[str, Any]) -> Completion:
        body: dict[str, Any] = {"model": self.config.model, "messages": messages, "temperature": 0}
        if self.config.structured_output:
            body["response_format"] = {"type": "json_schema",
                                       "json_schema": {"name": "verdict", "strict": True, "schema": schema}}
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        request = urllib.request.Request(
            self.config.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as e:
            error = RateLimited if e.code == 429 else InferenceError
            raise error(f"HTTP {e.code}: {e.read()[:300].decode(errors='replace')}") from e
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            raise InferenceError(str(e)) from e
        try:
            text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise InferenceError(f"no completion in response: {str(payload)[:300]}") from e
        if not isinstance(text, str):
            raise InferenceError("completion content is not text")
        return Completion(text=text, tokens=int((payload.get("usage") or {}).get("total_tokens") or 0))
