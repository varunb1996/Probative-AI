"""Domain models shared by the pure core. Imports nothing from the project."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SUMMARY_MAX_WORDS = 80  # part of the output contract, not a routing policy


class Event(BaseModel):
    """One raw log event. `fields` keeps the source record unchanged for citation checks."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    host: str
    timestamp: datetime
    fields: dict[str, Any]


class Alert(BaseModel):
    """One detection hit (Sigma/Hayabusa) and the event IDs that triggered it."""

    model_config = ConfigDict(frozen=True)

    alert_id: str
    rule_title: str
    rule_level: str
    mitre_tags: list[str]
    host: str
    user: str | None  # absent on some channels, e.g. Security 5156
    timestamp: datetime
    event_ids: list[str]


class IntelHit(BaseModel):
    model_config = ConfigDict(frozen=True)

    indicator: str
    kind: Literal["hash", "ip", "domain"]
    source: str
    detail: str


class EvidenceBundle(BaseModel):
    """Working context for one alert. Dies with the call."""

    model_config = ConfigDict(frozen=True)

    alert: Alert
    events: list[Event]
    intel_hits: list[IntelHit] = []


class Verdict(BaseModel):
    """Output contract of the triage call and the investigator (see CLAUDE.md).

    Strict and closed: off-schema output is a failure, never parsed loosely.
    Whether cited IDs exist in the bundle is checked by the verifier, not here.
    """

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    alert_id: str = Field(min_length=1)
    verdict: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0.0, le=1.0)
    cited_event_ids: list[str]
    summary: str
    missing_context: list[str]

    @field_validator("summary")
    @classmethod
    def _summary_max_80_words(cls, value: str) -> str:
        if len(value.split()) > SUMMARY_MAX_WORDS:
            raise ValueError(f"summary must be at most {SUMMARY_MAX_WORDS} words")
        return value


class RuleMode(StrEnum):
    SHADOW = "shadow"
    ASSISTED = "assisted"
    AUTO = "auto"


class QueryRecord(BaseModel):
    """One read-only investigator tool call and the event IDs it returned."""

    model_config = ConfigDict(frozen=True)

    tool: str
    arguments: dict[str, Any]
    result_event_ids: list[str]


class LoopState(BaseModel):
    """Investigator progress. Budgets are enforced in `investigate/`, not here."""

    model_config = ConfigDict(frozen=True)

    step_count: int = 0
    tokens_used: int = 0
    query_log: list[QueryRecord] = []
