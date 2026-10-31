"""Strict parse of a model reply to Verdict. Off-schema is a failure, never parsed loosely."""

from pydantic import ValidationError

from triage.domain import Verdict

VERDICT_SCHEMA = Verdict.model_json_schema()


class InvalidOutput(Exception):
    pass


def parse_verdict(text: str, alert_id: str) -> Verdict:
    """The whole reply must be one Verdict JSON object for this alert."""
    try:
        verdict = Verdict.model_validate_json(text.strip())
    except ValidationError as e:
        raise InvalidOutput("; ".join(f"{'.'.join(map(str, err['loc'])) or 'reply'}: {err['msg']}"
                                      for err in e.errors())) from e
    if verdict.alert_id != alert_id:
        raise InvalidOutput(f"alert_id {verdict.alert_id!r} is not {alert_id!r}")
    return verdict
