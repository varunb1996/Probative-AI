"""Step 5, the triage call: one alert, structured output only, exactly one retry."""

from triage.domain import EvidenceBundle, EvidenceScore, JudgeResult
from triage.judge.client import ChatClient, InferenceConfig, InferenceError, check_allowed
from triage.judge.parser import VERDICT_SCHEMA, InvalidOutput, parse_verdict
from triage.judge.prompt import build_messages

MAX_ATTEMPTS = 2

_RETRY = ("Your previous reply was invalid: {error}. Reply again with exactly one JSON object "
          "matching the required keys, and nothing else.")


def judge(bundle: EvidenceBundle, score: EvidenceScore, client: ChatClient,
          config: InferenceConfig) -> JudgeResult:
    """A verdict, or a failure result saying why. Raises CloudRefused before any call."""
    check_allowed(config, [bundle.alert])
    messages, shown = build_messages(bundle, score)
    alert_id = bundle.alert.alert_id
    errors: list[str] = []
    tokens = 0

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            completion = client.complete(messages, VERDICT_SCHEMA)
        except InferenceError as e:
            errors.append(f"attempt {attempt}: inference error: {e}")
            continue
        tokens += completion.tokens
        try:
            verdict = parse_verdict(completion.text, alert_id)
        except InvalidOutput as e:
            errors.append(f"attempt {attempt}: invalid output: {e}")
            messages = messages + [{"role": "assistant", "content": completion.text},
                                   {"role": "user", "content": _RETRY.format(error=e)}]
            continue
        return JudgeResult(alert_id=alert_id, verdict=verdict, attempts=attempt,
                           shown_event_ids=shown, tokens_used=tokens)

    return JudgeResult(alert_id=alert_id, attempts=MAX_ATTEMPTS, error=" | ".join(errors),
                       shown_event_ids=shown, tokens_used=tokens)
