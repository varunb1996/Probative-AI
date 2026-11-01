"""The bounded investigator loop (design: Investigator loop contract).

Read-only tools, at most `max_steps` decisions, and it always ends in a verdict the same verifier
accepts, or a hand-off to a human carrying its full query log. `decide` is a parameter: the
model in production, a script in tests. The loop, not the model, executes and stops.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict

from triage.domain import (EventSource, EvidenceBundle, EvidenceScore, IntelLookup, Investigation, JudgeResult,
                           LoopState, QueryRecord, Verdict)
from triage.investigate.tools import ToolError, run_tool
from triage.pipeline.score import score as evidence_score
from triage.verify.checks import VerifyPolicy, verify


class DecisionError(Exception):
    """The model's decision was not a valid tool call or verdict (off-schema output)."""


class ModelUnavailable(Exception):
    """The provider refused or failed the call (quota, outage). Not the model's fault, not retried."""


class Decision(BaseModel):
    """What the model proposes next: one tool call, or a final verdict."""

    model_config = ConfigDict(frozen=True)

    tool: str | None = None
    args: dict[str, Any] = {}
    verdict: Verdict | None = None
    tokens: int = 0
    shown_event_ids: list[str] = []


@dataclass(frozen=True)
class Budget:
    max_steps: int = 6
    max_tokens: int = 60_000


Decide = Callable[[EvidenceBundle, EvidenceScore, LoopState], Decision]


def run_investigation(bundle: EvidenceBundle, score: EvidenceScore, decide: Decide, source: EventSource,
                      intel: IntelLookup, policy: VerifyPolicy, budget: Budget = Budget()) -> Investigation:
    state = LoopState()
    malformed = empty = 0

    def stop(reason: str, result: JudgeResult | None = None, verified: bool = False) -> Investigation:
        return Investigation(alert_id=bundle.alert.alert_id, verified=verified, stop_reason=reason,
                             result=result, state=state)

    def log(record: QueryRecord, tokens: int = 0) -> LoopState:
        return state.model_copy(update={"step_count": state.step_count + 1, "tokens_used": state.tokens_used + tokens,
                                        "query_log": [*state.query_log, record]})

    while True:
        if state.step_count >= budget.max_steps:
            return stop("step cap")
        if state.tokens_used >= budget.max_tokens:
            return stop("token budget")

        try:
            decision = decide(bundle, score, state)
        except ModelUnavailable as e:
            return stop(f"model unavailable: {str(e)[:200]}")
        except DecisionError as e:
            state = log(QueryRecord(tool="(malformed)", arguments={}, result_event_ids=[], error=str(e)))
            malformed += 1
            if malformed >= 2:
                return stop("malformed tool calls")
            continue

        if decision.verdict is not None:
            state = state.model_copy(update={"step_count": state.step_count + 1,
                                             "tokens_used": state.tokens_used + decision.tokens})
            shown = decision.shown_event_ids or [e.event_id for e in bundle.events]
            result = JudgeResult(alert_id=bundle.alert.alert_id, verdict=decision.verdict, attempts=1,
                                 shown_event_ids=shown, tokens_used=state.tokens_used)
            report = verify(result, bundle, score, policy)
            if report.passed:
                return stop("verified verdict", result, verified=True)
            return stop(f"verdict failed verify: {', '.join(report.failed)}", result)

        try:
            output = run_tool(decision.tool or "", decision.args, bundle, source, intel)
        except ToolError as e:
            state = log(QueryRecord(tool=decision.tool or "(none)", arguments=decision.args, result_event_ids=[],
                                    error=str(e)), decision.tokens)
            malformed += 1
            if malformed >= 2:
                return stop("malformed tool calls")
            continue
        malformed = 0

        have = {e.event_id for e in bundle.events}
        new_events = []
        for e in output.events:
            if e.event_id not in have:
                have.add(e.event_id)
                new_events.append(e)
        known_hits = {(h.kind, h.indicator) for h in bundle.intel_hits}
        new_hits = [h for h in output.hits if (h.kind, h.indicator) not in known_hits]
        state = log(QueryRecord(tool=decision.tool, arguments=decision.args,
                                result_event_ids=[e.event_id for e in new_events],
                                intel=[f"{h.kind}:{h.indicator}" for h in new_hits]), decision.tokens)
        if new_events or new_hits:
            empty = 0
            bundle = bundle.model_copy(update={"events": [*bundle.events, *new_events],
                                               "intel_hits": [*bundle.intel_hits, *new_hits]})
            score = evidence_score(bundle)
        else:
            empty += 1
            if empty >= 2:
                return stop("no progress")
