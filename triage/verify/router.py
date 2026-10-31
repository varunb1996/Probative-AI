"""Step 6, route: code decides. Any failed check or doubt goes to a human."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from triage.domain import JudgeResult, RuleMode
from triage.verify.checks import VerifyReport


class Route(StrEnum):
    ESCALATE = "escalate"
    SUGGEST_CLOSE = "suggest_close"
    AUTO_CLOSE = "auto_close"
    INVESTIGATE = "investigate"


class RouteDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    route: Route
    reasons: list[str]


def route(result: JudgeResult, report: VerifyReport, mode: RuleMode) -> RouteDecision:
    if not report.passed:
        return RouteDecision(route=Route.ESCALATE, reasons=report.failed)
    verdict = result.verdict
    if verdict.verdict == "malicious":
        return RouteDecision(route=Route.ESCALATE, reasons=["malicious"])
    if verdict.verdict == "suspicious":
        if verdict.missing_context:
            return RouteDecision(route=Route.INVESTIGATE, reasons=["suspicious, insufficient context"])
        return RouteDecision(route=Route.ESCALATE, reasons=["suspicious"])
    if mode == RuleMode.AUTO:
        return RouteDecision(route=Route.AUTO_CLOSE, reasons=["benign, rule type promoted"])
    return RouteDecision(route=Route.SUGGEST_CLOSE, reasons=[f"benign, rule type in {mode} mode"])
