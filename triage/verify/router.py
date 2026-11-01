"""Step 6, route: code decides. Any failed check or doubt goes to a human."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from triage.domain import Investigation, JudgeResult, RuleMode
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


def route_investigation(investigation: Investigation, mode: RuleMode) -> RouteDecision:
    """Route an investigator outcome. It never goes back into investigation: anything short of a
    verified benign verdict stays with a human."""
    if not investigation.verified or investigation.result is None or investigation.result.verdict is None:
        return RouteDecision(route=Route.ESCALATE, reasons=[f"investigation stopped: {investigation.stop_reason}"])
    verdict = investigation.result.verdict.verdict
    if verdict != "benign":
        return RouteDecision(route=Route.ESCALATE, reasons=[f"{verdict} after investigation"])
    if mode == RuleMode.AUTO:
        return RouteDecision(route=Route.AUTO_CLOSE, reasons=["benign after investigation, rule type promoted"])
    return RouteDecision(route=Route.SUGGEST_CLOSE, reasons=[f"benign after investigation, rule type in {mode} mode"])
