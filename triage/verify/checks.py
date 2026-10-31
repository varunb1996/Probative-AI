"""The verifier: seven checks on a judge result. Pure; never imports triage.judge.

It guards only the close path. Escalation is always allowed, so checks 3, 4 and 6
(the close policy) apply to benign verdicts only; every other check applies to all.
Policy values come from a VerifyPolicy passed in, never from a prompt.
"""

import re

from pydantic import BaseModel, ConfigDict

from triage.domain import EvidenceBundle, EvidenceScore, JudgeResult

# Instruction-like text has no business in a log field; finding it is an attack signal.
_INJECTION = [re.compile(p, re.IGNORECASE) for p in (
    r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(instructions?|prompt|rules?|guidelines?)\b",
    r"\bclassify\b[^.\n]{0,40}\b(as\s+)?(benign|safe|clean|harmless)\b",
    r"\b(mark|label|treat|report)\b[^.\n]{0,30}\bas\s+(benign|safe|clean|harmless)\b",
    r"\bsystem\s+prompt\b",
    r"\byou\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|analyst|language\s+model)\b",
    r"\b(respond|reply|answer)\s+with\b",
    r"</?\s*(untrusted_logs|system|assistant|user)\s*>",
)]
_QUOTED = re.compile(r'"([^"]{3,})"|`([^`]{2,})`')


class VerifyPolicy(BaseModel):
    """Close-path policy. No defaults for thresholds: the caller must calibrate them."""

    model_config = ConfigDict(frozen=True)

    high_risk_score: float
    close_confidence: dict[str, float]          # rule_title -> minimum confidence to close
    critical_hosts: frozenset[str] = frozenset()


class Check(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    passed: bool
    detail: str = ""


class VerifyReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    alert_id: str
    checks: list[Check]

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failed(self) -> list[str]:
        return [c.name for c in self.checks if not c.passed]


def verify(result: JudgeResult, bundle: EvidenceBundle, score: EvidenceScore,
           policy: VerifyPolicy) -> VerifyReport:
    checks = [Check(name="schema", passed=result.ok, detail=result.error or "")]
    verdict = result.verdict
    if verdict is None:
        not_run = "not run: no verdict"
        checks += [Check(name=n, passed=False, detail=not_run) for n in (
            "citation_grounding", "hard_override", "baseline_disagreement")]
        checks.append(_injection_tripwire(bundle))
        checks += [Check(name=n, passed=False, detail=not_run) for n in (
            "calibrated_confidence", "trigger_anchoring")]
        return VerifyReport(alert_id=result.alert_id, checks=checks)

    benign = verdict.verdict == "benign"
    checks += [
        _citation_grounding(result, bundle),
        _hard_override(bundle, policy) if benign else _skipped("hard_override"),
        (_baseline_disagreement(score, policy) if benign else _skipped("baseline_disagreement")),
        _injection_tripwire(bundle),
        (_calibrated_confidence(result, bundle, policy) if benign else _skipped("calibrated_confidence")),
        _trigger_anchoring(result, bundle),
    ]
    return VerifyReport(alert_id=result.alert_id, checks=checks)


def _skipped(name: str) -> Check:
    return Check(name=name, passed=True, detail="close policy: not a benign verdict")


def _citation_grounding(result: JudgeResult, bundle: EvidenceBundle) -> Check:
    shown = set(result.shown_event_ids)
    by_id = {e.event_id: e for e in bundle.events}
    invented = [i for i in result.verdict.cited_event_ids if i not in shown or i not in by_id]
    if invented:
        return Check(name="citation_grounding", passed=False, detail=f"not in the evidence: {invented}")
    cited_text = " ".join(str(v) for i in result.verdict.cited_event_ids
                          for v in by_id[i].fields.values()).lower()
    quotes = [a or b for a, b in _QUOTED.findall(result.verdict.summary)]
    unfounded = [q for q in quotes if q.lower() not in cited_text]
    if unfounded:
        return Check(name="citation_grounding", passed=False,
                     detail=f"quoted values not in the cited events: {unfounded}")
    return Check(name="citation_grounding", passed=True)


def _hard_override(bundle: EvidenceBundle, policy: VerifyPolicy) -> Check:
    reasons = [f"intel hit ({h.kind} {h.indicator})" for h in bundle.intel_hits]
    if bundle.alert.host.lower() in {h.lower() for h in policy.critical_hosts}:
        reasons.append(f"critical host {bundle.alert.host}")
    return Check(name="hard_override", passed=not reasons, detail="; ".join(reasons))


def _baseline_disagreement(score: EvidenceScore, policy: VerifyPolicy) -> Check:
    high = score.total >= policy.high_risk_score
    return Check(name="baseline_disagreement", passed=not high,
                 detail=f"benign verdict but evidence score {score.total:g} >= {policy.high_risk_score:g}"
                 if high else "")


def _injection_tripwire(bundle: EvidenceBundle) -> Check:
    for event in bundle.events:
        for key, value in event.fields.items():
            if isinstance(value, str) and any(p.search(value) for p in _INJECTION):
                return Check(name="injection_tripwire", passed=False,
                             detail=f"instruction-like text in {event.event_id} field {key}")
    return Check(name="injection_tripwire", passed=True)


def _calibrated_confidence(result: JudgeResult, bundle: EvidenceBundle, policy: VerifyPolicy) -> Check:
    rule = bundle.alert.rule_title
    threshold = policy.close_confidence.get(rule)
    if threshold is None:
        return Check(name="calibrated_confidence", passed=False,
                     detail=f"no calibrated close threshold for rule type {rule!r}")
    ok = result.verdict.confidence >= threshold
    return Check(name="calibrated_confidence", passed=ok,
                 detail="" if ok else f"confidence {result.verdict.confidence} < {threshold} for {rule!r}")


def _trigger_anchoring(result: JudgeResult, bundle: EvidenceBundle) -> Check:
    anchored = bool(set(bundle.alert.event_ids) & set(result.verdict.cited_event_ids))
    return Check(name="trigger_anchoring", passed=anchored,
                 detail="" if anchored else f"triggering event {bundle.alert.event_ids} not cited")
