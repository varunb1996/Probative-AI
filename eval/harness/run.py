"""Full eval: pipeline + judge + verify + route over the labelled alerts; writes a Markdown report.

Judge results are cached per model in data/evals/, so a run cut off by rate limits resumes.
"""

import os
import re
import time
from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from eval.harness.calibrate import Row, loo_thresholds
from eval.harness.dataset import DATA, EXCLUDED, load_labels, load_pairs
from eval.harness.jsonl_source import NoIntel
from triage.domain import JudgeResult, RuleMode
from triage.judge.client import Completion, InferenceConfig, OpenAICompatibleClient, RateLimited
from triage.judge.judge import judge
from triage.pipeline.context import build_bundle
from triage.pipeline.enrich import enrich
from triage.pipeline.score import CLOSE_BELOW, score
from triage.verify.checks import VerifyPolicy, verify
from triage.verify.router import Route, route

ENV_FILE = Path(".env")
REPORTS = Path("eval") / "reports"
RATE_LIMIT_WAITS = (30, 60, 120)
CLOSES = {Route.SUGGEST_CLOSE, Route.AUTO_CLOSE}


class PatientClient:
    """Waits and resends on HTTP 429 only. Not the judge's retry on invalid output."""

    def __init__(self, inner: OpenAICompatibleClient, pause: float):
        self.inner, self.pause = inner, pause

    def complete(self, messages, schema) -> Completion:
        for wait in (*RATE_LIMIT_WAITS, None):
            time.sleep(self.pause)
            try:
                return self.inner.complete(messages, schema)
            except RateLimited:
                if wait is None:
                    raise
                print(f"    rate limited; waiting {wait}s", flush=True)
                time.sleep(wait)
        raise AssertionError("unreachable")


def load_env(path: Path = ENV_FILE) -> None:
    """KEY=VALUE lines from .env; values already in the environment win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def provider_env(env: Mapping[str, str], provider: str | None) -> dict[str, str]:
    """With a provider, map NAME_BASE_URL/MODEL/API_KEY (and optional NAME_ALLOW_CLOUD,
    NAME_STRUCTURED_OUTPUT) onto the OPENAI_* settings the client reads."""
    out = dict(env)
    if provider is None:
        return out
    prefix = provider.upper() + "_"
    missing = [prefix + k for k in ("BASE_URL", "MODEL") if not env.get(prefix + k)]
    if missing:
        raise ValueError(f"provider {provider!r} is not configured in .env: missing {', '.join(missing)}")
    for key in ("BASE_URL", "MODEL", "API_KEY"):
        out["OPENAI_" + key] = env.get(prefix + key, "")
    for flag in ("ALLOW_CLOUD", "STRUCTURED_OUTPUT"):
        if prefix + flag in env:
            out[flag] = env[prefix + flag]
    return out


def run(model: str | None, base_url: str | None, pause: float, provider: str | None = None) -> Path:
    load_env()
    env = provider_env(os.environ, provider)
    if model:
        env["OPENAI_MODEL"] = model
    if base_url:
        env["OPENAI_BASE_URL"] = base_url
    config = InferenceConfig.from_env(env)
    client = PatientClient(OpenAICompatibleClient(config), pause)
    cache = DATA / "evals" / re.sub(r"[^A-Za-z0-9._-]+", "_", config.model)
    cache.mkdir(parents=True, exist_ok=True)

    source, pairs = load_pairs()
    by_id = {alert.alert_id: (alert, trigger) for alert, trigger in pairs}
    labels = load_labels(include_spotcheck=True)

    cases = {}
    for n, (alert_id, (label, set_name)) in enumerate(labels.items(), 1):
        alert, trigger = by_id[alert_id]
        bundle = enrich(build_bundle(alert, trigger, source, prior_alerts=[]), NoIntel())
        evidence = score(bundle)
        path = cache / f"{alert_id}.json"
        if path.exists():
            result = JudgeResult.model_validate_json(path.read_text(encoding="utf-8"))
            note = "cached"
        else:
            result = judge(bundle, evidence, client, config)
            # A transport failure is not the model's answer: leave it uncached so a rerun retries it.
            if result.ok or "inference error" not in (result.error or ""):
                path.write_text(result.model_dump_json(indent=1), encoding="utf-8")
            note = f"{result.tokens_used} tokens"
        verdict = result.verdict.verdict if result.ok else f"FAILED ({result.error[:80]})"
        print(f"[{n:>2}/{len(labels)}] {alert_id} {label:<9} -> {verdict} ({note})", flush=True)
        cases[alert_id] = {"alert": alert, "label": label, "set": set_name, "bundle": bundle,
                           "score": evidence, "result": result}

    thresholds = loo_thresholds([
        Row(alert_id=a, rule_title=c["alert"].rule_title, label=c["label"],
            verdict=c["result"].verdict.verdict if c["result"].ok else None,
            confidence=c["result"].verdict.confidence if c["result"].ok else None)
        for a, c in cases.items()])

    for alert_id, c in cases.items():
        rule, threshold = c["alert"].rule_title, thresholds[alert_id]
        policy = VerifyPolicy(high_risk_score=CLOSE_BELOW,
                              close_confidence={rule: threshold} if threshold is not None else {})
        c["threshold"] = threshold
        c["report"] = verify(c["result"], c["bundle"], c["score"], policy)
        c["route"] = route(c["result"], c["report"], RuleMode.SHADOW)

    text = render(cases, config)
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.md"
    out.write_text(text, encoding="utf-8")
    print("\n" + text)
    return out


# --- report -----------------------------------------------------------------

def _closed(method: str, c: dict) -> bool:
    if method == "LLM (judge + verify, shadow)":
        return c["route"].route in CLOSES
    if method == "Evidence score":
        return c["score"].total < CLOSE_BELOW
    return c["alert"].rule_level not in ("high", "critical")   # severity only


METHODS = ("Evidence score", "LLM (judge + verify, shadow)", "Severity only")


def _metrics(cases: list[dict], method: str) -> dict:
    mal = [c for c in cases if c["label"] == "malicious"]
    closed = [c for c in cases if _closed(method, c)]
    caught = sum(1 for c in mal if not _closed(method, c))
    return {"n": len(cases), "mal": len(mal), "caught": caught, "closed": len(closed),
            "mal_closed": sum(1 for c in closed if c["label"] == "malicious"),
            "recall": caught / len(mal) if mal else float("nan"),
            "close_rate": len(closed) / len(cases) if cases else float("nan")}


def _miss_bound(m: dict) -> str:
    """Rule of three: with 0 malicious among n closes, the true miss rate is below 3/n (95%)."""
    if m["closed"] == 0:
        return "no closes"
    if m["mal_closed"] == 0:
        return f"< {3 / m['closed']:.0%}"
    return f"observed {m['mal_closed']}/{m['closed']}"


def render(cases: dict, config: InferenceConfig) -> str:
    allc = list(cases.values())
    lines = [f"# Eval report: {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", "",
             f"Model `{config.model}` at `{config.base_url}`. Scenario: OTRF `empire_mimikatz_logonpasswords`.",
             f"Labelled alerts: {len(allc)} ({sum(c['set'] == 'assisted' for c in allc)} assisted, "
             f"{sum(c['set'] == 'spotcheck' for c in allc)} spot-check; excluded: {', '.join(EXCLUDED)}). "
             "UNSURE labels count as malicious (pre-registered).",
             f"Routing in shadow mode: an LLM close is a `suggest_close`. Verifier policy: high_risk_score = "
             f"CLOSE_BELOW = {CLOSE_BELOW}; close thresholds per rule type by leave-one-out calibration.", ""]

    lines += ["## Headline", "",
              "| Set | Method | n | Malicious | Recall on malicious | Closed | Malicious among closes |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for set_name, subset in (("all", allc), ("assisted", [c for c in allc if c["set"] == "assisted"]),
                             ("spotcheck", [c for c in allc if c["set"] == "spotcheck"])):
        for method in METHODS:
            m = _metrics(subset, method)
            lines.append(f"| {set_name} | {method} | {m['n']} | {m['mal']} | {m['caught']}/{m['mal']} = "
                         f"{m['recall']:.0%} | {m['closed']}/{m['n']} = {m['close_rate']:.0%} | {m['mal_closed']} |")

    llm, base = _metrics(allc, METHODS[1]), _metrics(allc, METHODS[0])
    within = (abs(llm["recall"] - base["recall"]) <= 0.05 or base["recall"] > llm["recall"]) and \
             (abs(llm["close_rate"] - base["close_rate"]) <= 0.05 or base["close_rate"] > llm["close_rate"])
    lines += ["", "## Against the hypothesis and kill conditions", "",
              "| Test | Result |", "| --- | --- |",
              f"| Success: closed >= 50% at recall >= 95% | {'met' if llm['close_rate'] >= .5 and llm['recall'] >= .95 else 'not met'}: "
              f"{llm['close_rate']:.0%} closed at {llm['recall']:.0%} recall |",
              f"| Kill 1: recall below 90% at a meaningful queue reduction | "
              f"{'TRIGGERED' if llm['recall'] < .9 and llm['closed'] > 0 else 'not triggered'}: {llm['recall']:.0%} recall |",
              f"| Kill 2: evidence score within 5 points of the LLM (recall and close rate) | "
              f"{'TRIGGERED' if within else 'not triggered'}: baseline {base['recall']:.0%} recall / {base['close_rate']:.0%} closed "
              f"vs LLM {llm['recall']:.0%} / {llm['close_rate']:.0%} |", ""]

    lines += ["## Per rule type (all labelled)", "",
              "| Rule | n | Malicious | Score closes | Score miss bound | LLM closes | LLM malicious closed | LLM miss bound |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for rule in sorted({c["alert"].rule_title for c in allc}, key=lambda r: -sum(c["alert"].rule_title == r for c in allc)):
        sub = [c for c in allc if c["alert"].rule_title == rule]
        s, m = _metrics(sub, METHODS[0]), _metrics(sub, METHODS[1])
        lines.append(f"| {rule} | {len(sub)} | {m['mal']} | {s['closed']} | {_miss_bound(s)} | {m['closed']} | "
                     f"{m['mal_closed']} | {_miss_bound(m)} |")

    ok = [c for c in allc if c["result"].ok]
    failed_checks = Counter(name for c in allc for name in c["report"].failed)
    tokens = [c["result"].tokens_used for c in allc if c["result"].tokens_used]
    lines += ["", "## LLM diagnostics", "",
              f"- Verdicts: {dict(Counter(c['result'].verdict.verdict for c in ok))}; "
              f"failed results (no verdict): {len(allc) - len(ok)}; needed the retry: "
              f"{sum(c['result'].attempts == 2 and c['result'].ok for c in allc)}.",
              f"- Routes: {dict(Counter(str(c['route'].route) for c in allc))}.",
              f"- Failed checks: {dict(failed_checks) or 'none'}.",
              f"- Tokens per alert (new calls only): mean {sum(tokens) / len(tokens):,.0f}, max {max(tokens):,}."
              if tokens else "- Tokens: all results came from the cache.",
              "", "## Per alert", "",
              "| alert_id | set | rule | label | score | verdict | conf | LOO threshold | route | failed checks |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for a, c in sorted(cases.items(), key=lambda kv: (kv[1]["label"], kv[1]["alert"].rule_title, kv[0])):
        v = c["result"].verdict
        t = c["threshold"]
        lines.append(f"| {a} | {c['set']} | {c['alert'].rule_title} | {c['label']} | {c['score'].total:g} | "
                     f"{v.verdict if v else 'FAILED'} | {v.confidence if v else '-'} | "
                     f"{'never' if t is None else f'{t:.3g}'} | {c['route'].route} | "
                     f"{', '.join(c['report'].failed) or '-'} |")

    lines += ["", "## Caveats", "",
              "- Lab data underestimates benign noise: one scripted attack in a small lab, not a real network.",
              f"- n = {len(allc)} labelled alerts, {base['mal']} malicious. Rule-of-three bounds above are 95% upper bounds.",
              "- 30 of the labels are assisted (Claude-proposed, human-reviewed); the model under test is not Claude.",
              "- The evidence score's signals were chosen after reading label rationales (docs/baseline.md), "
              "and the score is shown to the model as evidence.",
              "- No allowlist and no threat-intel feed: hard overrides on intel never fired.", ""]
    return "\n".join(lines)
