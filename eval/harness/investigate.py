"""Phase 5 gate: the investigator vs escalating straight to a human, on the labelled alerts the
recorded Phase 3c run routed to investigate. Published whatever it shows.

Investigations are cached per model in data/evals/<model>/investigations/, so a run cut off by
rate limits resumes. One that hit an inference error is not cached and is retried next run.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from eval.harness.calibrate import loo_thresholds
from eval.harness.dataset import DATA, load_labels
from eval.harness.jsonl_source import JsonlEventSource, NoIntel
from eval.harness.run import REPORTS, PatientClient, load_env, provider_env
from eval.harness.stack import _policy, _rows, cache_dir, replay_judge
from triage.domain import Investigation, RuleMode
from triage.investigate.decide import model_decide
from triage.investigate.loop import run_investigation
from triage.judge.client import InferenceConfig, OpenAICompatibleClient
from triage.pipeline.context import build_bundle
from triage.pipeline.score import score
from triage.services.ingest import read_scenario
from triage.verify.checks import verify
from triage.verify.router import Route, route, route_investigation


@dataclass(frozen=True)
class Outcome:
    alert_id: str
    label: str
    route: str          # the investigator's final route
    tokens: int


def compare(rows: list[Outcome]) -> dict[str, dict]:
    """Recall on malicious, closes and tokens for the investigator and for escalate-to-human."""
    mal = [r for r in rows if r.label == "malicious"]

    def metrics(closed_ids: set[str], tokens: int) -> dict:
        caught = sum(1 for r in mal if r.alert_id not in closed_ids)
        return {"n": len(rows), "malicious": len(mal), "recall": caught / len(mal) if mal else float("nan"),
                "closed": len(closed_ids), "malicious_closed": sum(1 for r in mal if r.alert_id in closed_ids),
                "tokens": tokens}

    closes = {r.alert_id for r in rows if r.route in (Route.SUGGEST_CLOSE, Route.AUTO_CLOSE)}
    return {"Escalate to a human": metrics(set(), 0), "Investigator": metrics(closes, sum(r.tokens for r in rows))}


def investigate(provider: str | None, pause: float) -> Path:
    load_env()
    env = provider_env(os.environ, provider)
    config = InferenceConfig.from_env(env)
    plain = config.model_copy(update={"structured_output": False, "json_mode": True})
    decide = model_decide(PatientClient(OpenAICompatibleClient(plain), pause), plain)
    recorded = cache_dir(provider)
    judge_fn = replay_judge(recorded)
    store = recorded / "investigations"
    store.mkdir(parents=True, exist_ok=True)

    _, pairs = read_scenario(DATA)
    labels = load_labels(include_spotcheck=True)
    labelled = {a.alert_id: (a, t) for a, t in pairs if a.alert_id in labels}
    source = JsonlEventSource(DATA / "events.jsonl")
    bundles = {aid: build_bundle(a, t, source, prior_alerts=[]) for aid, (a, t) in labelled.items()}
    thresholds = loo_thresholds(_rows(labels, {aid: a for aid, (a, _) in labelled.items()}, judge_fn, bundles))

    rows, invs = [], {}
    for alert_id, bundle in bundles.items():
        evidence = score(bundle)
        report = verify(judge_fn(bundle, evidence), bundle, evidence, _policy(thresholds, bundle.alert))
        if route(judge_fn(bundle, evidence), report, RuleMode.SHADOW).route != Route.INVESTIGATE:
            continue
        path = store / f"{alert_id}.json"
        if path.exists():
            inv = Investigation.model_validate_json(path.read_text(encoding="utf-8"))
            note = "cached"
        else:
            inv = run_investigation(bundle, evidence, decide, source, NoIntel(), _policy(thresholds, bundle.alert))
            if not any((q.error or "").startswith("inference error") for q in inv.state.query_log):
                path.write_text(inv.model_dump_json(indent=1), encoding="utf-8")
            note = f"{inv.state.tokens_used} tokens"
        decision = route_investigation(inv, RuleMode.SHADOW)
        label = labels[alert_id][0]
        print(f"{alert_id} {label:<9} -> {decision.route} ({inv.stop_reason}; {inv.state.step_count} steps; {note})",
              flush=True)
        rows.append(Outcome(alert_id, label, str(decision.route), inv.state.tokens_used))
        invs[alert_id] = (inv, decision, labelled[alert_id][0].rule_title)

    text = _render(rows, invs, config)
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / f"investigator-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.md"
    out.write_text(text, encoding="utf-8")
    print("\n" + text)
    return out


def _pct(x: float) -> str:
    return "n/a" if x != x else f"{x:.0%}"


def _render(rows: list[Outcome], invs: dict, config: InferenceConfig) -> str:
    table = compare(rows)
    lines = [f"# Investigator report: {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", "",
             f"Model `{config.model}` at `{config.base_url}`. Alerts: the {len(rows)} labelled alerts the recorded "
             "Phase 3c run routed to investigate (suspicious, insufficient context). Read-only tools, at most 6 steps, "
             "the same verifier; shadow mode, so a close is a suggestion to a human.", "",
             "| Method | n | Malicious | Recall on malicious | Closed | Malicious among closes | Tokens |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for name, m in table.items():
        lines.append(f"| {name} | {m['n']} | {m['malicious']} | {_pct(m['recall'])} | {m['closed']} | "
                     f"{m['malicious_closed']} | {m['tokens']:,} |")
    inv, human = table["Investigator"], table["Escalate to a human"]
    lines += ["", "## Verdict on the gate", "",
              f"- Recall: investigator {_pct(inv['recall'])} vs escalate-to-human {_pct(human['recall'])}.",
              f"- Analyst work saved: {inv['closed']} of {len(rows)} alerts suggested for close, "
              f"{inv['malicious_closed']} of them malicious.",
              f"- Cost: {inv['tokens']:,} tokens ({inv['tokens'] // max(len(rows), 1):,} per alert).",
              "- Escalating straight to a human is the baseline the investigator has to beat: it misses nothing "
              "and costs nothing, but saves no analyst time.", "", "## Per alert", ""]
    for alert_id, (investigation, decision, rule) in invs.items():
        label = next(r.label for r in rows if r.alert_id == alert_id)
        lines.append(f"### {alert_id} · {rule} · label {label} → {decision.route}")
        lines.append(f"Stopped: {investigation.stop_reason}; {investigation.state.step_count} steps, "
                     f"{investigation.state.tokens_used:,} tokens.")
        for n, q in enumerate(investigation.state.query_log, 1):
            outcome = f"rejected: {q.error}" if q.error else f"+{len(q.result_event_ids)} events {' '.join(q.intel)}"
            lines.append(f"{n}. `{q.tool}` {q.arguments} → {outcome}")
        if investigation.result and investigation.result.verdict:
            v = investigation.result.verdict
            lines.append(f"\nVerdict: {v.verdict} ({v.confidence}). {v.summary}")
        lines.append("")
    lines += ["## Caveats", "",
              "- n is tiny (the alerts one recorded run sent to investigate); treat this as a smoke test of the "
              "loop, not a measurement.",
              "- One lab scenario; no threat-intel feed, so entity_lookup can only ever miss.", ""]
    return "\n".join(lines)
