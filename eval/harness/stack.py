"""Phase 4 gate: the split changes deployment, not behaviour.

Runs ingest + workers against the test database with a replay judge (the recorded Phase 3c
results, no model calls) and compares every labelled alert's route and evidence score with
the in-process path (JSONL source, same replay, same leave-one-out policy).
"""

import json
import os
import re
from pathlib import Path

from eval.harness.calibrate import Row, fit_thresholds, loo_thresholds
from eval.harness.dataset import DATA, load_labels
from eval.harness.jsonl_source import JsonlEventSource
from eval.harness.run import load_env, provider_env
from triage.domain import EvidenceBundle, EvidenceScore, JudgeResult, RuleMode
from triage.judge.client import InferenceConfig
from triage.pipeline.context import build_bundle
from triage.pipeline.score import CLOSE_BELOW, score
from triage.services import workers
from triage.services.config import load_policy
from triage.services.ingest import ingest, read_scenario
from triage.store import repositories as repo
from triage.store.db import connect, reset
from triage.verify.checks import VerifyPolicy, verify
from triage.verify.router import route

POLICY_FILE = Path("config") / "policy.json"


def cache_dir(provider: str | None) -> Path:
    model = InferenceConfig.from_env(provider_env(os.environ, provider)).model
    return DATA / "evals" / re.sub(r"[^A-Za-z0-9._-]+", "_", model)


def replay_judge(cache: Path):
    """A judge that returns the recorded result, or a failure if none was recorded."""
    def judge_fn(bundle: EvidenceBundle, evidence: EvidenceScore) -> JudgeResult:
        path = cache / f"{bundle.alert.alert_id}.json"
        if path.exists():
            return JudgeResult.model_validate_json(path.read_text(encoding="utf-8"))
        return JudgeResult(alert_id=bundle.alert.alert_id, attempts=0, shown_event_ids=[],
                           error="no recorded result (the recorded run failed for this alert)")
    return judge_fn


def _rows(labels: dict, alerts: dict, judge_fn, bundles: dict) -> list[Row]:
    rows = []
    for alert_id, (label, _) in labels.items():
        r = judge_fn(bundles[alert_id], EvidenceScore(total=0, contributions={}))
        rows.append(Row(alert_id=alert_id, rule_title=alerts[alert_id].rule_title, label=label,
                        verdict=r.verdict.verdict if r.ok else None,
                        confidence=r.verdict.confidence if r.ok else None))
    return rows


def _policy(thresholds: dict, alert) -> VerifyPolicy:
    t = thresholds[alert.alert_id]
    return VerifyPolicy(high_risk_score=CLOSE_BELOW, close_confidence={alert.rule_title: t} if t is not None else {})


def stack(provider: str | None) -> int:
    load_env()
    test_url, live_url = os.environ.get("TEST_DATABASE_URL"), os.environ.get("DATABASE_URL")
    if not test_url:
        raise SystemExit("TEST_DATABASE_URL is not set")
    if test_url == live_url:
        raise SystemExit("TEST_DATABASE_URL equals DATABASE_URL; refusing to wipe the live database")
    cache = cache_dir(provider)
    judge_fn = replay_judge(cache)

    events, pairs = read_scenario(DATA)
    labels = load_labels(include_spotcheck=True)
    labelled = [(a, t) for a, t in pairs if a.alert_id in labels]
    alerts = {a.alert_id: a for a, _ in labelled}

    # In-process path (Architecture A).
    source = JsonlEventSource(DATA / "events.jsonl")
    local = {a.alert_id: build_bundle(a, t, source, prior_alerts=[]) for a, t in labelled}
    thresholds = loo_thresholds(_rows(labels, alerts, judge_fn, local))
    expected = {}
    for alert_id, bundle in local.items():
        evidence = score(bundle)
        result = judge_fn(bundle, evidence)
        report = verify(result, bundle, evidence, _policy(thresholds, bundle.alert))
        expected[alert_id] = (str(route(result, report, RuleMode.SHADOW).route), evidence.total)

    # Split path (Architecture B): Postgres, queue, workers.
    print(f"replaying {cache} through the stack on the test database ...", flush=True)
    with connect(test_url) as conn:
        reset(conn)
        ingest(conn, events, labelled)
        workers.drain(conn, judge_fn, lambda alert: _policy(thresholds, alert))
        got = {}
        for alert_id in labels:
            v = repo.get_verdict(conn, alert_id)
            got[alert_id] = (v["route"], v["score"]["total"]) if v else ("missing", None)

    diffs = [(a, expected[a], got[a]) for a in labels if expected[a] != got[a]]
    print(f"\n| alert_id | in-process (route, score) | stack (route, score) |\n| --- | --- | --- |")
    for alert_id in sorted(labels):
        mark = " **DIFF**" if expected[alert_id] != got[alert_id] else ""
        print(f"| {alert_id} | {expected[alert_id]} | {got[alert_id]}{mark} |")
    print(f"\nlabelled alerts: {len(labels)}; route or score differences: {len(diffs)}")
    return len(diffs)


def seed(provider: str | None) -> int:
    """Fill the live database (DATABASE_URL) for the demo: the labelled alerts, routed with the recorded
    results and the production policy. No model calls and no reset; enqueueing is idempotent."""
    load_env()
    judge_fn = replay_judge(cache_dir(provider))
    events, pairs = read_scenario(DATA)
    labels = load_labels(include_spotcheck=True)
    labelled = [(a, t) for a, t in pairs if a.alert_id in labels]
    policy = load_policy(os.environ)
    with connect(os.environ["DATABASE_URL"]) as conn:
        queued = ingest(conn, events, labelled, policy.critical_hosts)
        workers.drain(conn, judge_fn, lambda alert: policy)
    return queued


def calibrate(provider: str | None) -> Path:
    """Fit production close thresholds on every labelled alert and write config/policy.json."""
    load_env()
    cache = cache_dir(provider)
    judge_fn = replay_judge(cache)
    _, pairs = read_scenario(DATA)
    labels = load_labels(include_spotcheck=True)
    alerts = {a.alert_id: a for a, _ in pairs if a.alert_id in labels}
    bundles = {a.alert_id: EvidenceBundle(alert=a, events=[t]) for a, t in pairs if a.alert_id in labels}
    thresholds = fit_thresholds(_rows(labels, alerts, judge_fn, bundles))
    POLICY_FILE.parent.mkdir(exist_ok=True)
    POLICY_FILE.write_text(json.dumps({
        "note": f"Close thresholds per rule type, fitted on {len(labels)} labelled alerts from the recorded "
                f"run in {cache.as_posix()}. Rule types not listed can never close.",
        "close_confidence": thresholds}, indent=2) + "\n", encoding="utf-8")
    return POLICY_FILE
