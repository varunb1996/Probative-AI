"""Stream workers: the same pure steps as Architecture A, wired to the Postgres queue.

enrich:  raw      -> context bundle, enrichment, evidence score -> enriched
triage:  enriched -> judge -> verify -> route -> verdict row (+ investigate stream)

A failed step is never acked: its lease expires and it is retried (at most queue.MAX_ATTEMPTS).
One triage thread means at most one inference call in flight.
"""

import logging
import threading
import time
from collections.abc import Callable

import psycopg

from triage.domain import Alert, EvidenceBundle, EvidenceScore, IntelLookup, JudgeResult
from triage.investigate.loop import Decide, run_investigation
from triage.judge.client import ChatClient, CloudRefused, Completion, InferenceConfig, RateLimited
from triage.judge.judge import judge
from triage.pipeline.context import build_bundle
from triage.pipeline.enrich import enrich
from triage.pipeline.score import score
from triage.store import queue, repositories as repo
from triage.store.db import connect
from triage.store.event_source import PostgresEventSource
from triage.verify.checks import VerifyPolicy, verify
from triage.verify.router import Route, route, route_investigation

log = logging.getLogger("triage.workers")

RAW, ENRICHED, INVESTIGATE = "raw", "enriched", "investigate"
JudgeFn = Callable[[EvidenceBundle, EvidenceScore], JudgeResult]
PolicyFn = Callable[[Alert], VerifyPolicy]
GateFn = Callable[[psycopg.Connection, str | None], str | None]   # (conn, case_id) -> reason to skip the LLM


class NoIntel:
    """No threat-intel feed is synced yet; every lookup misses."""

    def lookup_hash(self, value):
        return None

    def lookup_ip(self, value):
        return None

    def lookup_domain(self, value):
        return None


RATE_LIMIT_WAITS = (10, 20, 40)


class PatientClient:
    """Waits and resends on HTTP 429 only. Not the judge's single retry on invalid output."""

    def __init__(self, inner: ChatClient):
        self.inner = inner

    def complete(self, messages: list[dict], schema: dict) -> Completion:
        for wait in (*RATE_LIMIT_WAITS, None):
            try:
                return self.inner.complete(messages, schema)
            except RateLimited:
                if wait is None:
                    raise
                log.info("rate limited; waiting %ss", wait)
                time.sleep(wait)
        raise AssertionError("unreachable")


def model_judge(client: ChatClient, config: InferenceConfig) -> JudgeFn:
    patient = PatientClient(client)
    return lambda bundle, evidence: judge(bundle, evidence, patient, config)


def enrich_step(conn: psycopg.Connection, msg: queue.Message, intel: IntelLookup) -> None:
    alert, trigger = repo.get_alert(conn, msg.alert_id)
    source = PostgresEventSource(conn, repo.alert_case(conn, msg.alert_id))
    bundle = enrich(build_bundle(alert, trigger, source, repo.prior_alerts(conn, alert)), intel)
    evidence = score(bundle)
    priority = conn.execute("select priority from queue where id = %s", (msg.id,)).fetchone()["priority"]
    queue.enqueue(conn, ENRICHED, alert.alert_id,
                  {"bundle": bundle.model_dump(mode="json"), "score": evidence.model_dump(mode="json")},
                  priority=priority)
    queue.ack(conn, msg.id)


def triage_step(conn: psycopg.Connection, msg: queue.Message, judge_fn: JudgeFn, policy_for: PolicyFn,
                gate: GateFn | None = None) -> Route:
    bundle = EvidenceBundle.model_validate(msg.payload["bundle"])
    evidence = EvidenceScore.model_validate(msg.payload["score"])
    alert_id = bundle.alert.alert_id
    case_id = repo.alert_case(conn, alert_id)

    skip = gate(conn, case_id) if gate else None
    if skip:   # no verdict, so the verifier escalates it; it is never treated as benign
        result = JudgeResult(alert_id=alert_id, attempts=0, error=f"AI not run: {skip}", shown_event_ids=[])
    else:
        result = judge_fn(bundle, evidence)
    repo.audit(conn, alert_id, "judge", result.model_dump(mode="json"), case_id=case_id)
    report = verify(result, bundle, evidence, policy_for(bundle.alert))
    repo.audit(conn, alert_id, "verify", report.model_dump(mode="json"), case_id=case_id)
    decision = route(result, report, repo.get_rule_mode(conn, bundle.alert.rule_title))
    repo.upsert_verdict(conn, alert_id, result, evidence.model_dump(mode="json"), report.model_dump(mode="json"),
                        str(decision.route), decision.reasons)
    repo.audit(conn, alert_id, "route", decision.model_dump(mode="json"), case_id=case_id)
    if decision.route == Route.INVESTIGATE:
        queue.enqueue(conn, INVESTIGATE, alert_id, msg.payload)
    queue.ack(conn, msg.id)
    return decision.route


INVESTIGATIONS_PER_DAY = 5   # each can make up to 6 model calls; protects the free model allowance


def investigate_step(conn: psycopg.Connection, msg: queue.Message, decide: Decide, policy_for: PolicyFn,
                     daily_cap: int = INVESTIGATIONS_PER_DAY) -> Route:
    """Run the bounded investigator on one alert routed to investigate, then re-route it.
    Sandbox alerts and alerts past the daily cap go straight to a human."""
    bundle = EvidenceBundle.model_validate(msg.payload["bundle"])
    evidence = EvidenceScore.model_validate(msg.payload["score"])
    alert_id = bundle.alert.alert_id
    case_id = repo.alert_case(conn, alert_id)

    if case_id is not None:
        reason = "investigation not run in the sandbox; stays with the analyst"
    elif repo.investigations_today(conn) >= daily_cap:
        reason = "daily investigation budget used; stays with the analyst"
    else:
        reason = None
    if reason:
        repo.update_route(conn, alert_id, str(Route.ESCALATE), [reason])
        repo.audit(conn, alert_id, "route", {"route": str(Route.ESCALATE), "reasons": [reason]}, case_id=case_id)
        queue.ack(conn, msg.id)
        return Route.ESCALATE

    investigation = run_investigation(bundle, evidence, decide, PostgresEventSource(conn, case_id), NoIntel(),
                                      policy_for(bundle.alert))
    repo.upsert_investigation(conn, investigation)
    repo.audit(conn, alert_id, "investigation", {"verified": investigation.verified,
                                                 "stop_reason": investigation.stop_reason,
                                                 "steps": investigation.state.step_count,
                                                 "tokens_used": investigation.state.tokens_used}, case_id=case_id)
    decision = route_investigation(investigation, repo.get_rule_mode(conn, bundle.alert.rule_title))
    repo.update_route(conn, alert_id, str(decision.route), decision.reasons)
    repo.audit(conn, alert_id, "route", decision.model_dump(mode="json"), case_id=case_id)
    queue.ack(conn, msg.id)
    return decision.route


def run_once(conn: psycopg.Connection, stream: str, step: Callable[[queue.Message], object]) -> bool:
    """Claim and process one message. False when the stream had nothing ready."""
    batch = queue.claim(conn, stream)
    for msg in batch:
        try:
            step(msg)
        except CloudRefused:
            raise   # a configuration error: stop the worker rather than retry
        except Exception:   # noqa: BLE001 - logged; the message stays leased and is retried, never closed
            log.exception("step failed on %s message %s (attempt %s); left for retry", stream, msg.alert_id,
                          msg.attempts)
    return bool(batch)


def drain(conn: psycopg.Connection, judge_fn: JudgeFn, policy_for: PolicyFn,
          intel: IntelLookup | None = None, gate: GateFn | None = None) -> None:
    """Process both streams until nothing is ready. Used by the gate and by a one-shot run."""
    intel = intel or NoIntel()
    while (run_once(conn, RAW, lambda m: enrich_step(conn, m, intel))
           or run_once(conn, ENRICHED, lambda m: triage_step(conn, m, judge_fn, policy_for, gate))):
        pass


def start(url: str, judge_fn: JudgeFn, policy_for: PolicyFn, stop: threading.Event,
          poll_seconds: float, gate: GateFn | None = None, decide: Decide | None = None) -> list[threading.Thread]:
    """One enrich thread and one triage thread, each with its own connection."""
    def loop(stream: str, make_step):
        with connect(url) as conn:
            step = make_step(conn)
            while not stop.is_set():
                try:
                    busy = run_once(conn, stream, step)
                except CloudRefused:
                    log.exception("cloud refused; %s worker stopping", stream)
                    return
                if not busy:
                    stop.wait(poll_seconds)

    threads = [
        threading.Thread(target=loop, name="enrich", daemon=True,
                         args=(RAW, lambda c: (lambda m: enrich_step(c, m, NoIntel()))) ),
        threading.Thread(target=loop, name="triage", daemon=True,
                         args=(ENRICHED, lambda c: (lambda m: triage_step(c, m, judge_fn, policy_for, gate)))),
    ]
    if decide is not None:
        threads.append(threading.Thread(target=loop, name="investigate", daemon=True,
                                        args=(INVESTIGATE, lambda c: (lambda m: investigate_step(c, m, decide, policy_for)))))
    for t in threads:
        t.start()
    return threads
