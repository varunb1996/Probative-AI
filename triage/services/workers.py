"""Stream workers: the same pure steps as Architecture A, wired to the Postgres queue.

enrich:  raw      -> context bundle, enrichment, evidence score -> enriched
triage:  enriched -> judge -> verify -> route -> verdict row (+ investigate stream)

A failed step is never acked: its lease expires and it is retried (at most queue.MAX_ATTEMPTS).
One triage thread means at most one inference call in flight.
"""

import logging
import threading
from collections.abc import Callable

import psycopg

from triage.domain import Alert, EvidenceBundle, EvidenceScore, IntelLookup, JudgeResult
from triage.judge.client import ChatClient, CloudRefused, InferenceConfig
from triage.judge.judge import judge
from triage.pipeline.context import build_bundle
from triage.pipeline.enrich import enrich
from triage.pipeline.score import score
from triage.store import queue, repositories as repo
from triage.store.db import connect
from triage.store.event_source import PostgresEventSource
from triage.verify.checks import VerifyPolicy, verify
from triage.verify.router import Route, route

log = logging.getLogger("triage.workers")

RAW, ENRICHED, INVESTIGATE = "raw", "enriched", "investigate"
JudgeFn = Callable[[EvidenceBundle, EvidenceScore], JudgeResult]
PolicyFn = Callable[[Alert], VerifyPolicy]


class NoIntel:
    """No threat-intel feed is synced yet; every lookup misses."""

    def lookup_hash(self, value):
        return None

    def lookup_ip(self, value):
        return None

    def lookup_domain(self, value):
        return None


def model_judge(client: ChatClient, config: InferenceConfig) -> JudgeFn:
    return lambda bundle, evidence: judge(bundle, evidence, client, config)


def enrich_step(conn: psycopg.Connection, msg: queue.Message, intel: IntelLookup) -> None:
    alert, trigger = repo.get_alert(conn, msg.alert_id)
    bundle = enrich(build_bundle(alert, trigger, PostgresEventSource(conn), repo.prior_alerts(conn, alert)), intel)
    evidence = score(bundle)
    priority = conn.execute("select priority from queue where id = %s", (msg.id,)).fetchone()["priority"]
    queue.enqueue(conn, ENRICHED, alert.alert_id,
                  {"bundle": bundle.model_dump(mode="json"), "score": evidence.model_dump(mode="json")},
                  priority=priority)
    queue.ack(conn, msg.id)


def triage_step(conn: psycopg.Connection, msg: queue.Message, judge_fn: JudgeFn, policy_for: PolicyFn) -> Route:
    bundle = EvidenceBundle.model_validate(msg.payload["bundle"])
    evidence = EvidenceScore.model_validate(msg.payload["score"])
    alert_id = bundle.alert.alert_id

    result = judge_fn(bundle, evidence)
    repo.audit(conn, alert_id, "judge", result.model_dump(mode="json"))
    report = verify(result, bundle, evidence, policy_for(bundle.alert))
    repo.audit(conn, alert_id, "verify", report.model_dump(mode="json"))
    decision = route(result, report, repo.get_rule_mode(conn, bundle.alert.rule_title))
    repo.upsert_verdict(conn, alert_id, result, evidence.model_dump(mode="json"), report.model_dump(mode="json"),
                        str(decision.route), decision.reasons)
    repo.audit(conn, alert_id, "route", decision.model_dump(mode="json"))
    if decision.route == Route.INVESTIGATE:
        queue.enqueue(conn, INVESTIGATE, alert_id, msg.payload)
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
          intel: IntelLookup | None = None) -> None:
    """Process both streams until nothing is ready. Used by the gate and by a one-shot run."""
    intel = intel or NoIntel()
    while (run_once(conn, RAW, lambda m: enrich_step(conn, m, intel))
           or run_once(conn, ENRICHED, lambda m: triage_step(conn, m, judge_fn, policy_for))):
        pass


def start(url: str, judge_fn: JudgeFn, policy_for: PolicyFn, stop: threading.Event,
          poll_seconds: float) -> list[threading.Thread]:
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
                         args=(ENRICHED, lambda c: (lambda m: triage_step(c, m, judge_fn, policy_for)))),
    ]
    for t in threads:
        t.start()
    return threads
