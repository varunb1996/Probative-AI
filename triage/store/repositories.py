"""One function group per table. Upserts keyed by alert_id; the audit log only appends."""

from datetime import timedelta
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from triage.domain import Alert, Event, JudgeResult, PriorAlert, RuleMode
from triage.pipeline.process import actor_process, parent_process


# --- events -----------------------------------------------------------------

def upsert_events(conn: psycopg.Connection, events: list[Event], case_id: str | None = None) -> None:
    """Insert events in order, indexing each by its acting and parent process."""
    refs = [(actor_process(e), parent_process(e)) for e in events]
    with conn.cursor() as cur:
        cur.executemany(
            "insert into events (event_id, host, ts, channel, event_code, actor_pid, actor_guid, "
            "parent_pid, parent_guid, fields, case_id) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "on conflict (event_id) do nothing",
            [(e.event_id, e.host, e.timestamp, e.fields.get("Channel"), e.fields.get("EventID"),
              actor.pid if actor else None, actor.guid if actor else None,
              parent.pid if parent else None, parent.guid if parent else None, Jsonb(e.fields), case_id)
             for e, (actor, parent) in zip(events, refs)])


def row_to_event(row: dict[str, Any]) -> Event:
    return Event(event_id=row["event_id"], host=row["host"], timestamp=row["ts"], fields=row["fields"])


# --- alerts -----------------------------------------------------------------

def upsert_alert(conn: psycopg.Connection, alert: Alert, trigger_event_id: str, case_id: str | None = None) -> None:
    conn.execute(
        "insert into alerts (alert_id, rule_title, host, ts, trigger_event_id, alert, case_id) "
        "values (%s, %s, %s, %s, %s, %s, %s) on conflict (alert_id) do update set "
        "rule_title = excluded.rule_title, host = excluded.host, ts = excluded.ts, "
        "trigger_event_id = excluded.trigger_event_id, alert = excluded.alert, case_id = excluded.case_id",
        (alert.alert_id, alert.rule_title, alert.host, alert.timestamp, trigger_event_id,
         Jsonb(alert.model_dump(mode="json")), case_id))


def alert_case(conn: psycopg.Connection, alert_id: str) -> str | None:
    row = conn.execute("select case_id from alerts where alert_id = %s", (alert_id,)).fetchone()
    return row["case_id"] if row else None


def get_alert(conn: psycopg.Connection, alert_id: str) -> tuple[Alert, Event]:
    row = conn.execute(
        "select a.alert, e.event_id, e.host, e.ts, e.fields from alerts a "
        "join events e on e.event_id = a.trigger_event_id where a.alert_id = %s", (alert_id,)).fetchone()
    if row is None:
        raise KeyError(alert_id)
    return Alert.model_validate(row["alert"]), row_to_event(row)


def prior_alerts(conn: psycopg.Connection, alert: Alert) -> list[PriorAlert]:
    """Earlier alerts on the same host. An accepted suggested close is a human-confirmed benign."""
    rows = conn.execute(
        "select a.alert, d.decision from alerts a left join human_decisions d on d.alert_id = a.alert_id "
        "where a.host = %s and a.ts < %s and a.alert_id <> %s "
        "and a.case_id is not distinct from (select case_id from alerts where alert_id = %s) order by a.ts",
        (alert.host, alert.timestamp, alert.alert_id, alert.alert_id)).fetchall()
    return [PriorAlert(alert=Alert.model_validate(r["alert"]),
                       verdict="benign" if r["decision"] == "accept" else None,
                       human_confirmed=r["decision"] == "accept") for r in rows]


# --- verdicts ---------------------------------------------------------------

def upsert_verdict(conn: psycopg.Connection, alert_id: str, result: JudgeResult, score: dict,
                   report: dict, route: str, reasons: list[str]) -> None:
    conn.execute(
        "insert into verdicts (alert_id, judge_result, score, report, route, reasons) "
        "values (%s, %s, %s, %s, %s, %s) on conflict (alert_id) do update set "
        "judge_result = excluded.judge_result, score = excluded.score, report = excluded.report, "
        "route = excluded.route, reasons = excluded.reasons, updated_at = now()",
        (alert_id, Jsonb(result.model_dump(mode="json")), Jsonb(score), Jsonb(report), route, Jsonb(reasons)))


def get_verdict(conn: psycopg.Connection, alert_id: str) -> dict[str, Any] | None:
    return conn.execute("select * from verdicts where alert_id = %s", (alert_id,)).fetchone()


def list_by_route(conn: psycopg.Connection, routes: list[str], undecided_only: bool = True,
                  case_id: str | None = None) -> list[dict]:
    """Alerts of one case (None: the demo) whose route is one of `routes`, newest first."""
    return conn.execute(
        "select a.alert_id, a.rule_title, a.host, a.ts, v.route, v.reasons, v.score, v.judge_result, "
        "d.decision, d.analyst from verdicts v join alerts a on a.alert_id = v.alert_id "
        "left join human_decisions d on d.alert_id = v.alert_id "
        "where v.route = any(%s) and (not %s or d.alert_id is null) and a.case_id is not distinct from %s "
        "order by a.ts desc",
        (routes, undecided_only, case_id)).fetchall()


# --- human decisions and rule modes -----------------------------------------

def record_decision(conn: psycopg.Connection, alert_id: str, decision: str, analyst: str) -> None:
    conn.execute(
        "insert into human_decisions (alert_id, decision, analyst, human_confirmed) values (%s, %s, %s, true) "
        "on conflict (alert_id) do update set decision = excluded.decision, analyst = excluded.analyst, "
        "human_confirmed = true, decided_at = now()", (alert_id, decision, analyst))


def get_rule_mode(conn: psycopg.Connection, rule_title: str) -> RuleMode:
    row = conn.execute("select mode from rule_modes where rule_title = %s", (rule_title,)).fetchone()
    return RuleMode(row["mode"]) if row else RuleMode.SHADOW


def set_rule_mode(conn: psycopg.Connection, rule_title: str, mode: RuleMode) -> None:
    conn.execute("insert into rule_modes (rule_title, mode) values (%s, %s) "
                 "on conflict (rule_title) do update set mode = excluded.mode", (rule_title, str(mode)))


# --- audit ------------------------------------------------------------------

def audit(conn: psycopg.Connection, alert_id: str | None, kind: str, payload: dict[str, Any],
          case_id: str | None = None) -> None:
    conn.execute("insert into audit_log (alert_id, case_id, kind, payload) values (%s, %s, %s, %s)",
                 (alert_id, case_id, kind, Jsonb(payload)))


def llm_calls_today(conn: psycopg.Connection) -> int:
    """Judge calls that reached a model since UTC midnight (replays and skips spend no tokens)."""
    return conn.execute(
        "select count(*) as n from audit_log where kind = 'judge' "
        "and at >= date_trunc('day', now() at time zone 'utc') at time zone 'utc' "
        "and coalesce((payload->>'tokens_used')::int, 0) > 0").fetchone()["n"]


# --- sandbox cases ----------------------------------------------------------

def create_case(conn: psycopg.Connection, case_id: str, source: str, name: str, client: str,
                ttl: timedelta) -> None:
    conn.execute("insert into cases (case_id, source, name, client, expires_at) values (%s, %s, %s, %s, now() + %s)",
                 (case_id, source, name, client, ttl))


def get_case(conn: psycopg.Connection, case_id: str) -> dict[str, Any] | None:
    return conn.execute("select * from cases where case_id = %s", (case_id,)).fetchone()


_CASE_FIELDS = {"status", "detail", "n_events", "n_alerts"}


def update_case(conn: psycopg.Connection, case_id: str, **fields: Any) -> None:
    unknown = set(fields) - _CASE_FIELDS
    if unknown:
        raise ValueError(f"not updatable: {sorted(unknown)}")
    sets = ", ".join(f"{name} = %s" for name in fields)
    conn.execute(f"update cases set {sets} where case_id = %s", (*fields.values(), case_id))


def take_llm_slot(conn: psycopg.Connection, case_id: str, per_case: int) -> bool:
    """Atomically reserve one LLM judgment for the case. False once `per_case` are used."""
    return conn.execute("update cases set llm_used = llm_used + 1 where case_id = %s and llm_used < %s "
                        "returning llm_used", (case_id, per_case)).fetchone() is not None


def cases_since(conn: psycopg.Connection, client: str, window: timedelta) -> int:
    return conn.execute("select count(*) as n from cases where client = %s and created_at > now() - %s",
                        (client, window)).fetchone()["n"]


def expired_cases(conn: psycopg.Connection) -> list[str]:
    return [r["case_id"] for r in conn.execute(
        "select case_id from cases where expires_at < now() order by created_at").fetchall()]


def delete_case(conn: psycopg.Connection, case_id: str) -> None:
    """Remove a case and everything derived from it. Its audit rows go when retention allows."""
    alerts = "select alert_id from alerts where case_id = %s"
    with conn.transaction():
        conn.execute(f"delete from human_decisions where alert_id in ({alerts})", (case_id,))
        conn.execute(f"delete from verdicts where alert_id in ({alerts})", (case_id,))
        conn.execute(f"delete from queue where alert_id in ({alerts})", (case_id,))
        conn.execute("delete from alerts where case_id = %s", (case_id,))
        conn.execute("delete from events where case_id = %s", (case_id,))
        conn.execute("delete from cases where case_id = %s", (case_id,))
    conn.execute("delete from audit_log where case_id = %s and at < now() - interval '24 hours'", (case_id,))
