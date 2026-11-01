"""A durable work queue in Postgres, replacing Redis Streams.

At-least-once: a claimed message is leased, not removed. A worker acks it when done; if the
worker dies (or the host sleeps) the lease expires and another claim picks it up again.
Concurrent claims never collide (FOR UPDATE SKIP LOCKED). Higher priority is claimed first.
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

MAX_ATTEMPTS = 5
DEFAULT_LEASE = timedelta(minutes=5)


@dataclass(frozen=True)
class Message:
    id: int
    alert_id: str
    payload: dict[str, Any]
    attempts: int


def enqueue(conn: psycopg.Connection, stream: str, alert_id: str, payload: dict[str, Any],
            priority: int = 0) -> bool:
    """False if this alert is already on this stream (enqueue is idempotent)."""
    row = conn.execute(
        "insert into queue (stream, alert_id, priority, payload) values (%s, %s, %s, %s) "
        "on conflict (stream, alert_id) do nothing returning id",
        (stream, alert_id, priority, Jsonb(payload))).fetchone()
    return row is not None


def claim(conn: psycopg.Connection, stream: str, limit: int = 1,
          lease: timedelta = DEFAULT_LEASE) -> list[Message]:
    rows = conn.execute(
        """
        update queue set status = 'leased', lease_until = now() + %s, attempts = attempts + 1
        where id in (
            select id from queue
            where stream = %s and attempts < %s
              and (status = 'ready' or (status = 'leased' and lease_until < now()))
            order by priority desc, id
            for update skip locked
            limit %s)
        returning id, alert_id, payload, attempts, priority
        """, (lease, stream, MAX_ATTEMPTS, limit)).fetchall()
    rows.sort(key=lambda r: (-r["priority"], r["id"]))
    return [Message(id=r["id"], alert_id=r["alert_id"], payload=r["payload"], attempts=r["attempts"])
            for r in rows]


def ack(conn: psycopg.Connection, message_id: int) -> None:
    conn.execute("update queue set status = 'done', lease_until = null where id = %s", (message_id,))


def pending(conn: psycopg.Connection, stream: str) -> int:
    """Messages not yet done that can still be delivered."""
    return conn.execute("select count(*) as n from queue where stream = %s and status <> 'done' "
                        "and attempts < %s", (stream, MAX_ATTEMPTS)).fetchone()["n"]
