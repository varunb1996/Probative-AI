"""Postgres connections and schema. Autocommit: every statement stands alone."""

from pathlib import Path

import psycopg
from psycopg.rows import dict_row

SCHEMA = Path(__file__).with_name("schema.sql")
TABLES = ("queue", "audit_log", "human_decisions", "verdicts", "investigations", "rule_modes", "alerts", "events",
          "cases")


def connect(url: str) -> psycopg.Connection:
    return psycopg.connect(url, autocommit=True, row_factory=dict_row, connect_timeout=30)


def apply_schema(conn: psycopg.Connection) -> None:
    conn.execute(SCHEMA.read_text(encoding="utf-8"))


def reset(conn: psycopg.Connection) -> None:
    """Drop and recreate every table. Only ever pointed at a test database."""
    conn.execute(f"drop table if exists {', '.join(TABLES)} cascade")
    apply_schema(conn)
