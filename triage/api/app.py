"""FastAPI app: the analyst queues, human decisions, and (optionally) the workers in-process.

    uvicorn --factory triage.api.app:create_app

On a free host the workers run as threads in this process (RUN_WORKERS=true); they talk to
each other only through the Postgres queue, so they can move to their own services unchanged.
"""

import os
import threading
from collections.abc import Iterator
from contextlib import asynccontextmanager
from typing import Literal

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from triage.api import pages
from triage.api.auth import token_ok
from triage.judge.client import OpenAICompatibleClient
from triage.services import workers
from triage.services.config import Settings, inference_config, load_dotenv, load_policy
from triage.store import queue, repositories as repo
from triage.store.db import apply_schema, connect

ANALYST_ROUTES = ["escalate", "investigate"]
SUGGESTION_ROUTES = ["suggest_close"]


class DecisionIn(BaseModel):
    decision: Literal["accept", "reject"]
    analyst: str = Field(min_length=1, max_length=100)


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        load_dotenv()
        settings = Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with connect(settings.database_url) as conn:
            apply_schema(conn)
        stop = threading.Event()
        if settings.run_workers:
            config = inference_config(os.environ)
            policy = load_policy(os.environ)
            workers.start(settings.database_url, workers.model_judge(OpenAICompatibleClient(config), config),
                          lambda alert: policy, stop, settings.poll_seconds)
        yield
        stop.set()

    app = FastAPI(title="Probative AI", lifespan=lifespan)

    def get_conn() -> Iterator[psycopg.Connection]:
        with connect(settings.database_url) as conn:
            yield conn

    def require_token(authorization: str | None = Header(default=None)) -> None:
        if not settings.api_token:
            raise HTTPException(503, "writes are disabled: API_TOKEN is not configured")
        if not token_ok(authorization, settings.api_token):
            raise HTTPException(401, "a valid bearer token is required")

    def detail(conn: psycopg.Connection, alert_id: str) -> dict:
        try:
            alert, trigger = repo.get_alert(conn, alert_id)
        except KeyError:
            raise HTTPException(404, "unknown alert") from None
        decision = conn.execute("select decision, analyst, decided_at from human_decisions where alert_id = %s",
                                (alert_id,)).fetchone()
        return jsonable_encoder({"alert": alert.model_dump(mode="json"), "verdict": repo.get_verdict(conn, alert_id),
                                 "decision": decision, "trigger_event": trigger.model_dump(mode="json")})

    @app.get("/health")
    def health(conn: psycopg.Connection = Depends(get_conn)) -> dict:
        streams = (workers.RAW, workers.ENRICHED, workers.INVESTIGATE)
        return {"status": "ok", "pending": {s: queue.pending(conn, s) for s in streams}}

    @app.get("/api/queue")
    def analyst_queue(conn: psycopg.Connection = Depends(get_conn)) -> list[dict]:
        return jsonable_encoder(repo.list_by_route(conn, ANALYST_ROUTES))

    @app.get("/api/suggestions")
    def suggestions(conn: psycopg.Connection = Depends(get_conn)) -> list[dict]:
        return jsonable_encoder(repo.list_by_route(conn, SUGGESTION_ROUTES))

    @app.get("/api/alerts/{alert_id}")
    def alert_json(alert_id: str, conn: psycopg.Connection = Depends(get_conn)) -> dict:
        return detail(conn, alert_id)

    @app.post("/api/alerts/{alert_id}/decision", dependencies=[Depends(require_token)])
    def decide(alert_id: str, body: DecisionIn, conn: psycopg.Connection = Depends(get_conn)) -> dict:
        verdict = detail(conn, alert_id)["verdict"]
        if not verdict or verdict["route"] not in SUGGESTION_ROUTES:
            raise HTTPException(409, "only a suggested close can be accepted or rejected")
        repo.record_decision(conn, alert_id, body.decision, body.analyst)
        repo.audit(conn, alert_id, "human_decision", body.model_dump())
        return {"alert_id": alert_id, "decision": body.decision, "human_confirmed": True}

    @app.get("/", response_class=HTMLResponse)
    def home(conn: psycopg.Connection = Depends(get_conn)) -> str:
        counts = {r["route"]: r["n"] for r in conn.execute(
            "select route, count(*) as n from verdicts group by route order by route").fetchall()}
        return pages.home(counts, repo.list_by_route(conn, ANALYST_ROUTES), repo.list_by_route(conn, SUGGESTION_ROUTES))

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse)
    def alert_page(alert_id: str, conn: psycopg.Connection = Depends(get_conn)) -> str:
        return pages.alert(detail(conn, alert_id))

    return app
