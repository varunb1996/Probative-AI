"""FastAPI app: the analyst queues, human decisions, and (optionally) the workers in-process.

    uvicorn --factory triage.api.app:create_app

On a free host the workers run as threads in this process (RUN_WORKERS=true); they talk to
each other only through the Postgres queue, so they can move to their own services unchanged.
"""

import os
import threading
from collections.abc import Iterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import unquote

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from triage.api import pages
from triage.api.auth import token_ok
from triage.investigate.decide import model_decide
from triage.judge.client import OpenAICompatibleClient
from triage.services import sandbox, workers
from triage.services.config import Settings, inference_config, load_dotenv, load_policy
from triage.store import queue, repositories as repo
from triage.store.db import apply_schema, connect

ONE_HOUR = timedelta(hours=1)

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
            sandbox.sweep_expired(conn)
        stop = threading.Event()
        if settings.run_workers:
            config = inference_config(os.environ)
            policy = load_policy(os.environ)
            # The investigator's replies are a union (tool call | verdict); strict schema mode cannot express
            # it on most providers, so it runs without response_format. Parsing stays strict either way.
            plain = config.model_copy(update={"structured_output": False})
            decide = model_decide(workers.PatientClient(OpenAICompatibleClient(plain)), plain)
            workers.start(settings.database_url, workers.model_judge(OpenAICompatibleClient(config), config),
                          lambda alert: policy, stop, settings.poll_seconds, gate=sandbox.budget_gate, decide=decide)
            sandbox.start_case_worker(settings.database_url, stop, settings.poll_seconds)
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
                                 "decision": decision, "trigger_event": trigger.model_dump(mode="json"),
                                 "case_id": repo.alert_case(conn, alert_id),
                                 "investigation": repo.get_investigation(conn, alert_id)})

    def client_of(request: Request) -> str:
        address, _ = sandbox.client_address(dict(request.headers), request.client.host if request.client else None)
        return sandbox.client_hash(address)

    @app.get("/api/whoami")
    def whoami(request: Request) -> dict:
        """Which header identified you, and a short hash of it (never the address): checks rate limiting."""
        address, source = sandbox.client_address(dict(request.headers), request.client.host if request.client else None)
        return {"client": sandbox.client_hash(address)[:8], "source": source}

    def admit_case(conn: psycopg.Connection, client: str) -> None:
        if repo.cases_since(conn, client, ONE_HOUR) >= sandbox.CASES_PER_HOUR:
            raise HTTPException(429, f"the sandbox allows {sandbox.CASES_PER_HOUR} cases per hour; try again later")
        sandbox.sweep_expired(conn)

    def case_view(conn: psycopg.Connection, case_id: str) -> dict:
        case = repo.get_case(conn, case_id)
        if case is None:
            raise HTTPException(404, "unknown or expired case")
        triaged = conn.execute("select count(*) as n from verdicts v join alerts a on a.alert_id = v.alert_id "
                               "where a.case_id = %s", (case_id,)).fetchone()["n"]
        return {"case": case, "triaged": triaged,
                "analyst_queue": repo.list_by_route(conn, ANALYST_ROUTES, case_id=case_id),
                "suggestions": repo.list_by_route(conn, SUGGESTION_ROUTES, case_id=case_id)}

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

    # --- sandbox ----------------------------------------------------------------

    @app.get("/try", response_class=HTMLResponse)
    def try_page() -> str:
        return pages.try_page(sandbox.SCENARIOS, sandbox.MAX_UPLOAD_BYTES)

    @app.post("/api/cases/upload", status_code=202)
    async def upload(request: Request, x_declared_public: str | None = Header(default=None),
                     x_filename: str | None = Header(default=None)) -> dict:
        if (x_declared_public or "").strip().lower() != "yes":
            raise HTTPException(400, "confirm that the file contains no private or confidential data")
        client = client_of(request)
        with connect(settings.database_url) as conn:
            admit_case(conn, client)
        sandbox.UPLOADS.mkdir(parents=True, exist_ok=True)
        case_id = sandbox.new_case_id()
        path = sandbox.UPLOADS / f"{case_id}.upload"
        size, head = 0, b""
        with path.open("wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > sandbox.MAX_UPLOAD_BYTES:
                    f.close()
                    path.unlink(missing_ok=True)
                    raise HTTPException(413, f"files are limited to {sandbox.MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
                if len(head) < 64:
                    head += chunk[:64]
                f.write(chunk)
        fmt = sandbox.sniff_format(head)
        if fmt is None:
            path.unlink(missing_ok=True)
            raise HTTPException(415, "upload a Windows .evtx file or OTRF-style JSON lines")
        path = path.rename(path.with_suffix(f".{fmt}"))   # Hayabusa selects input files by extension
        name = Path(unquote(x_filename or "upload")).name[:100] or "upload"
        with connect(settings.database_url) as conn:
            repo.create_case(conn, case_id, "upload", name, client=client, ttl=sandbox.CASE_TTL)
            sandbox.enqueue_upload(conn, case_id, path, fmt)
        return {"case_id": case_id, "url": f"/cases/{case_id}"}

    @app.post("/api/cases/scenario/{key}", status_code=202)
    def start_scenario(key: str, request: Request, conn: psycopg.Connection = Depends(get_conn)) -> dict:
        if key not in sandbox.SCENARIOS:
            raise HTTPException(404, "unknown scenario")
        client = client_of(request)
        admit_case(conn, client)
        case_id = sandbox.new_case_id()
        repo.create_case(conn, case_id, "scenario", sandbox.SCENARIOS[key].title, client=client, ttl=sandbox.CASE_TTL)
        sandbox.enqueue_scenario(conn, case_id, key)
        return {"case_id": case_id, "url": f"/cases/{case_id}"}

    @app.get("/api/cases/{case_id}")
    def case_json(case_id: str, conn: psycopg.Connection = Depends(get_conn)) -> dict:
        view = case_view(conn, case_id)
        view["case"] = {k: v for k, v in view["case"].items() if k != "client"}
        return jsonable_encoder(view)

    @app.get("/cases/{case_id}", response_class=HTMLResponse)
    def case_page(case_id: str, conn: psycopg.Connection = Depends(get_conn)) -> str:
        return pages.case(**case_view(conn, case_id))

    return app
