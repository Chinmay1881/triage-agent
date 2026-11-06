"""The FastAPI app. Clients connect on first use, so /health answers even with Mongo down."""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import AsyncMongoClient
from pymongo.errors import PyMongoError

from app.agent.deps import MongoTelemetry
from app.api.routes import Services, router
from app.api.runner import Runner
from app.api.store import MongoStore
from app.config import get_settings
from app.llm import get_model
from app.telemetry.db import telemetry_client, telemetry_db
from app.tools import call_tool

log = logging.getLogger(__name__)

RESULTS_DIR = Path(__file__).resolve().parents[2] / "evals" / "results"


def build_services() -> Services:
    settings = get_settings()
    db = telemetry_db(telemetry_client())
    telemetry = MongoTelemetry(db)
    triage_client: AsyncMongoClient = AsyncMongoClient(
        settings.triage_mongo_uri.get_secret_value(), tz_aware=True, serverSelectionTimeoutMS=3000
    )
    store = MongoStore(triage_client.get_default_database())
    runner = Runner(store, telemetry, partial(call_tool, db=db), settings, get_model)
    return Services(store, telemetry, runner, settings, RESULTS_DIR)


def lazy(factory: Callable[[], Services]) -> Callable[[], Services]:
    built: list[Services] = []

    def get() -> Services:
        if not built:
            built.append(factory())
        return built[0]

    return get


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    services = app.state.services()
    store = services.store
    try:
        if isinstance(store, MongoStore):
            await store.ensure_indexes()
        interrupted = await store.mark_interrupted()
        if interrupted:
            log.warning("marked %d interrupted run(s) as failed", interrupted)
    except PyMongoError as exc:
        log.warning("could not prepare the triage db: %s", exc)
    yield


def create_app(services: Callable[[], Services] = lazy(build_services)) -> FastAPI:  # noqa: B008
    app = FastAPI(title="triage-agent", lifespan=lifespan)
    app.state.services = services
    # The dashboard runs on Next.js at localhost:3000 in development.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        # Liveness only: answers even if Mongo or Groq is down.
        return {"status": "ok"}

    app.include_router(router)
    return app


app = create_app()
