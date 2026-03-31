"""FastAPI application — main entry point for the MPP Scanner service."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import redis as redis_lib
from fastapi import FastAPI

from .middleware import MPPPricingMiddleware
from .routers import health, scan, certificate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown: connect Redis, teardown on exit."""
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        r = redis_lib.Redis.from_url(url, decode_responses=True)
        r.ping()
        app.state.redis = r
        logger.info("Redis connected at %s", url)
    except Exception:
        app.state.redis = None
        logger.warning("Redis unavailable — using in-memory fallback")

    yield

    if app.state.redis:
        app.state.redis.close()
    logger.info("MPP Scanner shut down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="MPP Security Scanner",
        description="Vulnerability scanner for Machine Payment Protocol services",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Add MPP payment middleware
    app.add_middleware(MPPPricingMiddleware)

    # Register routers
    app.include_router(health.router)
    app.include_router(scan.router)
    app.include_router(certificate.router)

    return app


# Default app instance for uvicorn
app = create_app()
