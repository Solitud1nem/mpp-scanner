"""Intentionally vulnerable MPP server for testing.

Run all checkers against this — expect findings on every checker category.
"""
from __future__ import annotations

import random
import time
import secrets

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

WALLET = "tempo1vulnserver0000000000000000000000000"
PRICE = 100_000  # $0.10 in micro-USDC

# VULN: Inconsistent pricing — jitters ±30% each request (OVER-001)
_request_count = 0
_session_store: dict[str, dict] = {}


def create_vuln_app() -> FastAPI:
    app = FastAPI(title="Vulnerable MPP Server")

    @app.middleware("http")
    async def mpp_middleware(request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)

        payment_tx = request.headers.get("X-Payment-Tx")

        if not payment_tx:
            # VULN: Missing X-Payment-Expires header (SESS-004)
            # VULN: Inconsistent pricing — different amount each time (OVER-001)
            global _request_count
            _request_count += 1
            jittered_price = PRICE + (_request_count % 3 - 1) * 30_000  # 70k, 100k, 130k cycle

            new_session = f"sess_{secrets.token_hex(16)}"
            _session_store[new_session] = {
                "amount": jittered_price,
            }
            return Response(
                status_code=402,
                headers={
                    "X-Payment-Scheme": "mpp-v1",
                    "X-Payment-Amount": str(jittered_price),
                    "X-Payment-Currency": "USDC",
                    "X-Payment-Destination": WALLET,
                    "X-Payment-Session": new_session,
                    # VULN: No X-Payment-Expires (SESS-004)
                    "X-Payment-Network": "tempo-testnet",
                },
            )

        # VULN: Accept ANY payment_tx without verification (VRFY-001, VRFY-002, VRFY-003)
        # VULN: No session validation (SESS-001, SESS-002, SESS-003)
        # VULN: No replay protection — same tx works multiple times (RACE-001, RACE-002)
        # VULN: No amount validation (PRICE-001 through PRICE-006)
        # VULN: No txhash format validation (INJ-001, INJ-002)
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/service")
    async def service():
        return {"result": "data", "status": "ok"}

    @app.post("/service")
    async def service_post():
        return {"result": "data", "status": "ok"}

    return app


def reset_state() -> None:
    """Reset server state between tests."""
    global _request_count
    _request_count = 0
    _session_store.clear()


# Module-level app instance for uvicorn / docker
app = create_vuln_app()
