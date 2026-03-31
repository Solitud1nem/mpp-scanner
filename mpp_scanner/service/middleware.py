"""MPP Pricing Middleware — implements the 402 payment flow."""
from __future__ import annotations

import json
import os
import time
import secrets
import logging

from redis import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from .verifier import verify_payment

logger = logging.getLogger(__name__)

SCANNER_WALLET = os.environ.get(
    "SCANNER_WALLET_ADDRESS", "tempo1scanner000000000000000000000000000"
)

PRICING = {
    "quick": 50_000,       # $0.05 in micro-USDC
    "full": 250_000,       # $0.25
    "certified": 1_000_000,  # $1.00
    "cached": 10_000,      # $0.01
}

SESSION_TTL = 300  # 5 minutes


def _get_redis(request: Request) -> Redis | None:
    return getattr(request.app.state, "redis", None)


def _create_session(r: Redis | None, session_id: str, data: dict) -> None:
    if r:
        r.setex(f"mpp:sess:{session_id}", SESSION_TTL, json.dumps(data))
    else:
        _mem_sessions[session_id] = data


def _get_session(r: Redis | None, session_id: str) -> dict | None:
    if r:
        raw = r.get(f"mpp:sess:{session_id}")
        return json.loads(raw) if raw else None
    return _mem_sessions.get(session_id)


def _mark_session_used(r: Redis | None, session_id: str) -> bool:
    """Atomically mark session as used. Returns True on first call only."""
    if r:
        key = f"mpp:sess:{session_id}:used"
        if r.setnx(key, "1"):
            r.expire(key, SESSION_TTL)
            return True
        return False
    session = _mem_sessions.get(session_id)
    if session and not session.get("used"):
        session["used"] = True
        return True
    return False


def _delete_session(r: Redis | None, session_id: str) -> None:
    if r:
        r.delete(f"mpp:sess:{session_id}", f"mpp:sess:{session_id}:used")
    else:
        _mem_sessions.pop(session_id, None)


# In-memory fallback (used when Redis is None)
_mem_sessions: dict[str, dict] = {}


class MPPPricingMiddleware(BaseHTTPMiddleware):
    """Middleware that gates /scan endpoints behind MPP 402 payment flow."""

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/scan"):
            return await call_next(request)

        r = _get_redis(request)
        payment_tx = request.headers.get("X-Payment-Tx")

        if not payment_tx:
            tier = request.query_params.get("tier", "full")
            price = PRICING.get(tier, PRICING["full"])
            session_id = f"sess_{secrets.token_hex(16)}"
            expires_at = int(time.time()) + SESSION_TTL

            _create_session(r, session_id, {
                "tier": tier,
                "price": price,
                "expires_at": expires_at,
            })

            return Response(
                status_code=402,
                headers={
                    "X-Payment-Scheme": "mpp-v1",
                    "X-Payment-Amount": str(price),
                    "X-Payment-Currency": "USDC",
                    "X-Payment-Destination": SCANNER_WALLET,
                    "X-Payment-Session": session_id,
                    "X-Payment-Expires": str(expires_at),
                    "X-Payment-Network": os.environ.get(
                        "TEMPO_NETWORK", "tempo-mainnet"
                    ),
                },
            )

        # Payment provided — verify it
        session_id = request.headers.get("X-Payment-Session", "")

        session = _get_session(r, session_id)
        if not session:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid or unknown session ID"},
            )

        if time.time() > session["expires_at"]:
            _delete_session(r, session_id)
            return JSONResponse(
                status_code=400,
                content={"error": "Session expired"},
            )

        if not _mark_session_used(r, session_id):
            return JSONResponse(
                status_code=400,
                content={"error": "Session already consumed"},
            )

        valid, reason = await verify_payment(r, payment_tx, session["price"])
        if not valid:
            return JSONResponse(
                status_code=402,
                content={"error": f"Payment verification failed: {reason}"},
                headers={
                    "X-Payment-Scheme": "mpp-v1",
                    "X-Payment-Amount": str(session["price"]),
                    "X-Payment-Currency": "USDC",
                    "X-Payment-Destination": SCANNER_WALLET,
                    "X-Payment-Session": session_id,
                    "X-Payment-Expires": str(session["expires_at"]),
                },
            )

        request.state.tier = session["tier"]
        request.state.session_id = session_id

        return await call_next(request)


def reset_sessions() -> None:
    """Reset in-memory fallback (for testing)."""
    _mem_sessions.clear()
