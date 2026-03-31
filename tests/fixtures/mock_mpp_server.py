"""Clean, correctly-implemented MPP server for testing.

Run all checkers against this — expect 0 findings.
Simulates on-chain payment verification by maintaining a whitelist of valid txhashes.
"""
from __future__ import annotations

import time
import secrets

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

WALLET = "tempo1cleanserver000000000000000000000000"
PRICE = 100_000  # $0.10 in micro-USDC

# Track used sessions/payments to prevent replay
_used_sessions: set[str] = set()
_used_txhashes: set[str] = set()
_session_store: dict[str, dict] = {}
# Whitelist of "verified" txhashes (simulates on-chain lookup)
_valid_txhashes: dict[str, dict] = {}


def register_valid_payment(txhash: str, amount: int, destination: str) -> None:
    """Register a txhash as a valid on-chain payment (for testing)."""
    _valid_txhashes[txhash] = {
        "amount": amount,
        "destination": destination,
        "confirmed": True,
    }


def create_clean_app() -> FastAPI:
    app = FastAPI(title="Clean MPP Server")

    @app.middleware("http")
    async def mpp_middleware(request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)

        payment_tx = request.headers.get("X-Payment-Tx")
        session_id = request.headers.get("X-Payment-Session")

        if not payment_tx:
            # Issue 402 with proper headers
            new_session = f"sess_{secrets.token_hex(16)}"
            expires_at = int(time.time()) + 300
            _session_store[new_session] = {
                "expires_at": expires_at,
                "amount": PRICE,
                "used": False,
            }
            return Response(
                status_code=402,
                headers={
                    "X-Payment-Scheme": "mpp-v1",
                    "X-Payment-Amount": str(PRICE),
                    "X-Payment-Currency": "USDC",
                    "X-Payment-Destination": WALLET,
                    "X-Payment-Session": new_session,
                    "X-Payment-Expires": str(expires_at),
                    "X-Payment-Network": "tempo-testnet",
                },
            )

        # --- Validate payment strictly ---

        # 1. Check session exists and is valid
        if not session_id or session_id not in _session_store:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid session ID"},
            )

        session = _session_store[session_id]

        # 2. Check session not expired
        if time.time() > session["expires_at"]:
            return JSONResponse(
                status_code=400,
                content={"error": "Session expired"},
            )

        # 3. Check session not already used (replay protection)
        if session["used"]:
            return JSONResponse(
                status_code=400,
                content={"error": "Session already used"},
            )

        # 4. Check txhash not reused across sessions
        if payment_tx in _used_txhashes:
            return JSONResponse(
                status_code=400,
                content={"error": "Transaction already used"},
            )

        # 5. Validate txhash format (must start with 0x and be 66 chars)
        if not payment_tx.startswith("0x") or len(payment_tx) != 66:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid transaction hash format"},
            )

        # 6. Simulate on-chain verification:
        #    - txhash must be in our verified whitelist
        #    - amount must match
        #    - destination must match
        if payment_tx not in _valid_txhashes:
            return JSONResponse(
                status_code=400,
                content={"error": "Transaction not found on chain"},
            )

        chain_data = _valid_txhashes[payment_tx]

        if not chain_data.get("confirmed", False):
            return JSONResponse(
                status_code=400,
                content={"error": "Transaction not yet confirmed"},
            )

        if chain_data["amount"] < session["amount"]:
            return JSONResponse(
                status_code=400,
                content={"error": "Insufficient payment amount"},
            )

        if chain_data["destination"] != WALLET:
            return JSONResponse(
                status_code=400,
                content={"error": "Payment destination mismatch"},
            )

        # 7. Ignore any client-supplied amount/destination overrides
        #    (server uses its own records, not client headers)

        # Mark as used atomically
        session["used"] = True
        _used_sessions.add(session_id)
        _used_txhashes.add(payment_tx)

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
    _used_sessions.clear()
    _used_txhashes.clear()
    _session_store.clear()
    _valid_txhashes.clear()
