from __future__ import annotations

import httpx

from .models import PaymentInfo

# Minimum headers needed to parse a 402 response
MINIMUM_HEADERS = [
    "X-Payment-Amount",
    "X-Payment-Currency",
    "X-Payment-Destination",
    "X-Payment-Session",
]


async def fingerprint(target: str, client: httpx.AsyncClient) -> PaymentInfo:
    """Send GET to target, expect 402, parse payment headers.

    Tolerates missing optional headers (X-Payment-Expires, X-Payment-Network)
    since those are findings, not blockers.
    """
    resp = await client.get(target, timeout=10.0)

    if resp.status_code != 402:
        raise ValueError(f"Expected 402, got {resp.status_code}. Not an MPP service.")

    missing = [h for h in MINIMUM_HEADERS if h not in resp.headers]
    if missing:
        raise ValueError(f"Missing required MPP headers: {missing}")

    return PaymentInfo(
        amount=int(resp.headers["X-Payment-Amount"]),
        currency=resp.headers["X-Payment-Currency"],
        destination=resp.headers["X-Payment-Destination"],
        session_id=resp.headers["X-Payment-Session"],
        expires_at=int(resp.headers.get("X-Payment-Expires", "0")),
        network=resp.headers.get("X-Payment-Network", "unknown"),
        scheme=resp.headers.get("X-Payment-Scheme", "mpp-v1"),
    )
