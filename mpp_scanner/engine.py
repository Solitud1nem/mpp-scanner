from __future__ import annotations

import asyncio
import secrets
from time import time

import httpx

from .discovery import fingerprint
from .models import ScanResult
from .checks import ALL_CHECKERS, QUICK_CHECKERS


TIER_MAP = {
    "quick": QUICK_CHECKERS,
    "full": ALL_CHECKERS,
    "certified": ALL_CHECKERS,
}


def _generate_scan_id() -> str:
    return f"scan_{secrets.token_hex(12)}"


async def run_scan(target: str, tier: str = "full") -> ScanResult:
    """Run security scan against an MPP endpoint."""
    start = time()

    async with httpx.AsyncClient() as client:
        info = await fingerprint(target, client)

        checkers = TIER_MAP.get(tier, ALL_CHECKERS)

        tasks = [checker(client).run(target, info) for checker in checkers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings = []
        for result in results:
            if isinstance(result, Exception):
                continue  # log but don't crash
            findings.extend(result)

        elapsed_ms = int((time() - start) * 1000)

        return ScanResult(
            target=target,
            scan_id=_generate_scan_id(),
            tier=tier,
            findings=findings,
            from_cache=False,
            scanned_at=int(time()),
            duration_ms=elapsed_ms,
        )
