"""Payment txhash verification logic."""
from __future__ import annotations

import logging
import os

from redis import Redis

logger = logging.getLogger(__name__)

SCANNER_WALLET = os.environ.get("SCANNER_WALLET_ADDRESS", "tempo1scanner")
TX_CONSUMED_TTL = 86400  # 24 hours

# In-memory fallback (used when Redis is None)
_mem_consumed: set[str] = set()


def _mark_tx_consumed(r: Redis | None, tx_hash: str) -> bool:
    """Atomically mark tx as consumed. Returns True on first call only."""
    if r:
        key = f"mpp:tx:{tx_hash}"
        if r.setnx(key, "1"):
            r.expire(key, TX_CONSUMED_TTL)
            return True
        return False
    if tx_hash in _mem_consumed:
        return False
    _mem_consumed.add(tx_hash)
    return True


def _skip_chain_verification() -> bool:
    return os.environ.get("MPP_SKIP_CHAIN_VERIFY", "").lower() in ("1", "true", "yes")


async def verify_payment(
    r: Redis | None, tx_hash: str, expected_amount: int
) -> tuple[bool, str]:
    """Verify that tx_hash represents a valid payment to the scanner wallet.

    Args:
        r: Redis connection from request.app.state.redis (or None for fallback).
        tx_hash: The transaction hash to verify.
        expected_amount: Required payment amount in micro-USDC.

    Returns:
        (is_valid, reason) tuple.
    """
    if not tx_hash.startswith("0x") or len(tx_hash) != 66:
        return False, "Invalid transaction hash format"

    if not _mark_tx_consumed(r, tx_hash):
        return False, "Transaction already consumed"

    if not _skip_chain_verification():
        from .chain import get_chain

        chain = get_chain()
        wallet = os.environ.get("SCANNER_WALLET_ADDRESS", SCANNER_WALLET)

        if chain.is_connected:
            valid, reason = await chain.verify_payment(
                tx_hash=tx_hash,
                expected_to=wallet,
                expected_amount=expected_amount,
                min_confirmations=1,
            )
            if not valid:
                return False, reason
        else:
            logger.warning(
                "Chain not connected — skipping on-chain verification for %s",
                tx_hash,
            )
    else:
        logger.info("Dev mode — skipping on-chain verification for %s", tx_hash)

    return True, "Payment verified"


def reset_consumed() -> None:
    """Reset in-memory fallback (for testing)."""
    _mem_consumed.clear()
