"""web3.py wrapper for Tempo RPC interactions."""
from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from typing import Optional

from web3 import Web3

logger = logging.getLogger(__name__)


@dataclass
class TxInfo:
    """On-chain transaction data."""
    tx_hash: str
    from_address: str
    to_address: str
    amount: int  # in micro-USDC (6 decimals)
    confirmed: bool
    block_number: int


class TempoChain:
    """Wrapper for Tempo L1 blockchain interactions via web3.py."""

    def __init__(self, rpc_url: str | None = None) -> None:
        self.rpc_url = rpc_url or os.environ.get(
            "TEMPO_RPC_URL", "https://rpc.tempo.xyz"
        )
        self._w3: Web3 | None = None

    @property
    def w3(self) -> Web3:
        if self._w3 is None:
            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        return self._w3

    @property
    def is_connected(self) -> bool:
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    async def get_tx(self, tx_hash: str) -> TxInfo | None:
        """Fetch transaction data from chain. Returns None if not found."""
        try:
            tx = self.w3.eth.get_transaction(tx_hash)
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)

            return TxInfo(
                tx_hash=tx_hash,
                from_address=tx["from"],
                to_address=tx.get("to", ""),
                amount=tx.get("value", 0),
                confirmed=receipt is not None and receipt["status"] == 1,
                block_number=tx.get("blockNumber", 0) or 0,
            )
        except Exception as e:
            logger.warning("Failed to fetch tx %s: %s", tx_hash, e)
            return None

    async def get_current_block(self) -> int:
        """Get current block number."""
        try:
            return self.w3.eth.block_number
        except Exception:
            return 0

    async def verify_payment(
        self,
        tx_hash: str,
        expected_to: str,
        expected_amount: int,
        min_confirmations: int = 1,
    ) -> tuple[bool, str]:
        """Verify a payment transaction on-chain.

        Returns (is_valid, reason).
        """
        tx_info = await self.get_tx(tx_hash)
        if tx_info is None:
            return False, "Transaction not found on chain"

        if not tx_info.confirmed:
            return False, "Transaction not yet confirmed"

        current_block = await self.get_current_block()
        confirmations = current_block - tx_info.block_number
        if confirmations < min_confirmations:
            return False, f"Insufficient confirmations: {confirmations}/{min_confirmations}"

        if tx_info.to_address.lower() != expected_to.lower():
            return False, f"Wrong destination: {tx_info.to_address}"

        if tx_info.amount < expected_amount:
            return False, f"Insufficient amount: {tx_info.amount} < {expected_amount}"

        return True, "Payment verified"


# Singleton — lazy-initialized from env
_chain: TempoChain | None = None


def get_chain() -> TempoChain:
    global _chain
    if _chain is None:
        _chain = TempoChain()
    return _chain


def reset_chain() -> None:
    """Reset chain singleton (for testing)."""
    global _chain
    _chain = None
