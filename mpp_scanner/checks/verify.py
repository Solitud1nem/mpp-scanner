from __future__ import annotations

from ..models import Finding, PaymentInfo, Severity
from .base import BaseChecker


class PaymentVerificationChecker(BaseChecker):
    """Check for payment verification vulnerabilities (VRFY-001..003)."""

    id = "VRFY"

    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        findings: list[Finding] = []
        evidence_base = {"target": target}

        # VRFY-001: Send a foreign (unrelated) txhash
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            # This is a made-up txhash that doesn't correspond to any real payment
            foreign_tx = f"0x{'de' * 32}"
            resp = await self.probe(
                target,
                headers={"X-Payment-Tx": foreign_tx, "X-Payment-Session": session},
            )

            if resp.status_code == 200:
                findings.append(
                    self.finding(
                        sub_id="001",
                        title="Foreign transaction hash accepted as payment",
                        severity=Severity.CRITICAL,
                        desc="Service accepted a random/foreign txhash without verifying "
                        "it corresponds to a real payment to the correct destination.",
                        evidence={
                            **evidence_base,
                            "foreign_tx": foreign_tx,
                            "response_code": resp.status_code,
                        },
                        remediation="Verify every txhash on-chain: check recipient, "
                        "amount, confirmation count, and that the tx hasn't been "
                        "used before.",
                    )
                )

        # VRFY-002: Send txhash with smaller amount (reuse session approach)
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            underpaid_tx = f"0x{'cf' * 32}"
            resp = await self.probe(
                target,
                headers={
                    "X-Payment-Tx": underpaid_tx,
                    "X-Payment-Session": session,
                    "X-Payment-Amount": "1",  # claim only 1 micro-USDC
                },
            )

            if resp.status_code == 200:
                findings.append(
                    self.finding(
                        sub_id="002",
                        title="Underpaid transaction accepted",
                        severity=Severity.CRITICAL,
                        desc="Service accepted a txhash with a client-declared amount "
                        "of 1 micro-USDC instead of verifying the actual on-chain amount.",
                        evidence={
                            **evidence_base,
                            "underpaid_tx": underpaid_tx,
                            "claimed_amount": 1,
                            "required_amount": info.amount,
                        },
                        remediation="Always verify payment amount on-chain. "
                        "Never trust client-supplied amount headers.",
                    )
                )

        # VRFY-003: Send a pending/unconfirmed txhash
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            pending_tx = f"0x{'00' * 32}"
            resp = await self.probe(
                target,
                headers={
                    "X-Payment-Tx": pending_tx,
                    "X-Payment-Session": session,
                },
            )

            if resp.status_code == 200:
                findings.append(
                    self.finding(
                        sub_id="003",
                        title="Unconfirmed (pending) transaction accepted",
                        severity=Severity.HIGH,
                        desc="Service accepted a txhash of all zeros (simulating an "
                        "unconfirmed/pending transaction). Real verification should "
                        "require minimum confirmations.",
                        evidence={
                            **evidence_base,
                            "pending_tx": pending_tx,
                            "response_code": resp.status_code,
                        },
                        remediation="Require minimum confirmation count before "
                        "accepting payment. Wait for at least 1 block confirmation.",
                    )
                )

        return findings
