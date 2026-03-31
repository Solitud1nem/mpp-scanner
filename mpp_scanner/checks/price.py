from __future__ import annotations

from ..models import Finding, PaymentInfo, Severity
from .base import BaseChecker


class PriceManipulationChecker(BaseChecker):
    """Check for price manipulation vulnerabilities (PRICE-001..006)."""

    id = "PRICE"

    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        findings: list[Finding] = []
        evidence_base = {"target": target, "declared_amount": info.amount}

        # Get a valid session first
        resp_402 = await self.probe(target)
        if resp_402.status_code != 402:
            return findings
        session_id = resp_402.headers.get("X-Payment-Session", "")

        checks = [
            ("001", "Underpayment by 1 micro-USDC accepted", str(info.amount - 1)),
            ("002", "Decimal confusion (18 vs 6 decimals) accepted", str(info.amount * 10**12)),
            ("003", "Float representation attack accepted", f"{info.amount * 0.009999:.6f}"),
            ("004", "Negative amount accepted", str(-info.amount)),
            ("005", "Zero amount accepted", "0"),
            ("006", "Integer overflow (2^256-1) accepted", str(2**256 - 1)),
        ]

        for sub_id, title, fake_amount in checks:
            # Get fresh session for each check
            resp_402 = await self.probe(target)
            if resp_402.status_code != 402:
                continue
            session = resp_402.headers.get("X-Payment-Session", "")

            resp = await self.probe(
                target,
                headers={
                    "X-Payment-Tx": f"0x{'ab' * 32}",
                    "X-Payment-Session": session,
                    "X-Payment-Amount": fake_amount,
                },
            )

            if resp.status_code == 200:
                severity = Severity.CRITICAL if sub_id in ("001", "004", "005") else Severity.HIGH
                findings.append(
                    self.finding(
                        sub_id=sub_id,
                        title=title,
                        severity=severity,
                        desc=f"Service accepted payment with manipulated amount: {fake_amount}",
                        evidence={**evidence_base, "sent_amount": fake_amount, "response_code": 200},
                        remediation="Validate payment amount on-chain before granting access. "
                        "Never trust client-supplied amount headers.",
                    )
                )

        return findings
