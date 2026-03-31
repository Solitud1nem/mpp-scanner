from __future__ import annotations

from ..models import Finding, PaymentInfo, Severity
from .base import BaseChecker


class OverclaimingChecker(BaseChecker):
    """Check for overclaiming vulnerabilities (OVER-001..002)."""

    id = "OVER"

    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        findings: list[Finding] = []
        evidence_base = {"target": target, "declared_amount": info.amount}

        # OVER-001: Compare declared amount across multiple 402 responses
        amounts: list[int] = []
        for _ in range(5):
            resp = await self.probe(target)
            if resp.status_code == 402:
                try:
                    amt = int(resp.headers.get("X-Payment-Amount", "0"))
                    amounts.append(amt)
                except ValueError:
                    pass

        if amounts and len(set(amounts)) > 1:
            findings.append(
                self.finding(
                    sub_id="001",
                    title="Inconsistent pricing across requests",
                    severity=Severity.HIGH,
                    desc=f"Service returned different prices across 5 requests: {amounts}. "
                    f"This could indicate dynamic price manipulation.",
                    evidence={
                        **evidence_base,
                        "observed_amounts": amounts,
                        "min": min(amounts),
                        "max": max(amounts),
                    },
                    remediation="Ensure consistent pricing for the same service tier. "
                    "Use deterministic pricing based on tier, not request metadata.",
                )
            )

        # OVER-002: Check if declared price is unreasonably high
        if amounts:
            avg_amount = sum(amounts) / len(amounts)
            # Flag if price is over $10 (10_000_000 micro-USDC) for a single request
            if avg_amount > 10_000_000:
                findings.append(
                    self.finding(
                        sub_id="002",
                        title="Suspiciously high price declared",
                        severity=Severity.MEDIUM,
                        desc=f"Service declares average price of {avg_amount} micro-USDC "
                        f"(${avg_amount / 1_000_000:.2f}). This exceeds reasonable "
                        f"thresholds for a single API call.",
                        evidence={
                            **evidence_base,
                            "average_amount": avg_amount,
                            "usd_equivalent": avg_amount / 1_000_000,
                        },
                        remediation="Review pricing to ensure it is reasonable for the "
                        "service provided. Consider implementing price caps.",
                    )
                )

        return findings
