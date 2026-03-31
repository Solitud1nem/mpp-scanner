from __future__ import annotations

import asyncio
import time

from ..models import Finding, PaymentInfo, Severity
from .base import BaseChecker


class DoSChecker(BaseChecker):
    """Check for denial-of-service vulnerabilities (DOS-001..004)."""

    id = "DOS"

    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        findings: list[Finding] = []
        evidence_base = {"target": target}

        # DOS-001: Measure delivery rate over 20 requests
        success_count = 0
        total_requests = 20
        for i in range(total_requests):
            resp_402 = await self.probe(target)
            if resp_402.status_code != 402:
                continue
            session = resp_402.headers.get("X-Payment-Session", "")
            tx = f"0x{i:064x}"
            resp = await self.probe(
                target,
                headers={"X-Payment-Tx": tx, "X-Payment-Session": session},
            )
            if resp.status_code == 200:
                success_count += 1

        delivery_rate = (success_count / total_requests * 100) if total_requests else 0
        if delivery_rate < 95 and success_count > 0:
            findings.append(
                self.finding(
                    sub_id="001",
                    title="Low delivery rate detected",
                    severity=Severity.MEDIUM,
                    desc=f"Service delivered only {success_count}/{total_requests} "
                    f"requests ({delivery_rate:.0f}%). Paid requests should have "
                    f">95% delivery rate.",
                    evidence={
                        **evidence_base,
                        "total_requests": total_requests,
                        "success_count": success_count,
                        "delivery_rate_pct": delivery_rate,
                    },
                    remediation="Ensure high availability for paid requests. "
                    "Implement retry/refund mechanisms for failed deliveries.",
                )
            )

        # DOS-002: Timeout check — does the service handle slow responses?
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            tx = f"0x{'dd' * 32}"
            start = time.monotonic()
            try:
                resp = await self.client.get(
                    target,
                    headers={"X-Payment-Tx": tx, "X-Payment-Session": session},
                    timeout=2.0,
                )
                elapsed = time.monotonic() - start
                if elapsed > 1.5:
                    findings.append(
                        self.finding(
                            sub_id="002",
                            title="Slow response after payment",
                            severity=Severity.LOW,
                            desc=f"Service took {elapsed:.1f}s to respond after payment. "
                            f"No refund mechanism detected for slow/failed deliveries.",
                            evidence={
                                **evidence_base,
                                "response_time_s": elapsed,
                                "response_code": resp.status_code,
                            },
                            remediation="Implement timeout guarantees and automatic "
                            "refund for failed deliveries.",
                        )
                    )
            except Exception:
                findings.append(
                    self.finding(
                        sub_id="002",
                        title="Timeout after payment — no refund mechanism",
                        severity=Severity.MEDIUM,
                        desc="Service timed out after payment was submitted. "
                        "No refund mechanism detected.",
                        evidence={**evidence_base, "timeout": True},
                        remediation="Implement timeout guarantees and automatic "
                        "refund for failed deliveries.",
                    )
                )

        # DOS-003: Pay-and-no-deliver ratio
        if total_requests > 0 and success_count > 0:
            no_deliver_ratio = (total_requests - success_count) / total_requests * 100
            if no_deliver_ratio > 5:
                findings.append(
                    self.finding(
                        sub_id="003",
                        title="High pay-and-no-deliver ratio",
                        severity=Severity.HIGH,
                        desc=f"Pay-and-no-deliver ratio: {no_deliver_ratio:.0f}% "
                        f"(threshold: 5%). Agent paid but did not receive service.",
                        evidence={
                            **evidence_base,
                            "no_deliver_ratio_pct": no_deliver_ratio,
                            "paid": total_requests,
                            "delivered": success_count,
                        },
                        remediation="Investigate delivery failures. Implement "
                        "automatic refunds when service is not delivered.",
                    )
                )

        # DOS-004: Recursive billing detection
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            tx = f"0x{'cc' * 32}"
            resp = await self.probe(
                target,
                headers={"X-Payment-Tx": tx, "X-Payment-Session": session},
            )

            if resp.status_code == 200:
                try:
                    body = resp.json()
                    # Check if response contains 402-like payment demands
                    body_str = str(body).lower()
                    if "402" in body_str or "x-payment" in body_str or "payment_required" in body_str:
                        findings.append(
                            self.finding(
                                sub_id="004",
                                title="Recursive billing detected",
                                severity=Severity.HIGH,
                                desc="Service response contains references to additional "
                                "payment requirements. This could indicate recursive "
                                "billing where service A charges, then calls service B "
                                "which also charges.",
                                evidence={
                                    **evidence_base,
                                    "response_body": body,
                                },
                                remediation="Declare sub-service costs upfront. "
                                "Implement billing transparency so agents know "
                                "total cost before committing.",
                            )
                        )
                except Exception:
                    pass

        return findings
