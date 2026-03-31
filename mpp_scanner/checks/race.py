from __future__ import annotations

import asyncio

from ..models import Finding, PaymentInfo, Severity
from .base import BaseChecker


class RaceConditionChecker(BaseChecker):
    """Check for race condition vulnerabilities (RACE-001..002)."""

    id = "RACE"

    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        findings: list[Finding] = []
        evidence_base = {"target": target}

        # RACE-001: Same payment proof used in 10 parallel requests
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            tx = f"0x{'aa' * 32}"
            headers = {"X-Payment-Tx": tx, "X-Payment-Session": session}

            tasks = [self.probe(target, headers=headers) for _ in range(10)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(
                1 for r in results
                if not isinstance(r, Exception) and r.status_code == 200
            )

            if success_count > 1:
                findings.append(
                    self.finding(
                        sub_id="001",
                        title="Race condition: same payment accepted multiple times",
                        severity=Severity.CRITICAL,
                        desc=f"Sent 10 parallel requests with same payment proof. "
                        f"{success_count}/10 returned 200. "
                        f"Attacker can multiply value of a single payment.",
                        evidence={
                            **evidence_base,
                            "parallel_requests": 10,
                            "success_count": success_count,
                            "txhash": tx,
                        },
                        remediation="Use atomic check-and-mark on payment proofs. "
                        "Implement distributed locking (e.g., Redis SETNX) "
                        "before processing payment.",
                    )
                )

        # RACE-002: TOCTOU — rapid fire after payment
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            tx = f"0x{'bb' * 32}"
            headers = {"X-Payment-Tx": tx, "X-Payment-Session": session}

            # Send one legitimate request, then immediately fire 10 more
            first = await self.probe(target, headers=headers)
            if first.status_code == 200:
                followup_tasks = [
                    self.probe(target, headers=headers) for _ in range(10)
                ]
                followups = await asyncio.gather(*followup_tasks, return_exceptions=True)

                extra_success = sum(
                    1 for r in followups
                    if not isinstance(r, Exception) and r.status_code == 200
                )

                if extra_success > 0:
                    findings.append(
                        self.finding(
                            sub_id="002",
                            title="TOCTOU: additional requests accepted after payment consumed",
                            severity=Severity.HIGH,
                            desc=f"After valid payment, {extra_success}/10 follow-up "
                            f"requests with same proof returned 200.",
                            evidence={
                                **evidence_base,
                                "first_status": first.status_code,
                                "extra_successes": extra_success,
                            },
                            remediation="Mark payment as consumed atomically "
                            "before returning the response.",
                        )
                    )

        return findings
