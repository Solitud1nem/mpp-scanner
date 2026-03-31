from __future__ import annotations

import time

from ..models import Finding, PaymentInfo, Severity
from .base import BaseChecker


class SessionReplayChecker(BaseChecker):
    """Check for session replay vulnerabilities (SESS-001..004)."""

    id = "SESS"

    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        findings: list[Finding] = []
        evidence_base = {"target": target, "session_id": info.session_id}

        # SESS-001: Session token replay — use same token twice
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            tx = f"0x{'01' * 32}"
            headers = {"X-Payment-Tx": tx, "X-Payment-Session": session}

            r1 = await self.probe(target, headers=headers)
            r2 = await self.probe(target, headers=headers)

            if r1.status_code == 200 and r2.status_code == 200:
                findings.append(
                    self.finding(
                        sub_id="001",
                        title="Session token replay accepted",
                        severity=Severity.CRITICAL,
                        desc="Same session token + txhash accepted twice. "
                        "Attacker can replay a single payment for unlimited access.",
                        evidence={
                            **evidence_base,
                            "session": session,
                            "first_status": r1.status_code,
                            "second_status": r2.status_code,
                        },
                        remediation="Invalidate session tokens after first use. "
                        "Track used txhashes server-side.",
                    )
                )

        # SESS-002: Expired session token
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            expires = resp_402.headers.get("X-Payment-Expires", "")

            # Try using the session with a timestamp far in the past
            tx = f"0x{'02' * 32}"
            headers = {
                "X-Payment-Tx": tx,
                "X-Payment-Session": session,
                "X-Payment-Expires": "1000000000",  # 2001 — long expired
            }
            resp = await self.probe(target, headers=headers)

            if resp.status_code == 200:
                findings.append(
                    self.finding(
                        sub_id="002",
                        title="Expired session token accepted",
                        severity=Severity.HIGH,
                        desc="Server accepted a session with an overridden expired timestamp.",
                        evidence={**evidence_base, "sent_expires": "1000000000", "response_code": resp.status_code},
                        remediation="Validate session expiry server-side. "
                        "Never trust client-supplied expiry headers.",
                    )
                )

        # SESS-003: Session ID swap
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session_a = resp_402.headers.get("X-Payment-Session", "")

            # Get a second session
            resp_402b = await self.probe(target)
            session_b = resp_402b.headers.get("X-Payment-Session", "") if resp_402b.status_code == 402 else ""

            if session_a and session_b and session_a != session_b:
                tx = f"0x{'03' * 32}"
                # Use session_a's token but claim session_b
                resp = await self.probe(
                    target,
                    headers={"X-Payment-Tx": tx, "X-Payment-Session": session_b},
                )

                # Also try with session_a to see if it cross-validates
                resp2 = await self.probe(
                    target,
                    headers={"X-Payment-Tx": f"0x{'04' * 32}", "X-Payment-Session": session_a},
                )

                if resp.status_code == 200 and resp2.status_code == 200:
                    findings.append(
                        self.finding(
                            sub_id="003",
                            title="Session ID swap accepted",
                            severity=Severity.HIGH,
                            desc="Server accepted payment with mismatched session IDs.",
                            evidence={
                                **evidence_base,
                                "session_a": session_a,
                                "session_b": session_b,
                                "response_code": resp.status_code,
                            },
                            remediation="Bind payment txhash to specific session ID. "
                            "Verify session-payment linkage server-side.",
                        )
                    )

        # SESS-004: Missing expires_at in 402 response
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            if "X-Payment-Expires" not in resp_402.headers:
                findings.append(
                    self.finding(
                        sub_id="004",
                        title="Missing X-Payment-Expires header in 402",
                        severity=Severity.MEDIUM,
                        desc="402 response lacks X-Payment-Expires header. "
                        "Session tokens may never expire.",
                        evidence={
                            **evidence_base,
                            "headers": dict(resp_402.headers),
                        },
                        remediation="Always include X-Payment-Expires in 402 responses. "
                        "Set reasonable expiry (5-15 minutes).",
                    )
                )

        return findings
