from __future__ import annotations

import re

from ..models import Finding, PaymentInfo, Severity
from .base import BaseChecker


class Malicious402Checker(BaseChecker):
    """Check for malicious 402 response vulnerabilities (INJ-001..002)."""

    id = "INJ"

    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        findings: list[Finding] = []
        evidence_base = {"target": target}

        # INJ-001: Check if destination address format is validated
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            destination = resp_402.headers.get("X-Payment-Destination", "")

            # Check basic address format validation
            # Tempo addresses should match a known pattern
            if destination:
                # Flag if destination doesn't look like a valid address
                is_valid_hex = bool(re.match(r"^0x[0-9a-fA-F]{40}$", destination))
                is_valid_tempo = destination.startswith("tempo1")

                if not is_valid_hex and not is_valid_tempo:
                    findings.append(
                        self.finding(
                            sub_id="001",
                            title="Invalid payment destination address format",
                            severity=Severity.HIGH,
                            desc=f"Payment destination '{destination}' does not match "
                            f"expected address format. An attacker could MITM the 402 "
                            f"response and redirect payments.",
                            evidence={
                                **evidence_base,
                                "destination": destination,
                                "is_valid_hex": is_valid_hex,
                                "is_valid_tempo": is_valid_tempo,
                            },
                            remediation="Validate destination address format server-side. "
                            "Agents should verify destination against a known registry.",
                        )
                    )

        # INJ-002: Send request with invalid EIP-55 checksum address
        resp_402 = await self.probe(target)
        if resp_402.status_code == 402:
            session = resp_402.headers.get("X-Payment-Session", "")
            # Send a payment claiming to be to an invalid checksum address
            bad_checksum = "0xINVALIDCHECKSUMaDDrEsS00000000000000"
            resp = await self.probe(
                target,
                headers={
                    "X-Payment-Tx": f"0x{'ee' * 32}",
                    "X-Payment-Session": session,
                    "X-Payment-Destination": bad_checksum,
                },
            )

            if resp.status_code == 200:
                findings.append(
                    self.finding(
                        sub_id="002",
                        title="Invalid checksum address accepted",
                        severity=Severity.MEDIUM,
                        desc="Service accepted a request with an invalid EIP-55 "
                        "checksum destination address. This suggests the server "
                        "does not validate address integrity.",
                        evidence={
                            **evidence_base,
                            "bad_checksum": bad_checksum,
                            "response_code": resp.status_code,
                        },
                        remediation="Validate EIP-55 checksum on all addresses. "
                        "Reject requests with malformed addresses.",
                    )
                )

        return findings
