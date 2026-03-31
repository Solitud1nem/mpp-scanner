from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from ..models import Finding, PaymentInfo, Severity
from ..poc import generate_poc


class BaseChecker(ABC):
    """All checkers inherit from this."""

    id: str  # e.g. "PRICE"

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    @abstractmethod
    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        """Run all sub-checks. Return list of findings (empty = clean)."""
        ...

    async def probe(
        self, target: str, headers: dict | None = None
    ) -> httpx.Response:
        """Send request to target with optional custom headers."""
        return await self.client.get(
            target,
            headers=headers or {},
            timeout=15.0,
        )

    def finding(
        self,
        sub_id: str,
        title: str,
        severity: Severity,
        desc: str,
        evidence: dict,
        remediation: str,
    ) -> Finding:
        return Finding(
            id=f"{self.id}-{sub_id}",
            title=title,
            severity=severity,
            description=desc,
            evidence=evidence,
            poc_code=generate_poc(f"{self.id}-{sub_id}", evidence),
            remediation=remediation,
        )
