from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PaymentInfo:
    """Parsed from 402 response headers."""

    amount: int  # in micro-USDC (6 decimals)
    currency: str  # "USDC"
    destination: str  # Tempo wallet address
    session_id: str  # X-Payment-Session header
    expires_at: int  # unix timestamp
    network: str  # "tempo-mainnet" or "tempo-testnet"
    scheme: str  # "mpp-v1"


@dataclass
class Finding:
    id: str  # e.g. "PRICE-001"
    title: str
    severity: Severity
    description: str
    evidence: dict  # raw proof data
    poc_code: str  # runnable Python exploit
    remediation: str  # how to fix


@dataclass
class ScanResult:
    target: str
    scan_id: str
    tier: str  # "quick" | "full" | "certified"
    findings: list[Finding]
    from_cache: bool
    scanned_at: int  # unix timestamp
    duration_ms: int

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == Severity.HIGH for f in self.findings)
