"""Health and discovery endpoints."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health():
    return {"status": "ok", "service": "mpp-scanner", "version": "0.1.0"}


@router.get("/.well-known/mpp-scanner")
async def well_known():
    """MPP service discovery endpoint."""
    return {
        "service": "mpp-scanner",
        "version": "0.1.0",
        "description": "Vulnerability scanner for MPP (Machine Payment Protocol) services",
        "pricing": {
            "quick": {"amount": 50_000, "currency": "USDC", "description": "3 critical checks"},
            "full": {"amount": 250_000, "currency": "USDC", "description": "All 7 checker categories"},
            "certified": {"amount": 1_000_000, "currency": "USDC", "description": "Full scan + on-chain certificate"},
        },
        "endpoints": {
            "scan": "/scan",
            "certificate": "/certificate/{target}",
            "health": "/health",
        },
    }
