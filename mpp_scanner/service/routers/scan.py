"""Scan endpoints — POST /scan, GET /scan/{scan_id}."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Query, HTTPException
from pydantic import BaseModel, HttpUrl

from mpp_scanner.engine import run_scan
from mpp_scanner.reporter import to_json
from mpp_scanner.service.cache import get_cache
from mpp_scanner.service.scheduler import get_scheduler

logger = logging.getLogger(__name__)

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    tier: str = "full"


class ScanQueued(BaseModel):
    scan_id: str
    status: str = "queued"
    message: str = "Scan enqueued. Poll GET /scan/{scan_id} for results."


@router.post("/scan")
async def create_scan(
    request: Request,
    body: ScanRequest,
):
    """Create a new scan. Requires MPP payment (handled by middleware)."""
    target = body.target
    tier = getattr(request.state, "tier", body.tier)

    # Check cache first
    cache = get_cache()
    cached = await cache.get(target, tier)
    if cached:
        return {
            "scan_id": cached.scan_id,
            "target": cached.target,
            "tier": cached.tier,
            "from_cache": True,
            "findings_count": len(cached.findings),
            "has_critical": cached.has_critical,
            "has_high": cached.has_high,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in cached.findings
            ],
            "scanned_at": cached.scanned_at,
            "duration_ms": cached.duration_ms,
        }

    # For full/certified: try async queue first
    if tier in ("full", "certified"):
        scheduler = get_scheduler()
        job_id = await scheduler.enqueue(target, tier)
        if job_id:
            return ScanQueued(scan_id=job_id)
        # Fall through to synchronous if queue unavailable

    # Synchronous scan (quick tier, or queue unavailable)
    try:
        result = await run_scan(target, tier)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error("Scan failed: %s", e)
        raise HTTPException(status_code=500, detail="Scan failed")

    # Cache the result
    await cache.set(target, result)

    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "tier": result.tier,
        "from_cache": False,
        "findings_count": len(result.findings),
        "has_critical": result.has_critical,
        "has_high": result.has_high,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
        "scanned_at": result.scanned_at,
        "duration_ms": result.duration_ms,
    }


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Poll for scan job status and results."""
    scheduler = get_scheduler()
    status = await scheduler.get_status(scan_id)

    if status.get("status") == "not_found":
        raise HTTPException(status_code=404, detail="Scan job not found")

    return status
