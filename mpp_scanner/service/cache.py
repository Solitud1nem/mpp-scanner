"""Redis cache layer with TTL strategy for scan results."""
from __future__ import annotations

import json
import os
import logging
from dataclasses import asdict
from typing import Optional

from mpp_scanner.models import ScanResult, Finding, Severity

logger = logging.getLogger(__name__)

# Cache TTL in seconds
CACHE_TTL = {
    "quick": 3600,       # 1 hour
    "full": 7200,        # 2 hours
    "certified": 86400,  # 24 hours
}


class ScanCache:
    """Redis-backed cache for scan results."""

    def __init__(self, redis_url: str | None = None) -> None:
        self.redis_url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        self._redis = None

    @property
    def redis(self):
        if self._redis is None:
            try:
                import redis as redis_lib
                self._redis = redis_lib.Redis.from_url(self.redis_url, decode_responses=True)
            except Exception as e:
                logger.warning("Redis not available: %s", e)
                return None
        return self._redis

    def _cache_key(self, target: str, tier: str) -> str:
        return f"scan:{tier}:{target}"

    async def get(self, target: str, tier: str = "full") -> ScanResult | None:
        """Retrieve cached scan result."""
        r = self.redis
        if r is None:
            return None

        try:
            key = self._cache_key(target, tier)
            data = r.get(key)
            if data is None:
                return None

            parsed = json.loads(data)
            findings = [
                Finding(
                    id=f["id"],
                    title=f["title"],
                    severity=Severity(f["severity"]),
                    description=f["description"],
                    evidence=f["evidence"],
                    poc_code=f["poc_code"],
                    remediation=f["remediation"],
                )
                for f in parsed["findings"]
            ]

            return ScanResult(
                target=parsed["target"],
                scan_id=parsed["scan_id"],
                tier=parsed["tier"],
                findings=findings,
                from_cache=True,
                scanned_at=parsed["scanned_at"],
                duration_ms=parsed["duration_ms"],
            )
        except Exception as e:
            logger.warning("Cache get failed: %s", e)
            return None

    async def set(self, target: str, result: ScanResult) -> None:
        """Store scan result in cache."""
        r = self.redis
        if r is None:
            return

        try:
            key = self._cache_key(target, result.tier)
            ttl = CACHE_TTL.get(result.tier, 3600)
            data = json.dumps(asdict(result), default=str)
            r.setex(key, ttl, data)
        except Exception as e:
            logger.warning("Cache set failed: %s", e)

    async def invalidate(self, target: str) -> None:
        """Remove all cached results for a target."""
        r = self.redis
        if r is None:
            return

        try:
            for tier in CACHE_TTL:
                key = self._cache_key(target, tier)
                r.delete(key)
        except Exception as e:
            logger.warning("Cache invalidate failed: %s", e)


# Singleton
_cache: ScanCache | None = None


def get_cache() -> ScanCache:
    global _cache
    if _cache is None:
        _cache = ScanCache()
    return _cache
