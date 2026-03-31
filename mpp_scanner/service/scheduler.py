"""RQ job scheduler for async scan jobs."""
from __future__ import annotations

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


class ScanScheduler:
    """Enqueue and track scan jobs via RQ."""

    def __init__(self, redis_url: str | None = None) -> None:
        self.redis_url = redis_url or REDIS_URL
        self._queue = None

    @property
    def queue(self):
        if self._queue is None:
            try:
                from redis import Redis
                from rq import Queue

                conn = Redis.from_url(self.redis_url)
                self._queue = Queue("scan-jobs", connection=conn)
            except Exception as e:
                logger.warning("RQ not available: %s", e)
                return None
        return self._queue

    async def enqueue(self, target: str, tier: str) -> str | None:
        """Enqueue a scan job. Returns job ID or None if queue unavailable."""
        q = self.queue
        if q is None:
            return None

        try:
            from mpp_scanner.engine import run_scan

            job = q.enqueue(
                run_scan,
                target,
                tier,
                job_timeout="5m",
                result_ttl=3600,
            )
            return job.id
        except Exception as e:
            logger.warning("Failed to enqueue scan: %s", e)
            return None

    async def get_status(self, job_id: str) -> dict:
        """Get job status and result."""
        q = self.queue
        if q is None:
            return {"status": "unknown", "error": "Queue unavailable"}

        try:
            from rq.job import Job
            from redis import Redis

            conn = Redis.from_url(self.redis_url)
            job = Job.fetch(job_id, connection=conn)

            result = {
                "job_id": job_id,
                "status": job.get_status(),
            }

            if job.is_finished:
                result["result"] = job.result
            elif job.is_failed:
                result["error"] = str(job.exc_info)

            return result
        except Exception as e:
            return {"job_id": job_id, "status": "not_found", "error": str(e)}


# Singleton
_scheduler: ScanScheduler | None = None


def get_scheduler() -> ScanScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = ScanScheduler()
    return _scheduler
