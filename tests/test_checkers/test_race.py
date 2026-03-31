from __future__ import annotations

import pytest
import httpx

from mpp_scanner.checks.race import RaceConditionChecker


@pytest.mark.asyncio
async def test_race_clean_server(clean_client, clean_payment_info):
    """Clean server should reject replayed payments in parallel."""
    checker = RaceConditionChecker(clean_client)
    findings = await checker.run("http://test/service", clean_payment_info)
    assert len(findings) == 0, f"Expected 0 findings, got: {[f.id for f in findings]}"


@pytest.mark.asyncio
async def test_race_vuln_server(vuln_client, vuln_payment_info):
    """Vulnerable server should accept parallel replayed payments."""
    checker = RaceConditionChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    assert len(findings) > 0, "Expected race condition findings"
    finding_ids = {f.id for f in findings}
    assert any(fid.startswith("RACE-") for fid in finding_ids)
