from __future__ import annotations

import pytest
import httpx

from mpp_scanner.checks.overclaim import OverclaimingChecker


@pytest.mark.asyncio
async def test_overclaim_clean_server(clean_client, clean_payment_info):
    """Clean server should have consistent pricing."""
    checker = OverclaimingChecker(clean_client)
    findings = await checker.run("http://test/service", clean_payment_info)
    assert len(findings) == 0, f"Expected 0 findings, got: {[f.id for f in findings]}"


@pytest.mark.asyncio
async def test_overclaim_vuln_server(vuln_client, vuln_payment_info):
    """Vulnerable server should have inconsistent pricing."""
    checker = OverclaimingChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    finding_ids = {f.id for f in findings}
    assert "OVER-001" in finding_ids, "Should detect inconsistent pricing"
