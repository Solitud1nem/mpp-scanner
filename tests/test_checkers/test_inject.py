from __future__ import annotations

import pytest
import httpx

from mpp_scanner.checks.inject import Malicious402Checker


@pytest.mark.asyncio
async def test_inject_clean_server(clean_client, clean_payment_info):
    """Clean server should have valid address format."""
    checker = Malicious402Checker(clean_client)
    findings = await checker.run("http://test/service", clean_payment_info)
    # Clean server uses tempo1... address — INJ-001 should not fire
    # INJ-002 should not fire because clean server rejects bad requests
    assert len(findings) == 0, f"Expected 0 findings, got: {[f.id for f in findings]}"


@pytest.mark.asyncio
async def test_inject_vuln_server(vuln_client, vuln_payment_info):
    """Vulnerable server should accept bad checksums."""
    checker = Malicious402Checker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    finding_ids = {f.id for f in findings}
    # Vuln server accepts anything, so INJ-002 should fire
    assert "INJ-002" in finding_ids, "Should detect invalid checksum accepted"
