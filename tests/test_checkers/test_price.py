from __future__ import annotations

import pytest
import httpx

from mpp_scanner.checks.price import PriceManipulationChecker


@pytest.mark.asyncio
async def test_price_clean_server(clean_client, clean_payment_info):
    """Clean server should reject all price manipulation attempts."""
    checker = PriceManipulationChecker(clean_client)
    findings = await checker.run("http://test/service", clean_payment_info)
    assert len(findings) == 0, f"Expected 0 findings, got: {[f.id for f in findings]}"


@pytest.mark.asyncio
async def test_price_vuln_server(vuln_client, vuln_payment_info):
    """Vulnerable server should accept manipulated prices."""
    checker = PriceManipulationChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    assert len(findings) > 0, "Expected findings for price manipulation"
    finding_ids = {f.id for f in findings}
    # Should detect at least some price manipulation issues
    assert any(fid.startswith("PRICE-") for fid in finding_ids)


@pytest.mark.asyncio
async def test_price_findings_have_poc(vuln_client, vuln_payment_info):
    """All price findings should include PoC code."""
    checker = PriceManipulationChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    for f in findings:
        assert f.poc_code, f"Finding {f.id} missing PoC code"
        assert "httpx" in f.poc_code or "import" in f.poc_code
