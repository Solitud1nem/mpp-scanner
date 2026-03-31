from __future__ import annotations

import pytest
import httpx

from mpp_scanner.checks.verify import PaymentVerificationChecker


@pytest.mark.asyncio
async def test_verify_clean_server(clean_client, clean_payment_info):
    """Clean server should reject foreign/invalid txhashes."""
    checker = PaymentVerificationChecker(clean_client)
    findings = await checker.run("http://test/service", clean_payment_info)
    assert len(findings) == 0, f"Expected 0 findings, got: {[f.id for f in findings]}"


@pytest.mark.asyncio
async def test_verify_vuln_server(vuln_client, vuln_payment_info):
    """Vulnerable server should accept any txhash."""
    checker = PaymentVerificationChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    assert len(findings) > 0, "Expected verification findings"
    finding_ids = {f.id for f in findings}
    assert "VRFY-001" in finding_ids, "Should detect foreign txhash accepted"
