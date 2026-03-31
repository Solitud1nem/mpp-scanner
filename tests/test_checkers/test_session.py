from __future__ import annotations

import pytest
import httpx

from mpp_scanner.checks.session import SessionReplayChecker


@pytest.mark.asyncio
async def test_session_clean_server(clean_client, clean_payment_info):
    """Clean server should reject all session replay attempts."""
    checker = SessionReplayChecker(clean_client)
    findings = await checker.run("http://test/service", clean_payment_info)
    assert len(findings) == 0, f"Expected 0 findings, got: {[f.id for f in findings]}"


@pytest.mark.asyncio
async def test_session_vuln_server(vuln_client, vuln_payment_info):
    """Vulnerable server should accept replayed sessions."""
    checker = SessionReplayChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    assert len(findings) > 0, "Expected findings for session replay"
    finding_ids = {f.id for f in findings}
    assert any(fid.startswith("SESS-") for fid in finding_ids)


@pytest.mark.asyncio
async def test_session_missing_expires(vuln_client, vuln_payment_info):
    """Vulnerable server is missing X-Payment-Expires."""
    checker = SessionReplayChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    finding_ids = {f.id for f in findings}
    assert "SESS-004" in finding_ids, "Should detect missing expires header"
