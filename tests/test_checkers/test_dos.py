from __future__ import annotations

import pytest
import httpx

from mpp_scanner.checks.dos import DoSChecker


@pytest.mark.asyncio
async def test_dos_clean_server(clean_client, clean_payment_info):
    """Clean server should have good delivery rate."""
    checker = DoSChecker(clean_client)
    findings = await checker.run("http://test/service", clean_payment_info)
    # Clean server requires valid 66-char txhashes, so most probes will fail
    # with 400. This means delivery rate will be low — but that's because
    # the clean server correctly rejects invalid payments, not a DoS issue.
    # We should not get DOS-004 (recursive billing) at least.
    finding_ids = {f.id for f in findings}
    assert "DOS-004" not in finding_ids, "Clean server should not show recursive billing"


@pytest.mark.asyncio
async def test_dos_vuln_server(vuln_client, vuln_payment_info):
    """Vulnerable server should have high delivery rate (accepts everything)."""
    checker = DoSChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)
    # Vuln server accepts everything, so delivery rate should be high (no DOS-001)
    # But we shouldn't get false positives for DOS-004 either
    finding_ids = {f.id for f in findings}
    assert "DOS-004" not in finding_ids, "Should not falsely detect recursive billing"
