"""Integration tests: discovery → engine → reporter full cycle."""
from __future__ import annotations

import pytest
import httpx

from mpp_scanner.discovery import fingerprint
from mpp_scanner.models import Severity
from mpp_scanner.reporter import to_json, to_markdown, to_sarif


@pytest.mark.asyncio
async def test_fingerprint_clean_server(clean_client):
    """Fingerprint a clean MPP server."""
    info = await fingerprint("http://test/service", clean_client)
    assert info.amount == 100_000
    assert info.currency == "USDC"
    assert info.destination == "tempo1cleanserver000000000000000000000000"
    assert info.session_id.startswith("sess_")
    assert info.network == "tempo-testnet"
    assert info.scheme == "mpp-v1"


@pytest.mark.asyncio
async def test_fingerprint_non_mpp_raises(clean_client):
    """Non-MPP endpoint (health) should raise ValueError."""
    with pytest.raises(ValueError, match="Expected 402"):
        await fingerprint("http://test/health", clean_client)


@pytest.mark.asyncio
async def test_fingerprint_vuln_missing_optional_headers(vuln_client):
    """Vuln server missing X-Payment-Expires — fingerprint should still work but expires_at=0."""
    info = await fingerprint("http://test/service", vuln_client)
    assert info.expires_at == 0  # missing header defaults to 0
    assert info.amount > 0


@pytest.mark.asyncio
async def test_reporter_json_output(vuln_client, vuln_payment_info):
    """Test JSON reporter output."""
    from mpp_scanner.checks.price import PriceManipulationChecker
    from mpp_scanner.models import ScanResult
    import time

    checker = PriceManipulationChecker(vuln_client)
    findings = await checker.run("http://test/service", vuln_payment_info)

    result = ScanResult(
        target="http://test/service",
        scan_id="scan_test123",
        tier="full",
        findings=findings,
        from_cache=False,
        scanned_at=int(time.time()),
        duration_ms=100,
    )

    json_str = to_json(result)
    assert "scan_test123" in json_str
    assert "PRICE" in json_str

    md_str = to_markdown(result)
    assert "# MPP Security Scan Report" in md_str
    assert "PRICE" in md_str

    sarif_str = to_sarif(result)
    assert "mpp-scanner" in sarif_str
    assert "2.1.0" in sarif_str


@pytest.mark.asyncio
async def test_reporter_empty_findings():
    """Test reporter with no findings."""
    from mpp_scanner.models import ScanResult
    import time

    result = ScanResult(
        target="http://test/service",
        scan_id="scan_empty",
        tier="quick",
        findings=[],
        from_cache=False,
        scanned_at=int(time.time()),
        duration_ms=50,
    )

    md = to_markdown(result)
    assert "No vulnerabilities found" in md

    json_str = to_json(result)
    assert "scan_empty" in json_str

    sarif = to_sarif(result)
    assert '"results": []' in sarif


@pytest.mark.asyncio
async def test_scan_result_properties():
    """Test ScanResult has_critical and has_high properties."""
    from mpp_scanner.models import ScanResult, Finding, Severity
    import time

    crit_finding = Finding(
        id="TEST-001",
        title="Test Critical",
        severity=Severity.CRITICAL,
        description="test",
        evidence={},
        poc_code="pass",
        remediation="fix it",
    )

    result = ScanResult(
        target="http://test",
        scan_id="scan_props",
        tier="full",
        findings=[crit_finding],
        from_cache=False,
        scanned_at=int(time.time()),
        duration_ms=10,
    )

    assert result.has_critical is True
    assert result.has_high is False
