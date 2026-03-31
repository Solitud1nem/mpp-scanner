"""Phase 2 integration tests for the FastAPI service layer."""
from __future__ import annotations

import os
import pytest
import httpx

from mpp_scanner.service.app import create_app
from mpp_scanner.service.middleware import reset_sessions
from mpp_scanner.service.verifier import reset_consumed


@pytest.fixture(autouse=True)
def _skip_chain(monkeypatch):
    """Skip on-chain verification for all service tests."""
    monkeypatch.setenv("MPP_SKIP_CHAIN_VERIFY", "1")


@pytest.fixture
def service_app():
    reset_sessions()
    reset_consumed()
    return create_app()


@pytest.fixture
def service_transport(service_app):
    return httpx.ASGITransport(app=service_app)


@pytest.fixture
def service_client(service_transport):
    return httpx.AsyncClient(transport=service_transport, base_url="http://test")


@pytest.mark.asyncio
async def test_health_endpoint(service_client):
    """GET /health should return 200 without payment."""
    resp = await service_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "mpp-scanner"


@pytest.mark.asyncio
async def test_well_known_endpoint(service_client):
    """GET /.well-known/mpp-scanner should return service info."""
    resp = await service_client.get("/.well-known/mpp-scanner")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "mpp-scanner"
    assert "pricing" in data
    assert "quick" in data["pricing"]
    assert "full" in data["pricing"]
    assert "certified" in data["pricing"]


@pytest.mark.asyncio
async def test_scan_returns_402_without_payment(service_client):
    """POST /scan without payment should return 402 with MPP headers."""
    resp = await service_client.post(
        "/scan?tier=quick",
        json={"target": "http://example.com", "tier": "quick"},
    )
    assert resp.status_code == 402

    # Verify all required MPP headers
    assert resp.headers["X-Payment-Scheme"] == "mpp-v1"
    assert resp.headers["X-Payment-Currency"] == "USDC"
    assert "X-Payment-Amount" in resp.headers
    assert "X-Payment-Destination" in resp.headers
    assert "X-Payment-Session" in resp.headers
    assert "X-Payment-Expires" in resp.headers
    assert "X-Payment-Network" in resp.headers


@pytest.mark.asyncio
async def test_scan_402_pricing_tiers(service_client):
    """Different tiers should return different prices."""
    prices = {}
    for tier in ("quick", "full", "certified"):
        resp = await service_client.post(
            f"/scan?tier={tier}",
            json={"target": "http://example.com", "tier": tier},
        )
        assert resp.status_code == 402
        prices[tier] = int(resp.headers["X-Payment-Amount"])

    assert prices["quick"] < prices["full"] < prices["certified"]
    assert prices["quick"] == 50_000
    assert prices["full"] == 250_000
    assert prices["certified"] == 1_000_000


@pytest.mark.asyncio
async def test_scan_rejects_invalid_session(service_client):
    """Payment with bogus session should be rejected."""
    resp = await service_client.post(
        "/scan",
        json={"target": "http://example.com"},
        headers={
            "X-Payment-Tx": f"0x{'ab' * 32}",
            "X-Payment-Session": "sess_bogus",
        },
    )
    assert resp.status_code == 400
    assert "Invalid" in resp.json()["error"]


@pytest.mark.asyncio
async def test_scan_full_payment_flow(service_client):
    """Full flow: get 402 → extract session → pay → get scan result."""
    # Step 1: Request scan, get 402
    resp_402 = await service_client.post(
        "/scan?tier=quick",
        json={"target": "http://httpbin.org/status/402", "tier": "quick"},
    )
    assert resp_402.status_code == 402
    session_id = resp_402.headers["X-Payment-Session"]

    # Step 2: Submit payment with session
    # In dev mode (no chain connection), verifier allows any valid-format tx
    tx_hash = f"0x{'ff' * 32}"
    resp = await service_client.post(
        "/scan?tier=quick",
        json={"target": "http://httpbin.org/status/402", "tier": "quick"},
        headers={
            "X-Payment-Tx": tx_hash,
            "X-Payment-Session": session_id,
        },
    )
    # Should either succeed (scan runs) or fail with scan error (target unreachable)
    # But NOT 402 — payment was accepted
    assert resp.status_code != 402, "Payment should have been accepted"


@pytest.mark.asyncio
async def test_scan_session_replay_rejected(service_client):
    """Using the same session twice should be rejected."""
    # Get a session
    resp_402 = await service_client.post(
        "/scan?tier=quick",
        json={"target": "http://example.com", "tier": "quick"},
    )
    session_id = resp_402.headers["X-Payment-Session"]
    tx_hash = f"0x{'ee' * 32}"

    # First use
    await service_client.post(
        "/scan?tier=quick",
        json={"target": "http://example.com", "tier": "quick"},
        headers={"X-Payment-Tx": tx_hash, "X-Payment-Session": session_id},
    )

    # Second use — should be rejected
    tx_hash_2 = f"0x{'dd' * 32}"
    resp = await service_client.post(
        "/scan?tier=quick",
        json={"target": "http://example.com", "tier": "quick"},
        headers={"X-Payment-Tx": tx_hash_2, "X-Payment-Session": session_id},
    )
    assert resp.status_code == 400
    assert "consumed" in resp.json()["error"].lower()


@pytest.mark.asyncio
async def test_certificate_no_contract(service_client):
    """Certificate endpoint should return 503 when contract not configured."""
    resp = await service_client.get("/certificate/0x1234567890abcdef1234567890abcdef12345678")
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_certificate_with_contract(service_client, monkeypatch):
    """Certificate endpoint should return JSON when contract is configured."""
    from mpp_scanner.service.chain import reset_chain

    monkeypatch.setenv(
        "CERTIFICATE_CONTRACT_ADDRESS",
        "0x8cF01fb57002CA878084cBFad43Ba105186BE722",
    )
    monkeypatch.setenv("TEMPO_RPC_URL", "https://rpc.moderato.tempo.xyz")
    reset_chain()  # force re-init with new RPC URL

    # We issued a test cert to address 0x0...01 during deploy verification
    resp = await service_client.get(
        "/certificate/0x0000000000000000000000000000000000000001"
    )
    # Should return 200 with valid JSON (cert was issued on-chain)
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "0x0000000000000000000000000000000000000001"
    assert "issued_at" in data
    assert "expires_at" in data
    assert "scan_id" in data
    assert "is_valid" in data
