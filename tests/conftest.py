from __future__ import annotations

import pytest
import httpx
from unittest.mock import AsyncMock

from tests.fixtures.mock_mpp_server import create_clean_app, reset_state as reset_clean
from tests.fixtures.vuln_mpp_server import create_vuln_app, reset_state as reset_vuln
from mpp_scanner.models import PaymentInfo


@pytest.fixture
def clean_app():
    reset_clean()
    return create_clean_app()


@pytest.fixture
def vuln_app():
    reset_vuln()
    return create_vuln_app()


@pytest.fixture
def clean_transport(clean_app):
    return httpx.ASGITransport(app=clean_app)


@pytest.fixture
def vuln_transport(vuln_app):
    return httpx.ASGITransport(app=vuln_app)


@pytest.fixture
def clean_client(clean_transport):
    return httpx.AsyncClient(transport=clean_transport, base_url="http://test")


@pytest.fixture
def vuln_client(vuln_transport):
    return httpx.AsyncClient(transport=vuln_transport, base_url="http://test")


@pytest.fixture
def clean_payment_info() -> PaymentInfo:
    import time

    return PaymentInfo(
        amount=100_000,
        currency="USDC",
        destination="tempo1cleanserver000000000000000000000000",
        session_id="sess_test123",
        expires_at=int(time.time()) + 300,
        network="tempo-testnet",
        scheme="mpp-v1",
    )


@pytest.fixture
def vuln_payment_info() -> PaymentInfo:
    import time

    return PaymentInfo(
        amount=100_000,
        currency="USDC",
        destination="tempo1vulnserver0000000000000000000000000",
        session_id="sess_vuln123",
        expires_at=int(time.time()) + 300,
        network="tempo-testnet",
        scheme="mpp-v1",
    )
