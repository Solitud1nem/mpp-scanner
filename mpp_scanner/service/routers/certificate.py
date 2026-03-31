"""Certificate endpoints — GET /certificate/{target}."""
from __future__ import annotations

import os
import logging

from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/certificate/{target}")
async def get_certificate(target: str):
    """Get the on-chain security certificate for a target address.

    Returns certificate data from the SecurityCertificate contract.
    """
    contract_address = os.environ.get("CERTIFICATE_CONTRACT_ADDRESS", "")
    if not contract_address:
        raise HTTPException(
            status_code=503,
            detail="Certificate contract not configured",
        )

    try:
        from mpp_scanner.service.chain import get_chain

        chain = get_chain()
        if not chain.is_connected:
            raise HTTPException(
                status_code=503,
                detail="Chain RPC not available",
            )

        # Read certificate from contract
        # ABI for getCertificate(address) -> Certificate
        contract = chain.w3.eth.contract(
            address=chain.w3.to_checksum_address(contract_address),
            abi=[
                {
                    "inputs": [{"name": "target", "type": "address"}],
                    "name": "getCertificate",
                    "outputs": [
                        {
                            "components": [
                                {"name": "target", "type": "address"},
                                {"name": "issuedAt", "type": "uint256"},
                                {"name": "expiresAt", "type": "uint256"},
                                {"name": "scanId", "type": "bytes32"},
                                {"name": "scannerVersion", "type": "uint8"},
                                {"name": "hasCritical", "type": "bool"},
                            ],
                            "name": "",
                            "type": "tuple",
                        }
                    ],
                    "stateMutability": "view",
                    "type": "function",
                },
                {
                    "inputs": [{"name": "target", "type": "address"}],
                    "name": "isValid",
                    "outputs": [{"name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function",
                },
            ],
        )

        target_addr = chain.w3.to_checksum_address(target)
        cert = contract.functions.getCertificate(target_addr).call()
        is_valid = contract.functions.isValid(target_addr).call()

        if cert[1] == 0:  # issuedAt == 0 means no certificate
            raise HTTPException(
                status_code=404,
                detail=f"No certificate found for {target}",
            )

        return {
            "target": cert[0],
            "issued_at": cert[1],
            "expires_at": cert[2],
            "scan_id": cert[3].hex(),
            "scanner_version": cert[4],
            "has_critical": cert[5],
            "is_valid": is_valid,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Certificate lookup failed: %s", e)
        raise HTTPException(status_code=500, detail="Certificate lookup failed")
