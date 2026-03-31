// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MPPSecurityCertificate {
    struct Certificate {
        address target;
        uint256 issuedAt;
        uint256 expiresAt; // issuedAt + 86400 (24h)
        bytes32 scanId;
        uint8 scannerVersion;
        bool hasCritical;
    }

    mapping(address => Certificate) public certificates;
    address public immutable SCANNER_WALLET;
    uint8 public constant VERSION = 1;

    event CertificateIssued(
        address indexed target,
        bytes32 scanId,
        bool hasCritical
    );

    constructor(address _scannerWallet) {
        SCANNER_WALLET = _scannerWallet;
    }

    modifier onlyScanner() {
        require(msg.sender == SCANNER_WALLET, "Only scanner can issue certs");
        _;
    }

    function issue(
        address target,
        bytes32 scanId,
        bool hasCritical
    ) external onlyScanner {
        certificates[target] = Certificate({
            target: target,
            issuedAt: block.timestamp,
            expiresAt: block.timestamp + 86400,
            scanId: scanId,
            scannerVersion: VERSION,
            hasCritical: hasCritical
        });
        emit CertificateIssued(target, scanId, hasCritical);
    }

    function isValid(address target) external view returns (bool) {
        Certificate memory c = certificates[target];
        return c.issuedAt > 0 && block.timestamp < c.expiresAt && !c.hasCritical;
    }

    function getCertificate(
        address target
    ) external view returns (Certificate memory) {
        return certificates[target];
    }
}
