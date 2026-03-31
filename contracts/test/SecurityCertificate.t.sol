// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/SecurityCertificate.sol";

contract SecurityCertificateTest is Test {
    MPPSecurityCertificate public cert;
    address public scanner = address(0x1);
    address public attacker = address(0x2);
    address public target = address(0x3);

    event CertificateIssued(address indexed target, bytes32 scanId, bool hasCritical);

    function setUp() public {
        cert = new MPPSecurityCertificate(scanner);
    }

    // --- Access control ---

    function test_issue_only_callable_by_scanner() public {
        vm.prank(scanner);
        cert.issue(target, bytes32("scan123"), false);

        MPPSecurityCertificate.Certificate memory c = cert.getCertificate(target);
        assertEq(c.target, target);
        assertEq(c.scanId, bytes32("scan123"));
    }

    function test_issue_reverts_for_non_scanner() public {
        vm.prank(attacker);
        vm.expectRevert("Only scanner can issue certs");
        cert.issue(target, bytes32("scan123"), false);
    }

    // --- isValid ---

    function test_isValid_returns_true_for_clean_cert() public {
        vm.prank(scanner);
        cert.issue(target, bytes32("scan_clean"), false);

        assertTrue(cert.isValid(target));
    }

    function test_isValid_returns_false_if_hasCritical() public {
        vm.prank(scanner);
        cert.issue(target, bytes32("scan_crit"), true);

        assertFalse(cert.isValid(target));
    }

    function test_isValid_returns_false_after_24h() public {
        vm.prank(scanner);
        cert.issue(target, bytes32("scan_expire"), false);

        // Fast forward 24 hours + 1 second
        vm.warp(block.timestamp + 86401);

        assertFalse(cert.isValid(target));
    }

    function test_isValid_returns_false_for_no_certificate() public {
        assertFalse(cert.isValid(address(0x99)));
    }

    function test_isValid_still_true_at_23h59m() public {
        vm.prank(scanner);
        cert.issue(target, bytes32("scan_edge"), false);

        // Fast forward 23h 59m 59s
        vm.warp(block.timestamp + 86399);

        assertTrue(cert.isValid(target));
    }

    // --- Full lifecycle ---

    function test_full_lifecycle_issue_valid_expire() public {
        // 1. Issue certificate
        vm.prank(scanner);
        cert.issue(target, bytes32("scan_lifecycle"), false);

        // 2. Should be valid immediately
        assertTrue(cert.isValid(target));

        // 3. Check certificate data
        MPPSecurityCertificate.Certificate memory c = cert.getCertificate(target);
        assertEq(c.target, target);
        assertEq(c.scannerVersion, 1);
        assertFalse(c.hasCritical);
        assertEq(c.expiresAt, c.issuedAt + 86400);

        // 4. Should expire after 24h
        vm.warp(block.timestamp + 86401);
        assertFalse(cert.isValid(target));
    }

    function test_reissue_overwrites_previous() public {
        // Issue with critical
        vm.prank(scanner);
        cert.issue(target, bytes32("scan_v1"), true);
        assertFalse(cert.isValid(target));

        // Reissue without critical
        vm.prank(scanner);
        cert.issue(target, bytes32("scan_v2"), false);
        assertTrue(cert.isValid(target));

        MPPSecurityCertificate.Certificate memory c = cert.getCertificate(target);
        assertEq(c.scanId, bytes32("scan_v2"));
        assertFalse(c.hasCritical);
    }

    // --- Events ---

    function test_issue_emits_event() public {
        vm.prank(scanner);
        vm.expectEmit(true, false, false, true);
        emit CertificateIssued(
            target,
            bytes32("scan_event"),
            false
        );
        cert.issue(target, bytes32("scan_event"), false);
    }

    // --- Constants ---

    function test_version_is_1() public view {
        assertEq(cert.VERSION(), 1);
    }

    function test_scanner_wallet_is_immutable() public view {
        assertEq(cert.SCANNER_WALLET(), scanner);
    }
}
