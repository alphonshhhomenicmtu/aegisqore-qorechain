// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {QoreGuardPolicyRegistry} from "../QoreGuardPolicyRegistry.sol";

/// @notice Minimal Foundry cheatcode interface (zero external git submodule deps).
interface Vm {
    function warp(uint256 newTimestamp) external;
    function prank(address msgSender) external;
    function startPrank(address msgSender) external;
    function stopPrank() external;
    function etch(address target, bytes calldata newRuntimeBytecode) external;
    function expectRevert(bytes calldata revertData) external;
    function expectRevert(bytes4 revertSelector) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData) external;
}

/// @notice Mock QoreChain IQorePQC.pqcVerify precompile (0x...0A01).
contract MockQorePQCVerify {
    bool public nextValid = true;
    bytes32 public expectedMessageHash;
    bool public enforceMessageMatch;

    function setResult(bool valid) external {
        nextValid = valid;
    }

    function setExpectedMessage(bytes32 msgHash, bool enforce) external {
        expectedMessageHash = msgHash;
        enforceMessageMatch = enforce;
    }

    function pqcVerify(
        bytes calldata pubkey,
        bytes calldata signature,
        bytes calldata message
    ) external view returns (bool valid) {
        if (pubkey.length != 2592 || signature.length != 4627 || message.length == 0) {
            return false;
        }
        if (enforceMessageMatch && keccak256(message) != expectedMessageHash) {
            return false;
        }
        return nextValid;
    }
}

/// @notice Mock QoreChain IQorePQC.pqcKeyStatus precompile (0x...0A02).
contract MockQorePQCKeyStatus {
    struct KeyRecord {
        bool registered;
        uint8 algorithmId;
        bytes pubkey;
        bool possessionProven;
    }

    mapping(address => KeyRecord) private _keys;

    function setKeyStatus(
        address account,
        bool registered,
        uint8 algorithmId,
        bytes calldata pubkey,
        bool possessionProven
    ) external {
        _keys[account] = KeyRecord(registered, algorithmId, pubkey, possessionProven);
    }

    function pqcKeyStatus(
        address account
    ) external view returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven) {
        KeyRecord storage rec = _keys[account];
        return (rec.registered, rec.algorithmId, rec.pubkey, rec.possessionProven);
    }
}

/// @notice Mock QoreChain IQoreAI.aiRiskScore precompile (0x...0B01).
contract MockQoreAIRiskScore {
    uint256 public riskScore = 15;
    uint8 public riskLevel = 1;

    function setRisk(uint256 score, uint8 level) external {
        riskScore = score;
        riskLevel = level;
    }

    function aiRiskScore(bytes calldata) external view returns (uint256 score, uint8 level) {
        return (riskScore, riskLevel);
    }
}

/// @notice Mock QoreChain IQoreAI.aiAnomalyCheck precompile (0x...0B02).
contract MockQoreAIAnomalyCheck {
    uint256 public anomalyScore = 10;
    bool public flagged;

    function setAnomaly(uint256 score, bool isFlagged) external {
        anomalyScore = score;
        flagged = isFlagged;
    }

    function aiAnomalyCheck(address, uint256) external view returns (uint256, bool) {
        return (anomalyScore, flagged);
    }
}

contract QoreGuardPolicyRegistryTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant OWNER = address(0xA11CE);
    address private constant AGENT = address(0xB0B);
    address private constant ATTACKER = address(0xBAD);
    address private constant TARGET_ALLOWED = address(0x000000000000000000000000000000000000dEaD);
    address private constant TARGET_UNKNOWN = address(0x2222222222222222222222222222222222222222);

    bytes4 private constant SEL_TRANSFER = 0xa9059cbb;
    bytes4 private constant SEL_APPROVE = 0x095ea7b3;
    bytes4 private constant SEL_SET_APPROVAL_ALL = 0xa22cb465;

    QoreGuardPolicyRegistry private registry;
    bytes private validPubkey;
    bytes private validSig;
    bytes32 private validPubkeyHash;

    function setUp() public {
        vm.warp(1_760_000_000);
        registry = new QoreGuardPolicyRegistry();

        // Deploy & vm.etch mock QoreChain precompiles at exact canonical addresses
        MockQorePQCVerify mockVerify = new MockQorePQCVerify();
        MockQorePQCKeyStatus mockStatus = new MockQorePQCKeyStatus();
        MockQoreAIRiskScore mockRisk = new MockQoreAIRiskScore();
        MockQoreAIAnomalyCheck mockAnomaly = new MockQoreAIAnomalyCheck();

        vm.etch(registry.PQC_VERIFY_PRECOMPILE(), address(mockVerify).code);
        vm.etch(registry.PQC_KEY_STATUS_PRECOMPILE(), address(mockStatus).code);
        vm.etch(registry.AI_RISK_SCORE_PRECOMPILE(), address(mockRisk).code);
        vm.etch(registry.AI_ANOMALY_CHECK_PRECOMPILE(), address(mockAnomaly).code);

        // Initialize etched precompile storage
        MockQorePQCVerify(registry.PQC_VERIFY_PRECOMPILE()).setResult(true);
        MockQoreAIRiskScore(registry.AI_RISK_SCORE_PRECOMPILE()).setRisk(12, 1);
        MockQoreAIAnomalyCheck(registry.AI_ANOMALY_CHECK_PRECOMPILE()).setAnomaly(5, false);

        validPubkey = _filledBytes(2592, 0x42);
        validSig = _filledBytes(4627, 0x77);
        validPubkeyHash = keccak256(validPubkey);

        MockQorePQCKeyStatus(registry.PQC_KEY_STATUS_PRECOMPILE()).setKeyStatus(
            AGENT,
            true,
            3, // ML-DSA-87
            validPubkey,
            true
        );

        address[] memory targets = new address[](1);
        targets[0] = TARGET_ALLOWED;
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = SEL_TRANSFER;

        vm.prank(OWNER);
        registry.registerAgentPolicy(
            QoreGuardPolicyRegistry.RegistrationInput({
                agent: AGENT,
                pqPubkeyHash: validPubkeyHash,
                maxSingleTxAmount: 5_000_000,
                dailyCapAmount: 10_000_000,
                windowDuration: 1 days,
                validUntil: uint64(block.timestamp + 7 days),
                maxAiRiskLevel: 2,
                requireOnchainKeyStatus: true,
                requireAiPrecompile: true,
                enforceTargetAllowlist: true,
                enforceSelectorAllowlist: true
            }),
            targets,
            selectors
        );
    }

    function _filledBytes(uint256 len, bytes1 fill) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) {
            out[i] = fill;
        }
    }

    function _validRequest(uint64 nonce, uint256 amount, bytes memory payload)
        internal
        view
        returns (QoreGuardPolicyRegistry.ActionAuthRequest memory)
    {
        return QoreGuardPolicyRegistry.ActionAuthRequest({
            agent: AGENT,
            target: TARGET_ALLOWED,
            amount: amount,
            calldataPayload: payload,
            nonce: nonce,
            expiresAt: uint64(block.timestamp + 600),
            pqAlgorithmId: 3,
            pqPubkey: validPubkey,
            pqSignature: validSig
        });
    }

    // -------------------------------------------------------------------------
    // 1. Valid ML-DSA-87 + Low AI-Risk Execution
    // -------------------------------------------------------------------------
    function test_AuthorizeValidMlDsa87AndLowAiRisk() public {
        bytes memory transferCall = abi.encodeWithSelector(SEL_TRANSFER, TARGET_ALLOWED, 1_000_000);
        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, 2_000_000, transferCall);

        (bytes32 commitHash, bytes32 decisionDigest) = registry.authorizeAction(req);
        assert(commitHash != bytes32(0));
        assert(decisionDigest != bytes32(0));
        assert(registry.getPolicy(AGENT).lastNonce == 1);
        assert(registry.currentSlidingWindowSpend(AGENT) == 2_000_000);
    }

    // -------------------------------------------------------------------------
    // 2. Quantum-Downgrade Rejections (empty sig, wrong algId, short key)
    // -------------------------------------------------------------------------
    function test_RevertOnQuantumDowngradeClassicalOnlyEmptySig() public {
        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, 500_000, "");
        req.pqSignature = "";
        bytes32 commitHash = registry.computeCommitment(req.agent, req.target, req.amount, req.calldataPayload, req.nonce, req.expiresAt);

        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_QUANTUM_DOWNGRADE(),
                commitHash
            )
        );
        registry.authorizeAction(req);
    }

    function test_RevertOnQuantumDowngradeWeakAlgorithmId() public {
        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, 500_000, "");
        req.pqAlgorithmId = 1; // Below ML-DSA-87 (3)
        bytes32 commitHash = registry.computeCommitment(req.agent, req.target, req.amount, req.calldataPayload, req.nonce, req.expiresAt);

        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_QUANTUM_DOWNGRADE(),
                commitHash
            )
        );
        registry.authorizeAction(req);
    }

    function test_RevertOnInvalidPqcSignatureFromPrecompile() public {
        MockQorePQCVerify(registry.PQC_VERIFY_PRECOMPILE()).setResult(false);
        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, 500_000, "");
        bytes32 commitHash = registry.computeCommitment(req.agent, req.target, req.amount, req.calldataPayload, req.nonce, req.expiresAt);

        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_PQC_SIGNATURE_INVALID(),
                commitHash
            )
        );
        registry.authorizeAction(req);
    }

    function test_RevertOnPubkeyHashMismatchAndUnprovenOnchainKeyStatus() public {
        // Case A: rogue 2592B key does not match registered pqPubkeyHash
        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, 500_000, "");
        req.pqPubkey = _filledBytes(2592, 0x99);
        bytes32 commitHash = registry.computeCommitment(req.agent, req.target, req.amount, req.calldataPayload, req.nonce, req.expiresAt);

        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_PUBKEY_HASH_MISMATCH(),
                commitHash
            )
        );
        registry.authorizeAction(req);

        // Case B: on-chain pqcKeyStatus reports possessionProven=false
        MockQorePQCKeyStatus(registry.PQC_KEY_STATUS_PRECOMPILE()).setKeyStatus(AGENT, true, 3, validPubkey, false);
        QoreGuardPolicyRegistry.ActionAuthRequest memory req2 = _validRequest(1, 500_000, "");
        bytes32 commitHash2 = registry.computeCommitment(req2.agent, req2.target, req2.amount, req2.calldataPayload, req2.nonce, req2.expiresAt);

        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_PQC_KEY_STATUS_INVALID(),
                commitHash2
            )
        );
        registry.authorizeAction(req2);
    }

    // -------------------------------------------------------------------------
    // 3. On-Chain IQoreAI Risk & Anomaly Precompile Rejection
    // -------------------------------------------------------------------------
    function test_RevertOnHighAiRiskScore() public {
        MockQoreAIRiskScore(registry.AI_RISK_SCORE_PRECOMPILE()).setRisk(92, 3);
        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, 500_000, "");
        bytes32 commitHash = registry.computeCommitment(req.agent, req.target, req.amount, req.calldataPayload, req.nonce, req.expiresAt);

        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_AI_RISK_EXCEEDED(),
                commitHash
            )
        );
        registry.authorizeAction(req);
    }

    function test_RevertOnAiAnomalyFlagged() public {
        MockQoreAIAnomalyCheck(registry.AI_ANOMALY_CHECK_PRECOMPILE()).setAnomaly(99, true);
        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, 500_000, "");
        bytes32 commitHash = registry.computeCommitment(req.agent, req.target, req.amount, req.calldataPayload, req.nonce, req.expiresAt);

        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_AI_ANOMALY_FLAGGED(),
                commitHash
            )
        );
        registry.authorizeAction(req);
    }

    // -------------------------------------------------------------------------
    // 4. Monotonic Anti-Replay Nonce Protection
    // -------------------------------------------------------------------------
    function test_RevertOnReplayNonceAndSkippedNonce() public {
        // Skipped nonce 2 before 1 reverts
        QoreGuardPolicyRegistry.ActionAuthRequest memory skipReq = _validRequest(2, 100_000, "");
        bytes32 skipCommit = registry.computeCommitment(skipReq.agent, skipReq.target, skipReq.amount, skipReq.calldataPayload, skipReq.nonce, skipReq.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_NONCE_REPLAY_OR_GAP(),
                skipCommit
            )
        );
        registry.authorizeAction(skipReq);

        // Nonce 1 succeeds
        QoreGuardPolicyRegistry.ActionAuthRequest memory req1 = _validRequest(1, 100_000, "");
        registry.authorizeAction(req1);

        // Replaying nonce 1 reverts
        bytes32 c1 = registry.computeCommitment(req1.agent, req1.target, req1.amount, req1.calldataPayload, req1.nonce, req1.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_NONCE_REPLAY_OR_GAP(),
                c1
            )
        );
        registry.authorizeAction(req1);
    }

    // -------------------------------------------------------------------------
    // 5. Spending Cap & O(1) Sliding-Window Daily Cap + Time-Warp Recovery
    // -------------------------------------------------------------------------
    function test_RevertOnSingleTxCapAndSlidingWindowDailyCap() public {
        // Single tx cap is 5_000_000
        QoreGuardPolicyRegistry.ActionAuthRequest memory overSingle = _validRequest(1, 5_000_001, "");
        bytes32 cSingle = registry.computeCommitment(overSingle.agent, overSingle.target, overSingle.amount, overSingle.calldataPayload, overSingle.nonce, overSingle.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_SINGLE_TX_CAP_EXCEEDED(),
                cSingle
            )
        );
        registry.authorizeAction(overSingle);

        // Spend 5M + 5M = 10M (hits exact daily cap)
        registry.authorizeAction(_validRequest(1, 5_000_000, ""));
        registry.authorizeAction(_validRequest(2, 5_000_000, ""));

        // 3rd tx of 1 uqor exceeds daily cap
        QoreGuardPolicyRegistry.ActionAuthRequest memory overDaily = _validRequest(3, 1, "");
        bytes32 cDaily = registry.computeCommitment(overDaily.agent, overDaily.target, overDaily.amount, overDaily.calldataPayload, overDaily.nonce, overDaily.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_DAILY_CAP_EXCEEDED(),
                cDaily
            )
        );
        registry.authorizeAction(overDaily);

        // Warp forward 2 full days -> sliding window decays to 0 -> tx 3 succeeds!
        vm.warp(block.timestamp + 2 days);
        assert(registry.currentSlidingWindowSpend(AGENT) == 0);
        registry.authorizeAction(_validRequest(3, 4_000_000, ""));
        assert(registry.getPolicy(AGENT).lastNonce == 3);
    }

    // -------------------------------------------------------------------------
    // 6. Blocked approve / setApprovalForAll Selector & Target Allowlist Reverts
    // -------------------------------------------------------------------------
    function test_RevertOnForbiddenApproveAndSetApprovalForAllSelectors() public {
        bytes memory approvePayload = abi.encodeWithSelector(SEL_APPROVE, ATTACKER, type(uint256).max);
        QoreGuardPolicyRegistry.ActionAuthRequest memory req1 = _validRequest(1, 0, approvePayload);
        bytes32 c1 = registry.computeCommitment(req1.agent, req1.target, req1.amount, req1.calldataPayload, req1.nonce, req1.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_SELECTOR_FORBIDDEN(),
                c1
            )
        );
        registry.authorizeAction(req1);

        bytes memory setAllPayload = abi.encodeWithSelector(SEL_SET_APPROVAL_ALL, ATTACKER, true);
        QoreGuardPolicyRegistry.ActionAuthRequest memory req2 = _validRequest(1, 0, setAllPayload);
        bytes32 c2 = registry.computeCommitment(req2.agent, req2.target, req2.amount, req2.calldataPayload, req2.nonce, req2.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_SELECTOR_FORBIDDEN(),
                c2
            )
        );
        registry.authorizeAction(req2);
    }

    function test_RevertOnDisallowedTargetAndDisallowedSelector() public {
        QoreGuardPolicyRegistry.ActionAuthRequest memory badTarget = _validRequest(1, 100, "");
        badTarget.target = TARGET_UNKNOWN;
        bytes32 c1 = registry.computeCommitment(badTarget.agent, badTarget.target, badTarget.amount, badTarget.calldataPayload, badTarget.nonce, badTarget.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_TARGET_NOT_ALLOWED(),
                c1
            )
        );
        registry.authorizeAction(badTarget);

        // Unknown 4-byte selector 0xdeadbeef not in allowedSelectors
        QoreGuardPolicyRegistry.ActionAuthRequest memory badSel = _validRequest(1, 100, hex"deadbeef00000000");
        bytes32 c2 = registry.computeCommitment(badSel.agent, badSel.target, badSel.amount, badSel.calldataPayload, badSel.nonce, badSel.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_SELECTOR_NOT_ALLOWED(),
                c2
            )
        );
        registry.authorizeAction(badSel);
    }

    // -------------------------------------------------------------------------
    // 7. Emergency Owner Revocation, Access Control & Window/Intent Expiry
    // -------------------------------------------------------------------------
    function test_EmergencyOwnerRevocationAndNonOwnerRevert() public {
        vm.prank(ATTACKER);
        vm.expectRevert(QoreGuardPolicyRegistry.NotPolicyOwner.selector);
        registry.revokeAgent(AGENT, keccak256("hijack"));

        vm.prank(OWNER);
        registry.revokeAgent(AGENT, keccak256("prompt-injection-detected"));
        assert(registry.getPolicy(AGENT).revoked == true);
        assert(registry.getPolicy(AGENT).active == false);

        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, 100, "");
        bytes32 c = registry.computeCommitment(req.agent, req.target, req.amount, req.calldataPayload, req.nonce, req.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_AGENT_INACTIVE_OR_REVOKED(),
                c
            )
        );
        registry.authorizeAction(req);
    }

    function test_RevertOnExpiredIntentAndExpiredPolicyWindow() public {
        QoreGuardPolicyRegistry.ActionAuthRequest memory expIntent = _validRequest(1, 100, "");
        expIntent.expiresAt = uint64(block.timestamp - 1);
        bytes32 c1 = registry.computeCommitment(expIntent.agent, expIntent.target, expIntent.amount, expIntent.calldataPayload, expIntent.nonce, expIntent.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_INTENT_EXPIRED(),
                c1
            )
        );
        registry.authorizeAction(expIntent);

        // Warp past 7-day EVM policy window
        vm.warp(block.timestamp + 8 days);
        QoreGuardPolicyRegistry.ActionAuthRequest memory expWin = _validRequest(1, 100, "");
        bytes32 c2 = registry.computeCommitment(expWin.agent, expWin.target, expWin.amount, expWin.calldataPayload, expWin.nonce, expWin.expiresAt);
        vm.expectRevert(
            abi.encodeWithSelector(
                QoreGuardPolicyRegistry.PolicyRejectedError.selector,
                registry.REASON_WINDOW_EXPIRED(),
                c2
            )
        );
        registry.authorizeAction(expWin);
    }

    // -------------------------------------------------------------------------
    // 8. Non-Reverting Forensic Audit Mode (`PolicyRejected` & `PolicyApproved`)
    // -------------------------------------------------------------------------
    function test_EvaluateAndLogEmitsPolicyRejectedWithoutAdvancingNonce() public {
        QoreGuardPolicyRegistry.ActionAuthRequest memory badReq = _validRequest(1, 500_000, "");
        badReq.pqSignature = ""; // quantum downgrade

        (bool approved, bytes32 reason, bytes32 digest) = registry.evaluateAndLogAction(badReq);
        assert(!approved);
        assert(reason == registry.REASON_QUANTUM_DOWNGRADE());
        assert(digest != bytes32(0));
        assert(registry.getPolicy(AGENT).lastNonce == 0);

        // Valid request immediately after succeeds with nonce 1
        (bool ok2, bytes32 reason2, bytes32 digest2) = registry.evaluateAndLogAction(_validRequest(1, 500_000, ""));
        assert(ok2);
        assert(reason2 == bytes32(0));
        assert(digest2 != bytes32(0));
        assert(registry.getPolicy(AGENT).lastNonce == 1);
    }

    // -------------------------------------------------------------------------
    // 9. Fuzz Test: Single-Tx Spend Cap Invariant Never Violated
    // -------------------------------------------------------------------------
    function testFuzz_SpendCapInvariant(uint256 rawAmount) public {
        uint256 amount = rawAmount % 20_000_000;
        QoreGuardPolicyRegistry.ActionAuthRequest memory req = _validRequest(1, amount, "");
        (bool approved, bytes32 reason,) = registry.evaluateAndLogAction(req);
        if (amount > 5_000_000) {
            assert(!approved);
            assert(reason == registry.REASON_SINGLE_TX_CAP_EXCEEDED());
            assert(registry.getPolicy(AGENT).lastNonce == 0);
        } else {
            assert(approved);
            assert(registry.getPolicy(AGENT).lastNonce == 1);
            assert(registry.currentSlidingWindowSpend(AGENT) == amount);
        }
    }
}
