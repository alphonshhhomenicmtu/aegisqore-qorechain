// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {QoreGuardPolicyRegistry} from "../QoreGuardPolicyRegistry.sol";
import {
    Vm,
    MockQorePQCVerify,
    MockQorePQCKeyStatus,
    MockQoreAIRiskScore,
    MockQoreAIAnomalyCheck
} from "./QoreGuardPolicyRegistry.t.sol";

/// @title AegisQoreHandler
/// @notice Stateful Foundry fuzz handler exercising policy registration, 30-day link leases,
///         scoped EVM windows, ML-DSA-87 action execution, emergency revocation, policy updates,
///         and `qorechain-msg-v1|<chainId>|<data>` anti-replay / cross-chain domain isolation.
contract AegisQoreHandler {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address public constant OWNER = address(0xA11CE);
    uint256 public constant AGENT_PK = 0xB0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0;
    address public immutable AGENT;
    address public constant ATTACKER = address(0xBAD);
    address public constant TARGET_ALLOWED = address(0x000000000000000000000000000000000000dEaD);
    address public constant TARGET_ALT = address(0x3333333333333333333333333333333333333333);

    bytes4 private constant SEL_TRANSFER = 0xa9059cbb;
    bytes4 private constant SEL_APPROVE = 0x095ea7b3;

    QoreGuardPolicyRegistry public immutable registry;
    bytes public validPubkey;
    bytes public validSig;
    bytes32 public validPubkeyHash;

    // Ghost invariant violation counters (all must remain 0)
    uint256 public ghost_singleTxCapViolations;
    uint256 public ghost_dailyCapViolations;
    uint256 public ghost_expiredLinkSuccesses;
    uint256 public ghost_revokedSuccesses;
    uint256 public ghost_replayOrCrossChainSuccesses;
    uint256 public ghost_unauthorizedOwnerOps;
    uint256 public ghost_weakAlgSuccesses;
    uint256 public ghost_scopedWindowViolations;

    // Ghost telemetry
    uint256 public ghost_totalApproved;
    uint256 public ghost_totalRejected;
    uint64 public ghost_lastNonce;
    uint256 public ghost_lastApprovedAmount;
    uint256 public ghost_singleCapAtLastApproval;
    uint256 public ghost_rollingAfterLastApproval;
    uint256 public ghost_dailyCapAtLastApproval;

    constructor(
        QoreGuardPolicyRegistry _registry,
        bytes memory _validPubkey,
        bytes memory _validSig
    ) {
        registry = _registry;
        AGENT = vm.addr(AGENT_PK);
        validPubkey = _validPubkey;
        validSig = _validSig;
        validPubkeyHash = keccak256(_validPubkey);
    }

    function _buildPayload(bytes4 selector, address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(selector, to, amount);
    }

    function _signAuthMsg(
        string memory chainId,
        bytes memory data,
        bool validSecp,
        bool validPq
    ) internal view returns (QoreGuardPolicyRegistry.AuthMessageInput memory input) {
        bytes memory formatted = abi.encodePacked("qorechain-msg-v1|", chainId, "|", data);
        bytes32 digest = keccak256(formatted);
        uint256 pk = validSecp ? AGENT_PK : (AGENT_PK + 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        bytes memory secpSig = abi.encodePacked(r, s, v);
        bytes memory pqSig = validPq ? validSig : new bytes(4627);
        input = QoreGuardPolicyRegistry.AuthMessageInput({
            chainId: chainId,
            data: data,
            secpSignature: secpSig,
            pqPubkey: validPubkey,
            pqSignature: pqSig
        });
    }

    /// @notice Exercises `authorizeAction` and `evaluateAndLogAction` across valid & adversarial inputs.
    function executeScopedPayment(
        uint256 amountSeed,
        uint256 targetSeed,
        uint8 nonceMode,
        uint8 algMode,
        bool useEvaluateGate,
        bool useForbiddenSelector
    ) external {
        QoreGuardPolicyRegistry.AgentPolicy memory pol = registry.getPolicy(AGENT);
        QoreGuardPolicyRegistry.ScopedEvmWindow memory win = registry.getScopedEvmWindow(AGENT);
        uint256 rollingBefore = registry.currentSlidingWindowSpend(AGENT);

        uint256 amount = (amountSeed % (pol.dailyCapAmount * 2 + 1));
        if (amount == 0) amount = 1;

        address target = (targetSeed % 4 == 0) ? TARGET_ALT : TARGET_ALLOWED;
        bytes4 sel = useForbiddenSelector ? SEL_APPROVE : SEL_TRANSFER;
        bytes memory payload = _buildPayload(sel, target, amount);

        uint64 nonce;
        if (nonceMode % 5 == 0) {
            nonce = pol.lastNonce; // duplicate replay
        } else if (nonceMode % 5 == 1) {
            nonce = pol.lastNonce + 2; // skipped nonce
        } else {
            nonce = pol.lastNonce + 1; // expected monotonic nonce
        }

        uint8 algId = (algMode % 6 == 0) ? 2 : 3; // 2 = weak ML-DSA-65 downgrade, 3 = ML-DSA-87
        uint64 expiresAt = uint64(block.timestamp + 300);

        QoreGuardPolicyRegistry.ActionAuthRequest memory req = QoreGuardPolicyRegistry.ActionAuthRequest({
            agent: AGENT,
            target: target,
            amount: amount,
            calldataPayload: payload,
            nonce: nonce,
            expiresAt: expiresAt,
            pqAlgorithmId: algId,
            pqPubkey: validPubkey,
            pqSignature: validSig
        });

        bool approved = false;
        if (useEvaluateGate) {
            (approved,,) = registry.evaluateAndLogAction(req);
        } else {
            try registry.authorizeAction(req) returns (bytes32, bytes32) {
                approved = true;
            } catch {
                approved = false;
            }
        }

        if (approved) {
            ghost_totalApproved += 1;
            ghost_lastApprovedAmount = amount;
            ghost_singleCapAtLastApproval = pol.maxSingleTxAmount;
            ghost_rollingAfterLastApproval = registry.currentSlidingWindowSpend(AGENT);
            ghost_dailyCapAtLastApproval = pol.dailyCapAmount;

            // Check invariant (a): single-tx cap & rolling 24h cap
            if (amount > pol.maxSingleTxAmount) {
                ghost_singleTxCapViolations += 1;
            }
            if (rollingBefore + amount > pol.dailyCapAmount) {
                ghost_dailyCapViolations += 1;
            }

            // Check invariant (b): 30-day MAX_LINK_TTL & revocation/pause
            if (block.timestamp > pol.linkExpiresAt || block.timestamp > pol.validUntil) {
                ghost_expiredLinkSuccesses += 1;
            }
            if (!pol.active || pol.revoked) {
                ghost_revokedSuccesses += 1;
            }

            // Check invariant (c): monotonic nonce (no replay or gap)
            if (nonce != pol.lastNonce + 1 || nonce <= ghost_lastNonce) {
                ghost_replayOrCrossChainSuccesses += 1;
            }
            ghost_lastNonce = nonce;

            // Check invariant (d): ML-DSA-87 only
            if (algId < 3) {
                ghost_weakAlgSuccesses += 1;
            }

            // Check Scoped EVM Window bounds if enabled
            if (win.enabled) {
                if (
                    block.number < win.startBlock ||
                    block.number > win.endBlock ||
                    win.usedTxCount + 1 > win.maxTxCount ||
                    win.usedTotalValue + amount > win.maxTotalValue
                ) {
                    ghost_scopedWindowViolations += 1;
                }
            }
        } else {
            ghost_totalRejected += 1;
            // Verify rejected action did NOT advance nonce
            QoreGuardPolicyRegistry.AgentPolicy memory polAfter = registry.getPolicy(AGENT);
            if (polAfter.lastNonce != pol.lastNonce) {
                ghost_replayOrCrossChainSuccesses += 1;
            }
        }
    }

    /// @notice Advances block timestamp (up to 35 days) and block number to test TTL & sliding windows.
    function warpTimeAndBlocks(uint256 deltaSecSeed, uint256 deltaBlockSeed) external {
        uint256 deltaSec = (deltaSecSeed % 35 days) + 1;
        uint256 deltaBlocks = (deltaBlockSeed % 50) + 1;
        vm.warp(block.timestamp + deltaSec);
        vm.roll(block.number + deltaBlocks);
    }

    /// @notice Exercises owner-only emergency revocation (`revokeAgent`) vs unauthorized attacker attempt.
    function revokeAgent(bool asAttacker) external {
        address caller = asAttacker ? ATTACKER : AGENT;
        vm.prank(caller);
        try registry.revokeAgent(AGENT, keccak256("INVARIANT_PAUSE")) {
            if (asAttacker) {
                ghost_unauthorizedOwnerOps += 1;
            }
        } catch {
            // Expected revert for non-owner
        }
    }

    /// @notice Exercises 30-day link renewal (`renewAgentLink`) and key rotation (`relinkAgentKey`).
    function linkAgent(uint256 ttlSeed, bool rotateKey, bool asAttacker) external {
        uint64 ttl = uint64((ttlSeed % 45 days) + 1); // includes >30d invalid TTLs
        uint64 newExpiry = uint64(block.timestamp) + ttl;
        address caller = asAttacker ? ATTACKER : AGENT;

        vm.prank(caller);
        if (rotateKey) {
            try registry.relinkAgentKey(AGENT, validPubkeyHash, newExpiry) {
                if (asAttacker || ttl > registry.MAX_LINK_TTL()) {
                    ghost_unauthorizedOwnerOps += 1;
                }
            } catch {
                // Expected revert on attacker or >30d TTL
            }
        } else {
            try registry.renewAgentLink(AGENT, newExpiry) {
                if (asAttacker || ttl > registry.MAX_LINK_TTL()) {
                    ghost_unauthorizedOwnerOps += 1;
                }
            } catch {
                // Expected revert on attacker or >30d TTL
            }
        }
    }

    /// @notice Exercises `registerAgentPolicy` / cap updates as owner vs unauthorized attacker.
    function updatePolicy(uint256 singleCapSeed, uint256 dailyCapSeed, bool asAttacker) external {
        uint256 singleCap = (singleCapSeed % 5_000_000) + 100_000;
        uint256 dailyCap = singleCap + (dailyCapSeed % 10_000_000);
        uint64 validUntil = uint64(block.timestamp + 14 days);

        address[] memory targets = new address[](1);
        targets[0] = TARGET_ALLOWED;
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = SEL_TRANSFER;

        address caller = asAttacker ? ATTACKER : AGENT;
        vm.prank(caller);
        try registry.registerAgentPolicy(
            QoreGuardPolicyRegistry.RegistrationInput({
                agent: AGENT,
                pqPubkeyHash: validPubkeyHash,
                maxSingleTxAmount: singleCap,
                dailyCapAmount: dailyCap,
                windowDuration: 1 days,
                validUntil: validUntil,
                maxAiRiskLevel: 2,
                requireOnchainKeyStatus: true,
                requireAiPrecompile: true,
                enforceTargetAllowlist: true,
                enforceSelectorAllowlist: true
            }),
            targets,
            selectors
        ) {
            if (asAttacker) {
                ghost_unauthorizedOwnerOps += 1;
            }
        } catch {
            // Expected revert for non-owner
        }
    }

    /// @notice Exercises `openScopedEvmWindow` and `closeScopedEvmWindow`.
    function toggleScopedWindow(bool openWindow, uint64 blockSpanSeed, uint64 maxTxSeed, uint256 maxValSeed) external {
        vm.prank(AGENT);
        if (openWindow) {
            uint64 span = (blockSpanSeed % 40) + 1;
            uint64 maxTx = (maxTxSeed % 5) + 1;
            uint256 maxVal = (maxValSeed % 10_000_000) + 100_000;
            address[] memory wTargets = new address[](1);
            wTargets[0] = TARGET_ALLOWED;
            registry.openScopedEvmWindow(
                AGENT,
                uint64(block.number),
                uint64(block.number) + span,
                maxTx,
                maxVal,
                wTargets
            );
        } else {
            registry.closeScopedEvmWindow(AGENT);
        }
    }

    /// @notice Exercises `qorechain-msg-v1|<chainId>|<data>` cross-chain & delimiter-injection isolation.
    function verifyAuthMessageDomain(bytes32 dataSeed, bool crossChainTamper, bool delimiterInject) external {
        bytes memory payload = abi.encodePacked(dataSeed);
        QoreGuardPolicyRegistry.AgentPolicy memory pol = registry.getPolicy(AGENT);

        if (delimiterInject) {
            QoreGuardPolicyRegistry.AuthMessageInput memory badDelim = _signAuthMsg("9800|evil", payload, true, true);
            try registry.verifyAgentAuthenticatedMessage(AGENT, badDelim) returns (bool valid, bytes32) {
                if (valid) {
                    ghost_replayOrCrossChainSuccesses += 1;
                }
            } catch {
                // Expected revert on '|' delimiter injection
            }
            return;
        }

        // Sign for chain "9800", then either verify as "9800" or replay under "9801" (cross-chain)
        QoreGuardPolicyRegistry.AuthMessageInput memory msgInput = _signAuthMsg("9800", payload, true, true);
        if (crossChainTamper) {
            msgInput.chainId = "9801";
        }

        (bool ok, bytes32 msgHash) = registry.verifyAgentAuthenticatedMessage(AGENT, msgInput);

        // Cross-chain replay must NEVER pass (ecrecover digest differs because chainId is inside signed framing)
        if (crossChainTamper && ok) {
            ghost_replayOrCrossChainSuccesses += 1;
        }

        // Inactive, revoked, or expired agent must NEVER pass
        if (
            ok &&
            (!pol.active || pol.revoked || block.timestamp > pol.linkExpiresAt || block.timestamp > pol.validUntil)
        ) {
            ghost_expiredLinkSuccesses += 1;
        }

        // Message hash must strictly match canonical `qorechain-msg-v1|<chainId>|<data>`
        bytes32 expectedHash = keccak256(abi.encodePacked("qorechain-msg-v1|", msgInput.chainId, "|", payload));
        if (msgHash != expectedHash) {
            ghost_replayOrCrossChainSuccesses += 1;
        }
    }
}

/// @title AegisQoreInvariantsTest
/// @notice Stateful Foundry invariant test suite for QoreGuardPolicyRegistry (256 runs / 8,192 calls per invariant).
contract AegisQoreInvariantsTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    QoreGuardPolicyRegistry private registry;
    AegisQoreHandler private handler;
    address[] private _targetContracts;

    function setUp() public {
        vm.warp(1_760_000_000);
        vm.roll(10_800_000);

        registry = new QoreGuardPolicyRegistry();

        MockQorePQCVerify mockVerify = new MockQorePQCVerify();
        MockQorePQCKeyStatus mockStatus = new MockQorePQCKeyStatus();
        MockQoreAIRiskScore mockRisk = new MockQoreAIRiskScore();
        MockQoreAIAnomalyCheck mockAnomaly = new MockQoreAIAnomalyCheck();

        vm.etch(registry.PQC_VERIFY_PRECOMPILE(), address(mockVerify).code);
        vm.etch(registry.PQC_KEY_STATUS_PRECOMPILE(), address(mockStatus).code);
        vm.etch(registry.AI_RISK_SCORE_PRECOMPILE(), address(mockRisk).code);
        vm.etch(registry.AI_ANOMALY_CHECK_PRECOMPILE(), address(mockAnomaly).code);

        MockQorePQCVerify(registry.PQC_VERIFY_PRECOMPILE()).setResult(true);
        MockQoreAIRiskScore(registry.AI_RISK_SCORE_PRECOMPILE()).setRisk(12, 1);
        MockQoreAIAnomalyCheck(registry.AI_ANOMALY_CHECK_PRECOMPILE()).setAnomaly(5, false);

        bytes memory validPubkey = new bytes(2592);
        bytes memory validSig = new bytes(4627);
        for (uint256 i = 0; i < 2592; ++i) {
            validPubkey[i] = 0x42;
        }
        for (uint256 i = 0; i < 4627; ++i) {
            validSig[i] = 0x77;
        }
        bytes32 validPubkeyHash = keccak256(validPubkey);

        handler = new AegisQoreHandler(registry, validPubkey, validSig);
        address agent = handler.AGENT();

        MockQorePQCKeyStatus(registry.PQC_KEY_STATUS_PRECOMPILE()).setKeyStatus(
            agent,
            true,
            3,
            validPubkey,
            true
        );

        address[] memory targets = new address[](1);
        targets[0] = handler.TARGET_ALLOWED();
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = 0xa9059cbb; // transfer

        vm.prank(handler.AGENT());
        registry.registerAgentPolicy(
            QoreGuardPolicyRegistry.RegistrationInput({
                agent: agent,
                pqPubkeyHash: validPubkeyHash,
                maxSingleTxAmount: 2_000_000,
                dailyCapAmount: 5_000_000,
                windowDuration: 1 days,
                validUntil: uint64(block.timestamp + 14 days),
                maxAiRiskLevel: 2,
                requireOnchainKeyStatus: true,
                requireAiPrecompile: true,
                enforceTargetAllowlist: true,
                enforceSelectorAllowlist: true
            }),
            targets,
            selectors
        );

        _targetContracts.push(address(handler));
    }

    function targetContracts() public view returns (address[] memory) {
        return _targetContracts;
    }

    /// @notice Invariant (a): No agent EVER exceeds per-tx cap or rolling 24h cap at execution time.
    function invariant_neverExceedsSingleTxOrRolling24hCap() public view {
        assert(handler.ghost_singleTxCapViolations() == 0);
        assert(handler.ghost_dailyCapViolations() == 0);
        assert(handler.ghost_lastApprovedAmount() <= handler.ghost_singleCapAtLastApproval());
        assert(handler.ghost_rollingAfterLastApproval() <= handler.ghost_dailyCapAtLastApproval());
    }

    /// @notice Invariant (b): No linked agent EVER executes past MAX_LINK_TTL (30 days) or after owner revocation.
    function invariant_neverExecutesPastMaxLinkTtlOrRevocation() public view {
        QoreGuardPolicyRegistry.AgentPolicy memory pol = registry.getPolicy(handler.AGENT());
        assert(handler.ghost_expiredLinkSuccesses() == 0);
        assert(handler.ghost_revokedSuccesses() == 0);
        assert(pol.validUntil <= pol.linkExpiresAt);
    }

    /// @notice Invariant (c): Nonce & `qorechain-msg-v1|<chainId>|<data>` NEVER allow cross-chain or duplicate replay.
    function invariant_neverAllowsCrossChainOrNonceReplay() public view {
        assert(handler.ghost_replayOrCrossChainSuccesses() == 0);
        assert(registry.getPolicy(handler.AGENT()).lastNonce == handler.ghost_lastNonce());
    }

    /// @notice Invariant (d): Only ML-DSA-87 and authorized owner can modify policy caps, renew links, or unpause.
    function invariant_onlyOwnerAndMlDsa87Enforced() public view {
        assert(handler.ghost_unauthorizedOwnerOps() == 0);
        assert(handler.ghost_weakAlgSuccesses() == 0);
        assert(registry.getPolicy(handler.AGENT()).owner == handler.AGENT());
        assert(registry.getPolicy(handler.AGENT()).owner != handler.OWNER());
    }

    /// @notice Invariant (e): Scoped EVM Windows strictly bound block height, tx count, and cumulative value.
    function invariant_scopedEvmWindowBoundsPreserved() public view {
        assert(handler.ghost_scopedWindowViolations() == 0);
        QoreGuardPolicyRegistry.ScopedEvmWindow memory win = registry.getScopedEvmWindow(handler.AGENT());
        if (win.enabled) {
            assert(win.usedTxCount <= win.maxTxCount);
            assert(win.usedTotalValue <= win.maxTotalValue);
        }
    }

    /// @notice Invariant (f): Approved count equals committed monotonic nonce across all stateful fuzz sequences.
    function invariant_approvedCountMatchesMonotonicNonce() public view {
        assert(handler.ghost_totalApproved() == handler.ghost_lastNonce());
        assert(registry.getPolicy(handler.AGENT()).lastNonce == handler.ghost_totalApproved());
    }
}
