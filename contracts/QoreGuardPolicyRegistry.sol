// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @title IQorePQCVerify
/// @notice QoreChain native EVM precompile at 0x0000000000000000000000000000000000000A01
///         for FIPS-204 ML-DSA-87 signature verification.
interface IQorePQCVerify {
    function pqcVerify(
        bytes calldata pubkey,
        bytes calldata signature,
        bytes calldata message
    ) external view returns (bool valid);
}

/// @title IQorePQCKeyStatus
/// @notice QoreChain native EVM precompile at 0x0000000000000000000000000000000000000A02
///         for on-chain post-quantum key registration and proof-of-possession status.
interface IQorePQCKeyStatus {
    function pqcKeyStatus(
        address account
    ) external view returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}

/// @title IQoreAIRiskScore
/// @notice QoreChain native EVM precompile at 0x0000000000000000000000000000000000000B01
///         for on-chain AI transaction risk scoring.
interface IQoreAIRiskScore {
    function aiRiskScore(bytes calldata txData) external view returns (uint256 score, uint8 level);
}

/// @title IQoreAIAnomalyCheck
/// @notice QoreChain native EVM precompile at 0x0000000000000000000000000000000000000B02
///         for on-chain AI sender/value anomaly detection.
interface IQoreAIAnomalyCheck {
    function aiAnomalyCheck(address sender, uint256 amount) external view returns (uint256 anomalyScore, bool flagged);
}

/// @title QoreGuardPolicyRegistry
/// @notice On-chain Post-Quantum AI Agent Policy Registry & Enforcement Gate for QoreChain / QoreX (EVM 9800).
/// @dev Enforces ML-DSA-87 (FIPS-204) post-quantum signatures via QoreChain precompiles 0x...0A01 and 0x...0A02,
///      on-chain AI risk/anomaly bounds via 0x...0B01 and 0x...0B02, per-tx & O(1) sliding-window daily spend caps,
///      target & 4-byte calldata selector firewalls, strict monotonic anti-replay nonces, and emergency owner revocation.
contract QoreGuardPolicyRegistry {
    // -------------------------------------------------------------------------
    // Fixed QoreChain EVM Precompile Addresses
    // -------------------------------------------------------------------------
    address public constant PQC_VERIFY_PRECOMPILE = address(0x0A01);
    address public constant PQC_KEY_STATUS_PRECOMPILE = address(0x0A02);
    address public constant AI_RISK_SCORE_PRECOMPILE = address(0x0B01);
    address public constant AI_ANOMALY_CHECK_PRECOMPILE = address(0x0B02);

    // -------------------------------------------------------------------------
    // Post-Quantum & Security Constants
    // -------------------------------------------------------------------------
    uint8 public constant ML_DSA_87_ALGORITHM_ID = 3;
    uint256 public constant ML_DSA_87_PUBKEY_BYTES = 2592;
    uint256 public constant ML_DSA_87_SIGNATURE_BYTES = 4627;

    bytes4 public constant SELECTOR_ERC20_APPROVE = 0x095ea7b3;
    bytes4 public constant SELECTOR_SET_APPROVAL_FOR_ALL = 0xa22cb465;

    bytes32 public constant COMMIT_DOMAIN_TAG = keccak256("qoreguard-evm-policy-commit-v1|");
    bytes32 public constant DECISION_DOMAIN_TAG = keccak256("qoreguard-evm-decision-v1|");

    // Structured machine-readable rejection reason codes (for PolicyRejected events)
    bytes32 public constant REASON_AGENT_INACTIVE_OR_REVOKED = keccak256("AGENT_INACTIVE_OR_REVOKED");
    bytes32 public constant REASON_WINDOW_EXPIRED = keccak256("EVM_WINDOW_EXPIRED");
    bytes32 public constant REASON_INTENT_EXPIRED = keccak256("INTENT_EXPIRED");
    bytes32 public constant REASON_NONCE_REPLAY_OR_GAP = keccak256("NONCE_REPLAY_OR_OUT_OF_ORDER");
    bytes32 public constant REASON_QUANTUM_DOWNGRADE = keccak256("QUANTUM_DOWNGRADE_DETECTED");
    bytes32 public constant REASON_PUBKEY_HASH_MISMATCH = keccak256("PUBKEY_HASH_MISMATCH");
    bytes32 public constant REASON_PQC_KEY_STATUS_INVALID = keccak256("PQC_KEY_STATUS_INVALID");
    bytes32 public constant REASON_PQC_SIGNATURE_INVALID = keccak256("PQC_SIGNATURE_INVALID");
    bytes32 public constant REASON_TARGET_NOT_ALLOWED = keccak256("TARGET_NOT_ALLOWLISTED");
    bytes32 public constant REASON_SELECTOR_FORBIDDEN = keccak256("SELECTOR_FORBIDDEN");
    bytes32 public constant REASON_SELECTOR_NOT_ALLOWED = keccak256("SELECTOR_NOT_ALLOWLISTED");
    bytes32 public constant REASON_SINGLE_TX_CAP_EXCEEDED = keccak256("SINGLE_TX_CAP_EXCEEDED");
    bytes32 public constant REASON_DAILY_CAP_EXCEEDED = keccak256("SLIDING_WINDOW_CAP_EXCEEDED");
    bytes32 public constant REASON_AI_RISK_EXCEEDED = keccak256("AI_RISK_THRESHOLD_EXCEEDED");
    bytes32 public constant REASON_AI_ANOMALY_FLAGGED = keccak256("AI_ANOMALY_FLAGGED");

    // -------------------------------------------------------------------------
    // Custom Errors
    // -------------------------------------------------------------------------
    error ZeroAddress();
    error InvalidPolicyParams();
    error NotPolicyOwner();
    error PolicyRejectedError(bytes32 reasonCode, bytes32 commitmentHash);

    // -------------------------------------------------------------------------
    // Storage Structures
    // -------------------------------------------------------------------------
    struct AgentPolicy {
        address owner;
        bytes32 pqPubkeyHash;
        uint256 maxSingleTxAmount;
        uint256 dailyCapAmount;
        uint64 windowDuration;
        uint64 validUntil;
        uint64 lastNonce;
        uint8 maxAiRiskLevel;
        bool requireOnchainKeyStatus;
        bool requireAiPrecompile;
        bool enforceTargetAllowlist;
        bool enforceSelectorAllowlist;
        bool active;
        bool revoked;
    }

    struct SlidingWindowLedger {
        uint64 lastEpoch;
        uint256 prevEpochSpend;
        uint256 curEpochSpend;
    }

    struct RegistrationInput {
        address agent;
        bytes32 pqPubkeyHash;
        uint256 maxSingleTxAmount;
        uint256 dailyCapAmount;
        uint64 windowDuration;
        uint64 validUntil;
        uint8 maxAiRiskLevel;
        bool requireOnchainKeyStatus;
        bool requireAiPrecompile;
        bool enforceTargetAllowlist;
        bool enforceSelectorAllowlist;
    }

    struct ActionAuthRequest {
        address agent;
        address target;
        uint256 amount;
        bytes calldataPayload;
        uint64 nonce;
        uint64 expiresAt;
        uint8 pqAlgorithmId;
        bytes pqPubkey;
        bytes pqSignature;
    }

    mapping(address => AgentPolicy) private _policies;
    mapping(address => SlidingWindowLedger) private _ledgers;
    mapping(address => mapping(address => bool)) public allowedTargets;
    mapping(address => mapping(bytes4 => bool)) public allowedSelectors;
    mapping(address => mapping(bytes4 => bool)) public forbiddenSelectors;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event AgentPolicyRegistered(
        address indexed agent,
        address indexed owner,
        bytes32 indexed pqPubkeyHash,
        uint256 maxSingleTxAmount,
        uint256 dailyCapAmount,
        uint64 validUntil
    );

    event TargetAllowlistUpdated(address indexed agent, address indexed target, bool allowed);
    event SelectorPolicyUpdated(address indexed agent, bytes4 indexed selector, bool allowed, bool forbidden);

    event PolicyApproved(
        address indexed agent,
        address indexed target,
        bytes4 indexed selector,
        uint256 amount,
        uint64 nonce,
        bytes32 commitmentHash,
        bytes32 decisionDigest
    );

    event PolicyRejected(
        address indexed agent,
        address indexed target,
        bytes4 indexed selector,
        uint256 amount,
        uint64 nonce,
        bytes32 commitmentHash,
        bytes32 reasonCode,
        bytes32 decisionDigest
    );

    event AgentRevoked(
        address indexed agent,
        address indexed revokedBy,
        bytes32 reasonHash,
        uint64 revokedAt
    );

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyPolicyOwner(address agent) {
        if (_policies[agent].owner != msg.sender) revert NotPolicyOwner();
        _;
    }

    // -------------------------------------------------------------------------
    // Policy Management
    // -------------------------------------------------------------------------

    /// @notice Registers or updates a scoped post-quantum policy for `input.agent`.
    /// @dev Pre-seeds dangerous ERC-20 / ERC-721 approval selectors in `forbiddenSelectors`.
    function registerAgentPolicy(
        RegistrationInput calldata input,
        address[] calldata initialTargets,
        bytes4[] calldata initialSelectors
    ) external {
        if (input.agent == address(0)) revert ZeroAddress();
        if (
            input.pqPubkeyHash == bytes32(0) ||
            input.maxSingleTxAmount == 0 ||
            input.dailyCapAmount < input.maxSingleTxAmount ||
            input.windowDuration == 0 ||
            input.validUntil <= block.timestamp
        ) {
            revert InvalidPolicyParams();
        }

        AgentPolicy storage existing = _policies[input.agent];
        if (existing.owner != address(0) && existing.owner != msg.sender) {
            revert NotPolicyOwner();
        }

        existing.owner = msg.sender;
        existing.pqPubkeyHash = input.pqPubkeyHash;
        existing.maxSingleTxAmount = input.maxSingleTxAmount;
        existing.dailyCapAmount = input.dailyCapAmount;
        existing.windowDuration = input.windowDuration;
        existing.validUntil = input.validUntil;
        existing.maxAiRiskLevel = input.maxAiRiskLevel;
        existing.requireOnchainKeyStatus = input.requireOnchainKeyStatus;
        existing.requireAiPrecompile = input.requireAiPrecompile;
        existing.enforceTargetAllowlist = input.enforceTargetAllowlist;
        existing.enforceSelectorAllowlist = input.enforceSelectorAllowlist;
        existing.active = true;
        existing.revoked = false;

        // Default selector firewall: forbid unbounded token approvals
        forbiddenSelectors[input.agent][SELECTOR_ERC20_APPROVE] = true;
        forbiddenSelectors[input.agent][SELECTOR_SET_APPROVAL_FOR_ALL] = true;

        uint256 tLen = initialTargets.length;
        for (uint256 i = 0; i < tLen; ++i) {
            address tgt = initialTargets[i];
            if (tgt == address(0)) revert ZeroAddress();
            allowedTargets[input.agent][tgt] = true;
            emit TargetAllowlistUpdated(input.agent, tgt, true);
        }

        uint256 sLen = initialSelectors.length;
        for (uint256 i = 0; i < sLen; ++i) {
            bytes4 sel = initialSelectors[i];
            allowedSelectors[input.agent][sel] = true;
            emit SelectorPolicyUpdated(input.agent, sel, true, forbiddenSelectors[input.agent][sel]);
        }

        emit AgentPolicyRegistered(
            input.agent,
            msg.sender,
            input.pqPubkeyHash,
            input.maxSingleTxAmount,
            input.dailyCapAmount,
            input.validUntil
        );
    }

    function setTargetAllowed(address agent, address target, bool allowed) external onlyPolicyOwner(agent) {
        if (target == address(0)) revert ZeroAddress();
        allowedTargets[agent][target] = allowed;
        emit TargetAllowlistUpdated(agent, target, allowed);
    }

    function setSelectorPolicy(
        address agent,
        bytes4 selector,
        bool allowed,
        bool forbidden
    ) external onlyPolicyOwner(agent) {
        allowedSelectors[agent][selector] = allowed;
        forbiddenSelectors[agent][selector] = forbidden;
        emit SelectorPolicyUpdated(agent, selector, allowed, forbidden);
    }

    /// @notice Emergency kill-switch immediately disabling all future agent actions.
    function revokeAgent(address agent, bytes32 reasonHash) external onlyPolicyOwner(agent) {
        AgentPolicy storage policy = _policies[agent];
        policy.active = false;
        policy.revoked = true;
        emit AgentRevoked(agent, msg.sender, reasonHash, uint64(block.timestamp));
    }

    // -------------------------------------------------------------------------
    // Read Helpers & Commitment Computation
    // -------------------------------------------------------------------------

    function getPolicy(address agent) external view returns (AgentPolicy memory) {
        return _policies[agent];
    }

    function computeCommitment(
        address agent,
        address target,
        uint256 amount,
        bytes calldata calldataPayload,
        uint64 nonce,
        uint64 expiresAt
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                COMMIT_DOMAIN_TAG,
                block.chainid,
                address(this),
                agent,
                target,
                amount,
                keccak256(calldataPayload),
                nonce,
                expiresAt
            )
        );
    }

    /// @notice Computes the O(1) two-epoch weighted sliding-window spend at `block.timestamp`.
    function currentSlidingWindowSpend(address agent) public view returns (uint256) {
        AgentPolicy storage policy = _policies[agent];
        uint64 duration = policy.windowDuration;
        if (duration == 0) return 0;

        SlidingWindowLedger storage ledger = _ledgers[agent];
        uint64 curEpoch = uint64(block.timestamp / uint256(duration));
        uint256 epochStart = uint256(curEpoch) * uint256(duration);
        uint256 elapsed = block.timestamp - epochStart;

        uint256 prevSpend;
        uint256 curSpend;
        if (curEpoch <= ledger.lastEpoch) {
            prevSpend = ledger.prevEpochSpend;
            curSpend = ledger.curEpochSpend;
        } else if (curEpoch <= ledger.lastEpoch + 1) {
            prevSpend = ledger.curEpochSpend;
            curSpend = 0;
        } else {
            return 0;
        }

        uint256 remainingWeight = uint256(duration) - elapsed;
        return curSpend + (prevSpend * remainingWeight) / uint256(duration);
    }

    // -------------------------------------------------------------------------
    // Authorization & Audit Gate
    // -------------------------------------------------------------------------

    /// @notice Strict execution gate: verifies ML-DSA-87 + AI risk + policy + nonce,
    ///         commits state on pass, and REVERTS with `PolicyRejectedError` on any violation.
    function authorizeAction(
        ActionAuthRequest calldata req
    ) external returns (bytes32 commitmentHash, bytes32 decisionDigest) {
        bytes4 selector = _extractSelector(req.calldataPayload);
        commitmentHash = computeCommitment(
            req.agent,
            req.target,
            req.amount,
            req.calldataPayload,
            req.nonce,
            req.expiresAt
        );

        bytes32 reasonCode = _checkRequest(req, selector, commitmentHash);
        if (reasonCode != bytes32(0)) {
            revert PolicyRejectedError(reasonCode, commitmentHash);
        }

        decisionDigest = _commitApproved(req, selector, commitmentHash);
    }

    /// @notice Non-reverting forensic audit gate: emits `PolicyRejected` on violation
    ///         (without advancing nonce or spend) or commits state and emits `PolicyApproved` on pass.
    function evaluateAndLogAction(
        ActionAuthRequest calldata req
    ) external returns (bool approved, bytes32 reasonCode, bytes32 decisionDigest) {
        bytes4 selector = _extractSelector(req.calldataPayload);
        bytes32 commitmentHash = computeCommitment(
            req.agent,
            req.target,
            req.amount,
            req.calldataPayload,
            req.nonce,
            req.expiresAt
        );

        reasonCode = _checkRequest(req, selector, commitmentHash);
        if (reasonCode != bytes32(0)) {
            decisionDigest = keccak256(
                abi.encode(DECISION_DOMAIN_TAG, false, reasonCode, commitmentHash, block.timestamp)
            );
            emit PolicyRejected(
                req.agent,
                req.target,
                selector,
                req.amount,
                req.nonce,
                commitmentHash,
                reasonCode,
                decisionDigest
            );
            return (false, reasonCode, decisionDigest);
        }

        decisionDigest = _commitApproved(req, selector, commitmentHash);
        return (true, bytes32(0), decisionDigest);
    }

    // -------------------------------------------------------------------------
    // Internal Verification & State Commit
    // -------------------------------------------------------------------------

    function _extractSelector(bytes calldata data) internal pure returns (bytes4 sel) {
        if (data.length < 4) return bytes4(0);
        assembly {
            sel := calldataload(data.offset)
        }
    }

    function _checkRequest(
        ActionAuthRequest calldata req,
        bytes4 selector,
        bytes32 commitmentHash
    ) internal view returns (bytes32) {
        AgentPolicy storage policy = _policies[req.agent];
        if (!policy.active || policy.revoked) {
            return REASON_AGENT_INACTIVE_OR_REVOKED;
        }
        if (block.timestamp > policy.validUntil) {
            return REASON_WINDOW_EXPIRED;
        }
        if (block.timestamp > req.expiresAt) {
            return REASON_INTENT_EXPIRED;
        }
        if (req.nonce != policy.lastNonce + 1) {
            return REASON_NONCE_REPLAY_OR_GAP;
        }

        // Anti-quantum-downgrade enforcement: must be ML-DSA-87 (FIPS-204 L5) with exact lengths
        if (
            req.pqAlgorithmId < ML_DSA_87_ALGORITHM_ID ||
            req.pqPubkey.length != ML_DSA_87_PUBKEY_BYTES ||
            req.pqSignature.length != ML_DSA_87_SIGNATURE_BYTES
        ) {
            return REASON_QUANTUM_DOWNGRADE;
        }
        if (keccak256(req.pqPubkey) != policy.pqPubkeyHash) {
            return REASON_PUBKEY_HASH_MISMATCH;
        }

        // Target & 4-byte calldata selector firewall
        if (policy.enforceTargetAllowlist && !allowedTargets[req.agent][req.target]) {
            return REASON_TARGET_NOT_ALLOWED;
        }
        if (selector != bytes4(0)) {
            if (forbiddenSelectors[req.agent][selector]) {
                return REASON_SELECTOR_FORBIDDEN;
            }
            if (policy.enforceSelectorAllowlist && !allowedSelectors[req.agent][selector]) {
                return REASON_SELECTOR_NOT_ALLOWED;
            }
        }

        // Single-tx cap and O(1) sliding-window daily cap
        if (req.amount > policy.maxSingleTxAmount) {
            return REASON_SINGLE_TX_CAP_EXCEEDED;
        }
        uint256 rollingSpend = currentSlidingWindowSpend(req.agent);
        if (rollingSpend + req.amount > policy.dailyCapAmount) {
            return REASON_DAILY_CAP_EXCEEDED;
        }

        // QoreChain native precompile 0x...0A02: on-chain PQ key registration & proof of possession
        if (policy.requireOnchainKeyStatus) {
            (bool registered, uint8 algId, bytes memory regPubkey, bool possessionProven) =
                IQorePQCKeyStatus(PQC_KEY_STATUS_PRECOMPILE).pqcKeyStatus(req.agent);
            if (
                !registered ||
                !possessionProven ||
                algId < ML_DSA_87_ALGORITHM_ID ||
                keccak256(regPubkey) != policy.pqPubkeyHash
            ) {
                return REASON_PQC_KEY_STATUS_INVALID;
            }
        }

        // QoreChain native precompile 0x...0A01: live FIPS-204 ML-DSA-87 signature verification
        bool pqValid = IQorePQCVerify(PQC_VERIFY_PRECOMPILE).pqcVerify(
            req.pqPubkey,
            req.pqSignature,
            abi.encodePacked(commitmentHash)
        );
        if (!pqValid) {
            return REASON_PQC_SIGNATURE_INVALID;
        }

        // QoreChain native precompiles 0x...0B01 & 0x...0B02: on-chain AI risk & anomaly checks
        if (policy.requireAiPrecompile) {
            (uint256 riskScore, uint8 riskLevel) =
                IQoreAIRiskScore(AI_RISK_SCORE_PRECOMPILE).aiRiskScore(req.calldataPayload);
            if (riskLevel > policy.maxAiRiskLevel || riskScore >= 100) {
                return REASON_AI_RISK_EXCEEDED;
            }
            (uint256 anomalyScore, bool flagged) =
                IQoreAIAnomalyCheck(AI_ANOMALY_CHECK_PRECOMPILE).aiAnomalyCheck(req.agent, req.amount);
            if (flagged || anomalyScore >= 100) {
                return REASON_AI_ANOMALY_FLAGGED;
            }
        }

        return bytes32(0);
    }

    function _commitApproved(
        ActionAuthRequest calldata req,
        bytes4 selector,
        bytes32 commitmentHash
    ) internal returns (bytes32 decisionDigest) {
        AgentPolicy storage policy = _policies[req.agent];
        SlidingWindowLedger storage ledger = _ledgers[req.agent];

        uint64 duration = policy.windowDuration;
        uint64 curEpoch = uint64(block.timestamp / uint256(duration));

        if (curEpoch <= ledger.lastEpoch) {
            ledger.curEpochSpend += req.amount;
        } else if (curEpoch <= ledger.lastEpoch + 1) {
            ledger.prevEpochSpend = ledger.curEpochSpend;
            ledger.curEpochSpend = req.amount;
            ledger.lastEpoch = curEpoch;
        } else {
            ledger.prevEpochSpend = 0;
            ledger.curEpochSpend = req.amount;
            ledger.lastEpoch = curEpoch;
        }

        policy.lastNonce = req.nonce;

        decisionDigest = keccak256(
            abi.encode(DECISION_DOMAIN_TAG, true, bytes32(0), commitmentHash, block.timestamp)
        );

        emit PolicyApproved(
            req.agent,
            req.target,
            selector,
            req.amount,
            req.nonce,
            commitmentHash,
            decisionDigest
        );
    }
}
