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
///      30-day maximum owner-to-agent link TTL with renewal/re-linking, Scoped EVM Windows (startBlock, endBlock,
///      maxTxCount, maxTotalValue, allowedTargets), authenticated messaging (`qorechain-msg-v1|<chainId>|<data>`
///      hybrid secp256k1 + ML-DSA-87), on-chain AI risk/anomaly bounds via 0x...0B01 and 0x...0B02, per-tx & O(1)
///      sliding-window daily spend caps, 4-byte calldata selector firewalls, strict monotonic nonces, and revocation.
contract QoreGuardPolicyRegistry {
    // -------------------------------------------------------------------------
    // Fixed QoreChain EVM Precompile Addresses
    // -------------------------------------------------------------------------
    address public constant PQC_VERIFY_PRECOMPILE = address(0x0A01);
    address public constant PQC_KEY_STATUS_PRECOMPILE = address(0x0A02);
    address public constant AI_RISK_SCORE_PRECOMPILE = address(0x0B01);
    address public constant AI_ANOMALY_CHECK_PRECOMPILE = address(0x0B02);

    // -------------------------------------------------------------------------
    // Post-Quantum, Link TTL & Authenticated Messaging Constants
    // -------------------------------------------------------------------------
    uint8 public constant ML_DSA_87_ALGORITHM_ID = 3;
    uint256 public constant ML_DSA_87_PUBKEY_BYTES = 2592;
    uint256 public constant ML_DSA_87_SIGNATURE_BYTES = 4627;

    /// @notice Maximum owner-to-agent link lease duration (owner must renew/re-link at least every 30 days).
    uint64 public constant MAX_LINK_TTL = 30 days;

    /// @notice Official QoreChain authenticated message domain prefix (`qorechain-msg-v1|<chainId>|<data>`).
    string public constant AUTH_MSG_PREFIX = "qorechain-msg-v1|";

    /// @dev Half-order of secp256k1 curve (EIP-2 signature malleability ceiling).
    uint256 private constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    bytes4 public constant SELECTOR_ERC20_APPROVE = 0x095ea7b3;
    bytes4 public constant SELECTOR_SET_APPROVAL_FOR_ALL = 0xa22cb465;

    bytes32 public constant COMMIT_DOMAIN_TAG = keccak256("qoreguard-evm-policy-commit-v1|");
    bytes32 public constant DECISION_DOMAIN_TAG = keccak256("qoreguard-evm-decision-v1|");

    // Structured machine-readable rejection reason codes (for PolicyRejected events)
    bytes32 public constant REASON_AGENT_INACTIVE_OR_REVOKED = keccak256("AGENT_INACTIVE_OR_REVOKED");
    bytes32 public constant REASON_AGENT_LINK_EXPIRED = keccak256("AGENT_LINK_TTL_EXPIRED");
    bytes32 public constant REASON_WINDOW_EXPIRED = keccak256("EVM_WINDOW_EXPIRED");
    bytes32 public constant REASON_INTENT_EXPIRED = keccak256("INTENT_EXPIRED");
    bytes32 public constant REASON_SCOPED_BLOCK_OUT_OF_RANGE = keccak256("SCOPED_BLOCK_OUT_OF_RANGE");
    bytes32 public constant REASON_SCOPED_TX_COUNT_EXCEEDED = keccak256("SCOPED_TX_COUNT_EXCEEDED");
    bytes32 public constant REASON_SCOPED_VALUE_CAP_EXCEEDED = keccak256("SCOPED_TOTAL_VALUE_EXCEEDED");
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
    error LinkTtlExceeded();
    error InvalidScopedWindow();
    error InvalidAuthMessageFormat();
    error NotPolicyOwner();
    error AgentNotController();
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
        uint64 linkExpiresAt;
        uint64 lastNonce;
        uint8 maxAiRiskLevel;
        bool requireOnchainKeyStatus;
        bool requireAiPrecompile;
        bool enforceTargetAllowlist;
        bool enforceSelectorAllowlist;
        bool active;
        bool revoked;
    }

    struct ScopedEvmWindow {
        bool enabled;
        bool hasWindowTargets;
        uint64 windowId;
        uint64 startBlock;
        uint64 endBlock;
        uint64 maxTxCount;
        uint64 usedTxCount;
        uint256 maxTotalValue;
        uint256 usedTotalValue;
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

    struct AuthMessageInput {
        string chainId;
        bytes data;
        bytes secpSignature;
        bytes pqPubkey;
        bytes pqSignature;
    }

    mapping(address => AgentPolicy) private _policies;
    mapping(address => SlidingWindowLedger) private _ledgers;
    mapping(address => ScopedEvmWindow) private _scopedWindows;
    mapping(address => mapping(uint64 => mapping(address => bool))) private _windowAllowedTargets;
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
        uint64 validUntil,
        uint64 linkExpiresAt
    );

    event AgentLinkRenewed(
        address indexed agent,
        address indexed owner,
        uint64 newExpiresAt
    );

    event AgentKeyRelinked(
        address indexed agent,
        address indexed owner,
        bytes32 indexed newPqPubkeyHash,
        uint64 newExpiresAt
    );

    event ScopedEvmWindowOpened(
        address indexed agent,
        address indexed owner,
        uint64 indexed windowId,
        uint64 startBlock,
        uint64 endBlock,
        uint64 maxTxCount,
        uint256 maxTotalValue,
        uint256 targetCount
    );

    event ScopedEvmWindowClosed(
        address indexed agent,
        address indexed owner,
        uint64 indexed windowId
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
    // Policy, 30-Day Link Lease & Scoped EVM Window Management
    // -------------------------------------------------------------------------

    /// @notice Registers or updates a scoped post-quantum policy for `input.agent`.
    /// @dev The first registration must be sent by `input.agent` itself. A later update
    ///      must come from that same owner. This stops a third party from binding a
    ///      public key to an agent address they do not control (and later emitting
    ///      `PolicyApproved` under that binding). Also enforces
    ///      `input.validUntil <= block.timestamp + MAX_LINK_TTL` (30 days) and pre-seeds
    ///      dangerous ERC-20 / ERC-721 approval selectors in `forbiddenSelectors`.
    function registerAgentPolicy(
        RegistrationInput calldata input,
        address[] calldata initialTargets,
        bytes4[] calldata initialSelectors
    ) external {
        if (input.agent == address(0)) revert ZeroAddress();

        AgentPolicy storage existing = _policies[input.agent];
        if (existing.owner == address(0)) {
            if (msg.sender != input.agent) revert AgentNotController();
        } else if (existing.owner != msg.sender) {
            revert NotPolicyOwner();
        }

        if (
            input.pqPubkeyHash == bytes32(0) ||
            input.maxSingleTxAmount == 0 ||
            input.dailyCapAmount < input.maxSingleTxAmount ||
            input.windowDuration == 0 ||
            input.validUntil <= block.timestamp
        ) {
            revert InvalidPolicyParams();
        }
        uint64 maxLinkExpiry = uint64(block.timestamp) + MAX_LINK_TTL;
        if (input.validUntil > maxLinkExpiry) {
            revert LinkTtlExceeded();
        }

        existing.owner = msg.sender;
        existing.pqPubkeyHash = input.pqPubkeyHash;
        existing.maxSingleTxAmount = input.maxSingleTxAmount;
        existing.dailyCapAmount = input.dailyCapAmount;
        existing.windowDuration = input.windowDuration;
        existing.validUntil = input.validUntil;
        existing.linkExpiresAt = maxLinkExpiry;
        existing.maxAiRiskLevel = input.maxAiRiskLevel;
        existing.requireOnchainKeyStatus = input.requireOnchainKeyStatus;
        existing.requireAiPrecompile = input.requireAiPrecompile;
        existing.enforceTargetAllowlist = input.enforceTargetAllowlist;
        existing.enforceSelectorAllowlist = input.enforceSelectorAllowlist;
        existing.active = true;
        existing.revoked = false;

        // Default selector firewall: forbid unbounded token approvals
        _seedInitialAllowlists(input.agent, initialTargets, initialSelectors);

        emit AgentPolicyRegistered(
            input.agent,
            msg.sender,
            input.pqPubkeyHash,
            input.maxSingleTxAmount,
            input.dailyCapAmount,
            input.validUntil,
            maxLinkExpiry
        );
    }

    function _seedInitialAllowlists(
        address agent,
        address[] calldata initialTargets,
        bytes4[] calldata initialSelectors
    ) internal {
        forbiddenSelectors[agent][SELECTOR_ERC20_APPROVE] = true;
        forbiddenSelectors[agent][SELECTOR_SET_APPROVAL_FOR_ALL] = true;

        uint256 tLen = initialTargets.length;
        for (uint256 i = 0; i < tLen; ++i) {
            address tgt = initialTargets[i];
            if (tgt == address(0)) revert ZeroAddress();
            allowedTargets[agent][tgt] = true;
            emit TargetAllowlistUpdated(agent, tgt, true);
        }

        uint256 sLen = initialSelectors.length;
        for (uint256 i = 0; i < sLen; ++i) {
            bytes4 sel = initialSelectors[i];
            allowedSelectors[agent][sel] = true;
            emit SelectorPolicyUpdated(agent, sel, true, forbiddenSelectors[agent][sel]);
        }
    }

    /// @notice Renews or re-links an owner-to-agent lease for up to `MAX_LINK_TTL` (30 days) from `block.timestamp`.
    function renewAgentLink(address agent, uint64 newExpiresAt) external onlyPolicyOwner(agent) {
        if (newExpiresAt <= block.timestamp || newExpiresAt > uint64(block.timestamp) + MAX_LINK_TTL) {
            revert LinkTtlExceeded();
        }
        AgentPolicy storage policy = _policies[agent];
        policy.linkExpiresAt = newExpiresAt;
        policy.validUntil = newExpiresAt;
        policy.active = true;
        policy.revoked = false;
        emit AgentLinkRenewed(agent, msg.sender, newExpiresAt);
    }

    /// @notice Rotates the agent's registered ML-DSA-87 public-key hash and re-links for up to `MAX_LINK_TTL`.
    function relinkAgentKey(
        address agent,
        bytes32 newPqPubkeyHash,
        uint64 newExpiresAt
    ) external onlyPolicyOwner(agent) {
        if (newPqPubkeyHash == bytes32(0)) revert InvalidPolicyParams();
        if (newExpiresAt <= block.timestamp || newExpiresAt > uint64(block.timestamp) + MAX_LINK_TTL) {
            revert LinkTtlExceeded();
        }
        AgentPolicy storage policy = _policies[agent];
        policy.pqPubkeyHash = newPqPubkeyHash;
        policy.linkExpiresAt = newExpiresAt;
        policy.validUntil = newExpiresAt;
        policy.active = true;
        policy.revoked = false;
        emit AgentKeyRelinked(agent, msg.sender, newPqPubkeyHash, newExpiresAt);
    }

    /// @notice Opens a Scoped EVM Window bounding block height `[startBlock, endBlock]`, total tx count,
    ///         cumulative value, and optional window-specific target allowlist.
    function openScopedEvmWindow(
        address agent,
        uint64 startBlock,
        uint64 endBlock,
        uint64 maxTxCount,
        uint256 maxTotalValue,
        address[] calldata windowTargets
    ) external onlyPolicyOwner(agent) {
        if (
            endBlock < startBlock ||
            endBlock < uint64(block.number) ||
            maxTxCount == 0 ||
            maxTotalValue == 0
        ) {
            revert InvalidScopedWindow();
        }
        ScopedEvmWindow storage win = _scopedWindows[agent];
        uint64 wid = win.windowId + 1;
        uint256 wLen = windowTargets.length;

        for (uint256 i = 0; i < wLen; ++i) {
            address tgt = windowTargets[i];
            if (tgt == address(0)) revert ZeroAddress();
            _windowAllowedTargets[agent][wid][tgt] = true;
        }

        win.enabled = true;
        win.hasWindowTargets = wLen > 0;
        win.windowId = wid;
        win.startBlock = startBlock;
        win.endBlock = endBlock;
        win.maxTxCount = maxTxCount;
        win.usedTxCount = 0;
        win.maxTotalValue = maxTotalValue;
        win.usedTotalValue = 0;

        emit ScopedEvmWindowOpened(
            agent,
            msg.sender,
            wid,
            startBlock,
            endBlock,
            maxTxCount,
            maxTotalValue,
            wLen
        );
    }

    /// @notice Closes the active Scoped EVM Window for `agent`.
    function closeScopedEvmWindow(address agent) external onlyPolicyOwner(agent) {
        ScopedEvmWindow storage win = _scopedWindows[agent];
        win.enabled = false;
        emit ScopedEvmWindowClosed(agent, msg.sender, win.windowId);
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
    // Official Authenticated Messaging (`qorechain-msg-v1|<chainId>|<data>`)
    // -------------------------------------------------------------------------

    /// @notice Formats the canonical QoreChain authenticated message payload `qorechain-msg-v1|<chainId>|<data>`.
    /// @dev Rejects empty `chainId` or `'|'` delimiter injection inside `chainId` to ensure unambiguous framing.
    function formatAuthenticatedMessage(
        string calldata chainId,
        bytes calldata data
    ) public pure returns (bytes memory) {
        bytes calldata cid = bytes(chainId);
        uint256 cLen = cid.length;
        if (cLen == 0) revert InvalidAuthMessageFormat();
        for (uint256 i = 0; i < cLen; ++i) {
            if (cid[i] == 0x7c) revert InvalidAuthMessageFormat();
        }
        return abi.encodePacked(AUTH_MSG_PREFIX, chainId, "|", data);
    }

    /// @notice Verifies a hybrid `secp256k1` + `ML-DSA-87` signature over `qorechain-msg-v1|<chainId>|<data>`.
    function verifyAuthenticatedMessage(
        AuthMessageInput calldata msgInput,
        address expectedSecpSigner,
        bytes32 expectedPqPubkeyHash
    ) public view returns (bool valid, bytes32 messageHash) {
        bytes memory formatted = formatAuthenticatedMessage(msgInput.chainId, msgInput.data);
        messageHash = keccak256(formatted);

        if (expectedSecpSigner == address(0)) {
            return (false, messageHash);
        }
        address recovered = _recoverSecp256k1(messageHash, msgInput.secpSignature);
        if (recovered == address(0) || recovered != expectedSecpSigner) {
            return (false, messageHash);
        }

        if (
            msgInput.pqPubkey.length != ML_DSA_87_PUBKEY_BYTES ||
            msgInput.pqSignature.length != ML_DSA_87_SIGNATURE_BYTES
        ) {
            return (false, messageHash);
        }
        if (expectedPqPubkeyHash != bytes32(0) && keccak256(msgInput.pqPubkey) != expectedPqPubkeyHash) {
            return (false, messageHash);
        }

        bool pqOk = IQorePQCVerify(PQC_VERIFY_PRECOMPILE).pqcVerify(
            msgInput.pqPubkey,
            msgInput.pqSignature,
            formatted
        );
        return (pqOk, messageHash);
    }

    /// @notice Verifies an authenticated message signed by a registered, non-expired QoreGuard agent.
    function verifyAgentAuthenticatedMessage(
        address agent,
        AuthMessageInput calldata msgInput
    ) external view returns (bool valid, bytes32 messageHash) {
        AgentPolicy storage policy = _policies[agent];
        if (
            !policy.active ||
            policy.revoked ||
            block.timestamp > policy.linkExpiresAt ||
            block.timestamp > policy.validUntil
        ) {
            bytes memory formatted = formatAuthenticatedMessage(msgInput.chainId, msgInput.data);
            return (false, keccak256(formatted));
        }
        return verifyAuthenticatedMessage(msgInput, agent, policy.pqPubkeyHash);
    }

    // -------------------------------------------------------------------------
    // Read Helpers & Commitment Computation
    // -------------------------------------------------------------------------

    function getPolicy(address agent) external view returns (AgentPolicy memory) {
        return _policies[agent];
    }

    function getScopedEvmWindow(address agent) external view returns (ScopedEvmWindow memory) {
        return _scopedWindows[agent];
    }

    function isScopedWindowTargetAllowed(address agent, address target) external view returns (bool) {
        ScopedEvmWindow storage win = _scopedWindows[agent];
        if (!win.enabled) return allowedTargets[agent][target];
        if (!win.hasWindowTargets) return ! _policies[agent].enforceTargetAllowlist || allowedTargets[agent][target];
        return _windowAllowedTargets[agent][win.windowId][target];
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

    /// @notice Strict execution gate: verifies ML-DSA-87 + 30-day link TTL + Scoped EVM Window + AI risk + policy + nonce,
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

    function _recoverSecp256k1(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) return address(0);
        if (uint256(r) == 0 || uint256(s) == 0 || uint256(s) > SECP256K1N_HALF) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
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
        if (block.timestamp > policy.linkExpiresAt) {
            return REASON_AGENT_LINK_EXPIRED;
        }
        if (block.timestamp > policy.validUntil) {
            return REASON_WINDOW_EXPIRED;
        }
        if (block.timestamp > req.expiresAt) {
            return REASON_INTENT_EXPIRED;
        }

        // Scoped EVM Window bounds (startBlock, endBlock, maxTxCount, maxTotalValue, windowTargets)
        ScopedEvmWindow storage win = _scopedWindows[req.agent];
        if (win.enabled) {
            if (block.number < win.startBlock || block.number > win.endBlock) {
                return REASON_SCOPED_BLOCK_OUT_OF_RANGE;
            }
            if (win.usedTxCount + 1 > win.maxTxCount) {
                return REASON_SCOPED_TX_COUNT_EXCEEDED;
            }
            if (win.usedTotalValue + req.amount > win.maxTotalValue) {
                return REASON_SCOPED_VALUE_CAP_EXCEEDED;
            }
            if (win.hasWindowTargets && !_windowAllowedTargets[req.agent][win.windowId][req.target]) {
                return REASON_TARGET_NOT_ALLOWED;
            }
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
        ScopedEvmWindow storage win = _scopedWindows[req.agent];

        if (win.enabled) {
            win.usedTxCount += 1;
            win.usedTotalValue += req.amount;
        }

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
