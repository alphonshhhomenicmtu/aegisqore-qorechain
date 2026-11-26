// SPDX-License-Identifier: Apache-2.0
//
// Shared strongly-typed data contracts for QoreGuard hybrid PQ policy evaluation,
// anti-downgrade verification, and tamper-evident audit bundles.

import type { QoreNetworkName } from "./networks.js";

export type PqAlgorithm = "ml-dsa-87" | "ml-dsa-65" | "ml-dsa-44" | "slh-dsa-sha2-128f" | "slh-dsa-sha2-128s";
export type ClassicalAlgorithm = "secp256k1" | "ed25519";
export type SignatureTier = "hybrid-pqc" | "classical-only" | "shake-only";
export type SignBytesVersion = "v1" | "v2";

export type GuardRejectionCode =
  | "QUANTUM_DOWNGRADE_CLASSICAL_ONLY"
  | "QUANTUM_DOWNGRADE_SIGN_BYTES_V1"
  | "QUANTUM_DOWNGRADE_WEAK_ALGORITHM"
  | "PQC_SIGNATURE_MISSING"
  | "PQC_SIGNATURE_INVALID"
  | "CLASSICAL_SIGNATURE_INVALID"
  | "COMMITMENT_TAMPERED"
  | "PUBKEY_HASH_MISMATCH"
  | "INTENT_EXPIRED"
  | "AGENT_LINK_EXPIRED"
  | "AGENT_LINK_TTL_EXCEEDED"
  | "AGENT_REVOKED"
  | "SCOPED_EVM_BLOCK_OUT_OF_RANGE"
  | "SCOPED_EVM_TX_COUNT_EXCEEDED"
  | "SCOPED_EVM_VALUE_EXCEEDED"
  | "CHAIN_ID_MISMATCH"
  | "POLICY_HASH_MISMATCH"
  | "AGENT_ID_MISMATCH"
  | "NONCE_REPLAY"
  | "NONCE_OUT_OF_ORDER"
  | "SPEND_CAP_EXCEEDED"
  | "VELOCITY_SPEND_EXCEEDED"
  | "VELOCITY_COUNT_EXCEEDED"
  | "TARGET_NOT_ALLOWLISTED"
  | "TARGET_DENYLISTED"
  | "SELECTOR_NOT_ALLOWED"
  | "SELECTOR_FORBIDDEN"
  | "AI_RISK_THRESHOLD_EXCEEDED"
  | "AI_ANOMALY_FLAGGED"
  | "AUTH_MSG_FORMAT_INVALID"
  | "INVALID_VALUE";

export interface ScopedEvmWindowRule {
  readonly startBlock: number;
  readonly endBlock: number;
  readonly maxTxCount: number;
  readonly maxTotalValueUqor: string;
  readonly allowedTargets?: readonly string[];
}

export interface AgentLinkLease {
  readonly ownerAddress: string;
  readonly linkedAtUnix: number;
  readonly expiresAtUnix: number;
}

export interface AuthenticatedMessageEnvelope {
  readonly format: "qorechain-msg-v1";
  readonly chainId: string;
  readonly dataHex: string;
  readonly formattedMessageUtf8?: string;
  readonly formattedMessageHex: string;
  readonly messageKeccak256Hex: `0x${string}`;
  readonly secp256k1: {
    readonly evmAddress: string;
    readonly publicKeyHex: string;
    /** 65-byte recoverable ECDSA signature hex (`r[32] || s[32] || v[1]`). */
    readonly signatureHex: string;
  };
  readonly mldsa87: {
    readonly publicKeyHex: string;
    readonly pubkeyHashHex: string;
    readonly signatureHex: string;
  };
}

export interface AuthenticatedMessageVerification {
  readonly valid: boolean;
  readonly formatValid: boolean;
  readonly secp256k1Valid: boolean;
  readonly mldsa87Valid: boolean;
  readonly pubkeyHashMatches: boolean;
  readonly recoveredEvmAddress: string | null;
  readonly messageKeccak256Hex: `0x${string}` | null;
  readonly codes: readonly GuardRejectionCode[];
}

export interface VelocityWindowRule {
  /** Human-readable window label (e.g. "5m_burst", "24h_daily"). */
  readonly label: string;
  /** Rolling window duration in seconds. */
  readonly windowSec: number;
  /** Maximum cumulative spend in uqor within the window (decimal string or bigint). */
  readonly maxSpendUqor: string;
  /** Maximum number of authorized transactions within the window. */
  readonly maxTxCount: number;
}

export interface AgentPolicy {
  readonly policyId: string;
  readonly agentId: string;
  readonly network: QoreNetworkName;
  readonly chainId: string;
  readonly evmChainId: number;
  /** Enforces hybrid classical + post-quantum authorization on every tx. */
  readonly requireHybridPqc: boolean;
  /** Minimum NIST PQC security level accepted (default: ml-dsa-87 = FIPS-204 L5). */
  readonly minPqAlgorithm: PqAlgorithm;
  /** Required QoreChain hybrid sign-bytes framing version ("v2" on qorechain-diana/vladi). */
  readonly requiredSignBytesVersion: SignBytesVersion;
  /** Pay-to-pubkey-hash binding: 32-byte SHAKE-256 hex digest of registered agent PQ pubkey. */
  readonly registeredPqPubkeyHashHex?: string;
  /** Maximum single-transaction spend in uqor (1 QOR = 10^6 uqor). */
  readonly maxSingleTxUqor: string;
  /** Rolling time-window spend and transaction-count rate limits. */
  readonly velocityWindows: readonly VelocityWindowRule[];
  /** If non-empty, only these recipient/contract addresses (0x... or qor1...) are permitted. */
  readonly allowlistedTargets: readonly string[];
  /** Explicit denylist checked before allowlist. */
  readonly denylistedTargets: readonly string[];
  /** Optional allowlist of 4-byte EVM calldata selectors (e.g. "0xa9059cbb"). */
  readonly allowedSelectors?: readonly string[];
  /** Optional denylist of dangerous selectors (e.g. "0x095ea7b3" approve, "0xa22cb465" setApprovalForAll). */
  readonly forbiddenSelectors?: readonly string[];
  /** Maximum tolerable QoreChain IQoreAI risk level (0-100 scale or tier level). */
  readonly maxAiRiskLevel?: number;
  /** If true, enforces gap-free strictly sequential nonces (lastNonce + 1). */
  readonly requireStrictSequentialNonce: boolean;
  /** Optional owner-to-agent link lease (enforced <= 30 days MAX_AGENT_LINK_TTL_SEC). */
  readonly agentLink?: AgentLinkLease;
  /** Optional on-chain Scoped EVM Window bounds (startBlock, endBlock, maxTxCount, maxTotalValue, allowedTargets). */
  readonly scopedEvmWindow?: ScopedEvmWindowRule;
}

export interface HybridAgentIdentity {
  readonly agentId: string;
  readonly classicalAlgorithm: ClassicalAlgorithm;
  readonly classicalPublicKeyHex: string;
  readonly classicalSecretKeyHex: string;
  readonly evmAddress: string;
  readonly pqAlgorithm: PqAlgorithm;
  readonly pqPublicKeyHex: string;
  readonly pqSecretKeyHex: string;
  readonly pqPubkeyHashHex: string;
}

export interface PublicAgentIdentity {
  readonly agentId: string;
  readonly classicalAlgorithm: ClassicalAlgorithm;
  readonly classicalPublicKeyHex: string;
  readonly evmAddress: string;
  readonly pqAlgorithm: PqAlgorithm;
  readonly pqPublicKeyHex: string;
  readonly pqPubkeyHashHex: string;
}

export interface TransactionIntent {
  readonly agentId: string;
  readonly policyHashHex: string;
  readonly chainId: string;
  readonly evmChainId: number;
  readonly from: string;
  readonly to: string;
  /** Amount in uqor (decimal integer string). */
  readonly valueUqor: string;
  /** Optional 0x-prefixed EVM calldata (default "0x"). */
  readonly calldataHex: string;
  /** Monotonically increasing anti-replay nonce (>= 1). */
  readonly nonce: number;
  /** Expiration UNIX timestamp in seconds. */
  readonly expiresAtUnix: number;
  /** Optional EVM block number for Scoped EVM Window evaluation. */
  readonly blockNumber?: number;
  /** Optional human-readable intent memo. */
  readonly memo?: string;
}

export interface HybridSignedEnvelope {
  readonly signatureTier: SignatureTier;
  readonly signBytesVersion: SignBytesVersion;
  readonly intent: TransactionIntent;
  /** SHAKE-256 32-byte commitment hex over length-prefixed intent fields. */
  readonly commitmentHex: string;
  /** Framed QoreChain v2 hybrid sign bytes hex (domain || chainId || body || auth). */
  readonly hybridSignBytesHex: string;
  readonly classical: {
    readonly algorithm: ClassicalAlgorithm;
    readonly publicKeyHex: string;
    readonly signatureHex: string;
  };
  readonly pqc?: {
    readonly algorithm: PqAlgorithm;
    readonly publicKeyHex: string;
    readonly pubkeyHashHex: string;
    readonly signatureHex: string;
  };
}

export interface AiPreflightSignal {
  readonly riskScore: number;
  readonly riskLevel: number;
  readonly anomalyFlagged: boolean;
  readonly source: "onchain-precompile" | "local-heuristic";
}

export interface CryptoVerificationResult {
  readonly valid: boolean;
  readonly classicalValid: boolean;
  readonly pqcValid: boolean;
  readonly commitmentMatches: boolean;
  readonly pubkeyHashMatches: boolean;
  readonly downgradeDetected: boolean;
  readonly codes: readonly GuardRejectionCode[];
  readonly computedCommitmentHex: string;
}

export interface PolicyDecision {
  readonly decisionId: string;
  readonly verdict: "ALLOW" | "DENY";
  readonly committed: boolean;
  readonly evaluatedAtUnix: number;
  readonly policyId: string;
  readonly policyHashHex: string;
  readonly agentId: string;
  readonly nonce: number;
  readonly valueUqor: string;
  readonly to: string;
  readonly signatureTier: SignatureTier;
  readonly pqAlgorithm: PqAlgorithm | "none";
  readonly signBytesVersion: SignBytesVersion;
  readonly rejectionCodes: readonly GuardRejectionCode[];
  readonly reasons: readonly string[];
  readonly crypto: CryptoVerificationResult;
  readonly velocitySnapshot: readonly {
    readonly label: string;
    readonly windowSpendUqor: string;
    readonly maxSpendUqor: string;
    readonly windowTxCount: number;
    readonly maxTxCount: number;
  }[];
  readonly aiSignal?: AiPreflightSignal;
  readonly decisionDigestHex: string;
}

export interface AuditLogEntry {
  readonly seq: number;
  readonly timestampUnix: number;
  readonly decision: PolicyDecision;
  readonly prevEntryHashHex: string;
  readonly entryHashHex: string;
}

export interface AuditBundle {
  readonly version: "qoreguard-audit-v1";
  readonly exportedAtUnix: number;
  readonly policyId: string;
  readonly policyHashHex: string;
  readonly network: QoreNetworkName;
  readonly chainId: string;
  readonly evmChainId: number;
  readonly entryCount: number;
  readonly allowedCount: number;
  readonly deniedCount: number;
  readonly blockedDowngradeCount: number;
  readonly chainHeadHashHex: string;
  readonly entries: readonly AuditLogEntry[];
  readonly attestation?: {
    readonly domain: string;
    readonly pqAlgorithm: PqAlgorithm;
    readonly pqPublicKeyHex: string;
    readonly pqPubkeyHashHex: string;
    readonly signatureHex: string;
  };
}

export type QuantumAttackVector =
  | "strip_pqc_to_classical_only"
  | "downgrade_sign_bytes_v2_to_v1"
  | "downgrade_algorithm_to_mldsa44"
  | "tamper_commitment_amount"
  | "tamper_pqc_signature_byte"
  | "replay_consumed_nonce";

export interface AttackSimulationResult {
  readonly vector: QuantumAttackVector;
  readonly description: string;
  readonly blocked: boolean;
  readonly expectedCodes: readonly GuardRejectionCode[];
  readonly observedCodes: readonly GuardRejectionCode[];
  readonly decision: PolicyDecision;
}
