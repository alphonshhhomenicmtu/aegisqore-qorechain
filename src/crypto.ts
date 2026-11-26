// SPDX-License-Identifier: Apache-2.0
//
// Hybrid Post-Quantum Cryptography Layer for QoreGuard.
// Combines @qorechain/pqc (FIPS-204 ML-DSA-87/65/44, FIPS-202 SHAKE-256,
// QoreChain v2 hybrid sign-bytes framing) + @noble/post-quantum (FIPS-205
// SLH-DSA stateless hash-based signatures) + @noble/curves (secp256k1/ed25519).

import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { slh_dsa_sha2_128f, slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import {
  hybridSignBytes,
  mldsa44,
  mldsa65,
  mldsa87,
  pubkeyHash,
  shake256,
  type SigScheme,
} from "@qorechain/pqc";
import { getAddress } from "viem";
import { QOREGUARD_DOMAINS } from "./networks.js";
import type {
  AgentPolicy,
  AuthenticatedMessageEnvelope,
  AuthenticatedMessageVerification,
  ClassicalAlgorithm,
  CryptoVerificationResult,
  GuardRejectionCode,
  HybridAgentIdentity,
  HybridSignedEnvelope,
  PqAlgorithm,
  PublicAgentIdentity,
  SignBytesVersion,
  SignatureTier,
  TransactionIntent,
} from "./types.js";

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true });

export const QORECHAIN_AUTH_MSG_PREFIX = QOREGUARD_DOMAINS.authenticatedMessagePrefix;

/** Numeric NIST post-quantum security rank for anti-downgrade comparison. */
export const PQ_SECURITY_LEVEL: Readonly<Record<PqAlgorithm, number>> = {
  "ml-dsa-44": 2,
  "slh-dsa-sha2-128f": 3,
  "slh-dsa-sha2-128s": 3,
  "ml-dsa-65": 3,
  "ml-dsa-87": 5,
};

export function toHexPrefixed(bytes: Uint8Array): `0x${string}` {
  return `0x${bytesToHex(bytes)}`;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length === 0) return new Uint8Array(0);
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error(`Invalid hex string (length=${clean.length})`);
  }
  return hexToBytes(clean);
}

/** Length-prefixed binary framing: BE32(len) || bytes for every field (collision-free). */
export function frameFields(fields: readonly (string | Uint8Array)[]): Uint8Array {
  const chunks = fields.map((f) => (typeof f === "string" ? TEXT_ENCODER.encode(f) : f));
  let total = 0;
  for (const c of chunks) total += 4 + c.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const c of chunks) {
    view.setUint32(offset, c.length, false);
    offset += 4;
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export function shake256Hex(data: Uint8Array, outLen = 32): string {
  return bytesToHex(shake256(data, outLen));
}

function getMldsaScheme(alg: "ml-dsa-87" | "ml-dsa-65" | "ml-dsa-44"): SigScheme {
  if (alg === "ml-dsa-87") return mldsa87;
  if (alg === "ml-dsa-65") return mldsa65;
  return mldsa44;
}

export function pqcKeygen(algorithm: PqAlgorithm = "ml-dsa-87", seed?: Uint8Array): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  pubkeyHashHex: string;
} {
  let kp: { publicKey: Uint8Array; secretKey: Uint8Array };
  if (algorithm === "slh-dsa-sha2-128f") {
    kp = slh_dsa_sha2_128f.keygen(seed);
  } else if (algorithm === "slh-dsa-sha2-128s") {
    kp = slh_dsa_sha2_128s.keygen(seed);
  } else {
    kp = getMldsaScheme(algorithm).keygen(seed);
  }
  return {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
    pubkeyHashHex: bytesToHex(pubkeyHash(kp.publicKey, 32)),
  };
}

export function pqcSignBytes(algorithm: PqAlgorithm, secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (algorithm === "slh-dsa-sha2-128f") {
    return slh_dsa_sha2_128f.sign(message, secretKey);
  }
  if (algorithm === "slh-dsa-sha2-128s") {
    return slh_dsa_sha2_128s.sign(message, secretKey);
  }
  return getMldsaScheme(algorithm).sign(secretKey, message);
}

export function pqcVerifyBytes(
  algorithm: PqAlgorithm,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (algorithm === "slh-dsa-sha2-128f") {
      return slh_dsa_sha2_128f.verify(signature, message, publicKey);
    }
    if (algorithm === "slh-dsa-sha2-128s") {
      return slh_dsa_sha2_128s.verify(signature, message, publicKey);
    }
    return getMldsaScheme(algorithm).verify(publicKey, message, signature);
  } catch {
    return false;
  }
}

function deriveEvmAddressFromSecpPubkey(uncompressedOrCompressed: Uint8Array): string {
  const pt = secp256k1.ProjectivePoint
    ? secp256k1.ProjectivePoint.fromHex(uncompressedOrCompressed).toRawBytes(false)
    : secp256k1.Point.fromBytes(uncompressedOrCompressed).toBytes(false);
  const hash = keccak_256(pt.slice(1));
  return getAddress(`0x${bytesToHex(hash.slice(-20))}`);
}

function deriveEvmAddressFromEdPubkey(edPubkey: Uint8Array): string {
  const hash = keccak_256(edPubkey);
  return getAddress(`0x${bytesToHex(hash.slice(-20))}`);
}

function classicalKeygen(algorithm: ClassicalAlgorithm): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  evmAddress: string;
} {
  if (algorithm === "ed25519") {
    const sk = ed25519.utils.randomPrivateKey
      ? ed25519.utils.randomPrivateKey()
      : ed25519.utils.randomSecretKey();
    const pk = ed25519.getPublicKey(sk);
    return { publicKey: pk, secretKey: sk, evmAddress: deriveEvmAddressFromEdPubkey(pk) };
  }
  const sk = secp256k1.utils.randomPrivateKey
    ? secp256k1.utils.randomPrivateKey()
    : secp256k1.utils.randomSecretKey();
  const pk = secp256k1.getPublicKey(sk, true);
  return { publicKey: pk, secretKey: sk, evmAddress: deriveEvmAddressFromSecpPubkey(pk) };
}

function classicalSign(algorithm: ClassicalAlgorithm, secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (algorithm === "ed25519") {
    return ed25519.sign(message, secretKey);
  }
  const msgHash = shake256(message, 32);
  const sig = secp256k1.sign(msgHash, secretKey) as Uint8Array | { toCompactRawBytes: () => Uint8Array };
  return sig instanceof Uint8Array ? sig : sig.toCompactRawBytes();
}

function classicalVerify(
  algorithm: ClassicalAlgorithm,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (algorithm === "ed25519") {
      return ed25519.verify(signature, message, publicKey);
    }
    const msgHash = shake256(message, 32);
    return secp256k1.verify(signature, msgHash, publicKey);
  } catch {
    return false;
  }
}

/**
 * Generates a dual-layer post-quantum + classical AI agent identity.
 */
export function generateHybridAgentIdentity(
  agentId: string,
  options: {
    pqAlgorithm?: PqAlgorithm;
    classicalAlgorithm?: ClassicalAlgorithm;
    pqSeed?: Uint8Array;
  } = {},
): HybridAgentIdentity {
  const pqAlgorithm = options.pqAlgorithm ?? "ml-dsa-87";
  const classicalAlgorithm = options.classicalAlgorithm ?? "secp256k1";
  const cl = classicalKeygen(classicalAlgorithm);
  const pq = pqcKeygen(pqAlgorithm, options.pqSeed);
  return {
    agentId,
    classicalAlgorithm,
    classicalPublicKeyHex: bytesToHex(cl.publicKey),
    classicalSecretKeyHex: bytesToHex(cl.secretKey),
    evmAddress: cl.evmAddress,
    pqAlgorithm,
    pqPublicKeyHex: bytesToHex(pq.publicKey),
    pqSecretKeyHex: bytesToHex(pq.secretKey),
    pqPubkeyHashHex: pq.pubkeyHashHex,
  };
}

export function toPublicIdentity(id: HybridAgentIdentity): PublicAgentIdentity {
  return {
    agentId: id.agentId,
    classicalAlgorithm: id.classicalAlgorithm,
    classicalPublicKeyHex: id.classicalPublicKeyHex,
    evmAddress: id.evmAddress,
    pqAlgorithm: id.pqAlgorithm,
    pqPublicKeyHex: id.pqPublicKeyHex,
    pqPubkeyHashHex: id.pqPubkeyHashHex,
  };
}

/**
 * Deterministic SHAKE-256 policy fingerprint binding every policy rule.
 */
export function computePolicyHash(policy: AgentPolicy): string {
  const canonical = JSON.stringify({
    policyId: policy.policyId,
    agentId: policy.agentId,
    network: policy.network,
    chainId: policy.chainId,
    evmChainId: policy.evmChainId,
    requireHybridPqc: policy.requireHybridPqc,
    minPqAlgorithm: policy.minPqAlgorithm,
    requiredSignBytesVersion: policy.requiredSignBytesVersion,
    registeredPqPubkeyHashHex: policy.registeredPqPubkeyHashHex?.toLowerCase() ?? "",
    maxSingleTxUqor: policy.maxSingleTxUqor,
    velocityWindows: policy.velocityWindows.map((w) => ({
      label: w.label,
      windowSec: w.windowSec,
      maxSpendUqor: w.maxSpendUqor,
      maxTxCount: w.maxTxCount,
    })),
    allowlistedTargets: [...policy.allowlistedTargets].map((a) => a.toLowerCase()).sort(),
    denylistedTargets: [...policy.denylistedTargets].map((a) => a.toLowerCase()).sort(),
    allowedSelectors: [...(policy.allowedSelectors ?? [])].map((s) => s.toLowerCase()).sort(),
    forbiddenSelectors: [...(policy.forbiddenSelectors ?? [])].map((s) => s.toLowerCase()).sort(),
    maxAiRiskLevel: policy.maxAiRiskLevel ?? null,
    requireStrictSequentialNonce: policy.requireStrictSequentialNonce,
  });
  return shake256Hex(frameFields([QOREGUARD_DOMAINS.policyCommit, "policy-spec", canonical]), 32);
}

/**
 * Canonical length-prefixed SHAKE-256 commitment over a TransactionIntent.
 */
export function computeIntentCommitment(intent: TransactionIntent): {
  commitmentBytes: Uint8Array;
  commitmentHex: string;
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
} {
  const calldataClean = (intent.calldataHex || "0x").toLowerCase();
  const calldataHash = shake256Hex(fromHex(calldataClean), 32);
  const bodyBytes = frameFields([
    QOREGUARD_DOMAINS.policyCommit,
    intent.chainId,
    String(intent.evmChainId),
    intent.policyHashHex.toLowerCase(),
    intent.agentId,
    intent.from.toLowerCase(),
    intent.to.toLowerCase(),
    intent.valueUqor,
    calldataHash,
    intent.memo ?? "",
  ]);
  const authInfoBytes = frameFields([
    "auth-v1",
    String(intent.nonce),
    String(intent.expiresAtUnix),
  ]);
  const commitmentBytes = shake256(frameFields([bodyBytes, authInfoBytes]), 32);
  return {
    commitmentBytes,
    commitmentHex: bytesToHex(commitmentBytes),
    bodyBytes,
    authInfoBytes,
  };
}

/**
 * Signs a TransactionIntent with both classical and post-quantum keys using
 * QoreChain's official hybridSignBytes framing (`qorechain-pqc-hybrid-v2`).
 */
export function signHybridIntent(
  identity: HybridAgentIdentity,
  intent: TransactionIntent,
  options: {
    signBytesVersion?: SignBytesVersion;
    signatureTier?: SignatureTier;
  } = {},
): HybridSignedEnvelope {
  const signBytesVersion = options.signBytesVersion ?? "v2";
  const signatureTier = options.signatureTier ?? "hybrid-pqc";
  const { commitmentHex, bodyBytes, authInfoBytes } = computeIntentCommitment(intent);
  const framedSignBytes = hybridSignBytes(signBytesVersion, intent.chainId, bodyBytes, authInfoBytes);

  const classicalSig = classicalSign(
    identity.classicalAlgorithm,
    fromHex(identity.classicalSecretKeyHex),
    framedSignBytes,
  );

  if (signatureTier !== "hybrid-pqc") {
    return {
      signatureTier,
      signBytesVersion,
      intent,
      commitmentHex,
      hybridSignBytesHex: bytesToHex(framedSignBytes),
      classical: {
        algorithm: identity.classicalAlgorithm,
        publicKeyHex: identity.classicalPublicKeyHex,
        signatureHex: bytesToHex(classicalSig),
      },
    };
  }

  const pqSig = pqcSignBytes(identity.pqAlgorithm, fromHex(identity.pqSecretKeyHex), framedSignBytes);
  return {
    signatureTier: "hybrid-pqc",
    signBytesVersion,
    intent,
    commitmentHex,
    hybridSignBytesHex: bytesToHex(framedSignBytes),
    classical: {
      algorithm: identity.classicalAlgorithm,
      publicKeyHex: identity.classicalPublicKeyHex,
      signatureHex: bytesToHex(classicalSig),
    },
    pqc: {
      algorithm: identity.pqAlgorithm,
      publicKeyHex: identity.pqPublicKeyHex,
      pubkeyHashHex: identity.pqPubkeyHashHex,
      signatureHex: bytesToHex(pqSig),
    },
  };
}

/**
 * Verifies a HybridSignedEnvelope against an AgentPolicy's cryptographic and
 * anti-quantum-downgrade requirements. Never throws on malformed hex/signatures.
 */
export function verifyHybridEnvelope(
  envelope: HybridSignedEnvelope,
  policy: AgentPolicy,
): CryptoVerificationResult {
  const codes: GuardRejectionCode[] = [];
  const { commitmentHex: computedCommitmentHex, bodyBytes, authInfoBytes } = computeIntentCommitment(envelope.intent);
  const commitmentMatches =
    computedCommitmentHex.toLowerCase() === (envelope.commitmentHex ?? "").toLowerCase();
  if (!commitmentMatches) {
    codes.push("COMMITMENT_TAMPERED");
  }

  // Reconstruct the exact expected QoreChain hybrid sign-bytes from the intent
  const expectedFramed = hybridSignBytes(
    envelope.signBytesVersion,
    envelope.intent.chainId,
    bodyBytes,
    authInfoBytes,
  );
  const expectedFramedHex = bytesToHex(expectedFramed);
  if (expectedFramedHex !== (envelope.hybridSignBytesHex ?? "").toLowerCase()) {
    if (!codes.includes("COMMITMENT_TAMPERED")) {
      codes.push("COMMITMENT_TAMPERED");
    }
  }

  let downgradeDetected = false;

  // Anti-quantum-downgrade check 1: sign-bytes version (v1 on v2 chain)
  if (policy.requiredSignBytesVersion === "v2" && envelope.signBytesVersion !== "v2") {
    downgradeDetected = true;
    codes.push("QUANTUM_DOWNGRADE_SIGN_BYTES_V1");
  }

  // Anti-quantum-downgrade check 2: classical-only / shake-only tier
  if (policy.requireHybridPqc && envelope.signatureTier !== "hybrid-pqc") {
    downgradeDetected = true;
    codes.push("QUANTUM_DOWNGRADE_CLASSICAL_ONLY");
  }

  // Classical signature verification over canonical expectedFramed bytes
  let classicalValid = false;
  try {
    classicalValid = classicalVerify(
      envelope.classical.algorithm,
      fromHex(envelope.classical.publicKeyHex),
      expectedFramed,
      fromHex(envelope.classical.signatureHex),
    );
  } catch {
    classicalValid = false;
  }
  if (!classicalValid) {
    codes.push("CLASSICAL_SIGNATURE_INVALID");
  }

  // Post-quantum signature verification + pubkeyHash binding + security-level floor
  let pqcValid = false;
  let pubkeyHashMatches = true;
  if (!envelope.pqc) {
    if (policy.requireHybridPqc) {
      downgradeDetected = true;
      codes.push("PQC_SIGNATURE_MISSING");
    }
  } else {
    const minLevel = PQ_SECURITY_LEVEL[policy.minPqAlgorithm];
    const offeredLevel = PQ_SECURITY_LEVEL[envelope.pqc.algorithm] ?? 0;
    if (offeredLevel < minLevel) {
      downgradeDetected = true;
      codes.push("QUANTUM_DOWNGRADE_WEAK_ALGORITHM");
    }

    try {
      const pkBytes = fromHex(envelope.pqc.publicKeyHex);
      const actualHash = bytesToHex(pubkeyHash(pkBytes, 32));
      const claimedMatches = actualHash === envelope.pqc.pubkeyHashHex.toLowerCase();
      const policyMatches = policy.registeredPqPubkeyHashHex
        ? actualHash === policy.registeredPqPubkeyHashHex.toLowerCase()
        : true;
      pubkeyHashMatches = claimedMatches && policyMatches;
      if (!pubkeyHashMatches) {
        codes.push("PUBKEY_HASH_MISMATCH");
      }

      const sigBytes = fromHex(envelope.pqc.signatureHex);
      pqcValid = pqcVerifyBytes(envelope.pqc.algorithm, pkBytes, expectedFramed, sigBytes);
      if (!pqcValid) {
        codes.push("PQC_SIGNATURE_INVALID");
      }
    } catch {
      pubkeyHashMatches = false;
      pqcValid = false;
      codes.push("PQC_SIGNATURE_INVALID");
    }
  }

  const valid =
    codes.length === 0 &&
    commitmentMatches &&
    classicalValid &&
    (!policy.requireHybridPqc || (pqcValid && pubkeyHashMatches && !downgradeDetected));

  return {
    valid,
    classicalValid,
    pqcValid,
    commitmentMatches,
    pubkeyHashMatches,
    downgradeDetected,
    codes,
    computedCommitmentHex,
  };
}

// ---------------------------------------------------------------------------
// Official QoreChain Authenticated Messaging (`qorechain-msg-v1|<chainId>|<data>`)
// ---------------------------------------------------------------------------

/**
 * Formats the canonical QoreChain authenticated message payload:
 *   `qorechain-msg-v1|<chainId>|<data>`
 * Rejects empty `chainId` or `|` delimiter characters inside `chainId` to
 * prevent cross-field boundary collisions (byte-identical to QoreGuardPolicyRegistry.sol).
 */
export function formatQorechainAuthMessage(
  chainId: string,
  data: string | Uint8Array,
): Uint8Array {
  if (!chainId || chainId.includes("|")) {
    throw new Error("Invalid chainId for qorechain-msg-v1: must be non-empty and contain no '|' delimiter");
  }
  const prefixBytes = TEXT_ENCODER.encode(`${QORECHAIN_AUTH_MSG_PREFIX}${chainId}|`);
  const dataBytes = typeof data === "string" ? TEXT_ENCODER.encode(data) : data;
  const out = new Uint8Array(prefixBytes.length + dataBytes.length);
  out.set(prefixBytes, 0);
  out.set(dataBytes, prefixBytes.length);
  return out;
}

/**
 * Signs an authenticated message in exact official QoreChain format
 * (`qorechain-msg-v1|<chainId>|<data>`) using hybrid `secp256k1` (65-byte
 * EVM-recoverable `r || s || v` over `keccak256(message)`) + FIPS-204 `ML-DSA-87`
 * (`4,627`-byte signature over raw `message`).
 */
export function signAuthenticatedMessage(
  identity: HybridAgentIdentity,
  params: {
    readonly chainId: string;
    readonly data: string | Uint8Array;
  },
): AuthenticatedMessageEnvelope {
  if (identity.classicalAlgorithm !== "secp256k1") {
    throw new Error("qorechain-msg-v1 requires a secp256k1 classical keypair");
  }
  if (identity.pqAlgorithm !== "ml-dsa-87") {
    throw new Error("qorechain-msg-v1 requires an ml-dsa-87 post-quantum keypair");
  }

  const dataBytes = typeof params.data === "string" ? TEXT_ENCODER.encode(params.data) : params.data;
  const formatted = formatQorechainAuthMessage(params.chainId, dataBytes);
  const msgDigest = keccak_256(formatted);

  const rawSecpSig = secp256k1.sign(msgDigest, fromHex(identity.classicalSecretKeyHex)) as {
    toCompactRawBytes: () => Uint8Array;
    recovery?: number;
  };
  const compact64 = rawSecpSig.toCompactRawBytes();
  const vByte = 27 + (rawSecpSig.recovery ?? 0);
  const sig65 = new Uint8Array(65);
  sig65.set(compact64, 0);
  sig65[64] = vByte;

  const pqSig = mldsa87.sign(fromHex(identity.pqSecretKeyHex), formatted);

  let formattedUtf8: string | undefined;
  try {
    formattedUtf8 = TEXT_DECODER.decode(formatted);
  } catch {
    formattedUtf8 = undefined;
  }

  return {
    format: "qorechain-msg-v1",
    chainId: params.chainId,
    dataHex: bytesToHex(dataBytes),
    ...(formattedUtf8 !== undefined ? { formattedMessageUtf8: formattedUtf8 } : {}),
    formattedMessageHex: bytesToHex(formatted),
    messageKeccak256Hex: toHexPrefixed(msgDigest),
    secp256k1: {
      evmAddress: identity.evmAddress,
      publicKeyHex: identity.classicalPublicKeyHex,
      signatureHex: bytesToHex(sig65),
    },
    mldsa87: {
      publicKeyHex: identity.pqPublicKeyHex,
      pubkeyHashHex: identity.pqPubkeyHashHex,
      signatureHex: bytesToHex(pqSig),
    },
  };
}

/**
 * Verifies a hybrid `secp256k1` + `ML-DSA-87` authenticated message in
 * `qorechain-msg-v1|<chainId>|<data>` format. Never throws on malformed input.
 */
export function verifyAuthenticatedMessage(
  envelope: AuthenticatedMessageEnvelope,
  expected: {
    readonly chainId?: string;
    readonly expectedEvmSigner?: string;
    readonly expectedPqPubkeyHashHex?: string;
  } = {},
): AuthenticatedMessageVerification {
  const codes: GuardRejectionCode[] = [];

  if (!envelope || envelope.format !== "qorechain-msg-v1") {
    codes.push("AUTH_MSG_FORMAT_INVALID");
    return {
      valid: false,
      formatValid: false,
      secp256k1Valid: false,
      mldsa87Valid: false,
      pubkeyHashMatches: false,
      recoveredEvmAddress: null,
      messageKeccak256Hex: null,
      codes,
    };
  }

  if (expected.chainId !== undefined && envelope.chainId !== expected.chainId) {
    codes.push("CHAIN_ID_MISMATCH");
  }

  let formatted: Uint8Array;
  let formatValid = false;
  try {
    const dataBytes = fromHex(envelope.dataHex);
    formatted = formatQorechainAuthMessage(envelope.chainId, dataBytes);
    const expectedHex = bytesToHex(formatted);
    formatValid = expectedHex === (envelope.formattedMessageHex ?? "").toLowerCase();
    if (!formatValid) {
      codes.push("COMMITMENT_TAMPERED");
    }
  } catch {
    codes.push("AUTH_MSG_FORMAT_INVALID");
    return {
      valid: false,
      formatValid: false,
      secp256k1Valid: false,
      mldsa87Valid: false,
      pubkeyHashMatches: false,
      recoveredEvmAddress: null,
      messageKeccak256Hex: null,
      codes,
    };
  }

  const digest = keccak_256(formatted);
  const computedKeccakHex = toHexPrefixed(digest);
  if (computedKeccakHex.toLowerCase() !== (envelope.messageKeccak256Hex ?? "").toLowerCase()) {
    if (!codes.includes("COMMITMENT_TAMPERED")) {
      codes.push("COMMITMENT_TAMPERED");
    }
  }

  // 1. Recover and verify 65-byte secp256k1 signature over keccak256(formatted)
  let secp256k1Valid = false;
  let recoveredEvmAddress: string | null = null;
  try {
    const sigBytes = fromHex(envelope.secp256k1?.signatureHex ?? "");
    if (sigBytes.length === 65) {
      const rawV = sigBytes[64]!;
      const normalizedV = rawV < 27 ? rawV + 27 : rawV;
      if (normalizedV === 27 || normalizedV === 28) {
        const parsed = secp256k1.Signature.fromCompact(sigBytes.slice(0, 64));
        if (!parsed.hasHighS()) {
          const recPt = parsed.addRecoveryBit(normalizedV - 27).recoverPublicKey(digest);
          const rawUncompressed = recPt.toRawBytes
            ? recPt.toRawBytes(false)
            : (recPt as unknown as { toBytes: (c: boolean) => Uint8Array }).toBytes(false);
          recoveredEvmAddress = deriveEvmAddressFromSecpPubkey(rawUncompressed);
          const claimedAddr = getAddress(envelope.secp256k1.evmAddress);
          const pubkeyDerivedAddr = deriveEvmAddressFromSecpPubkey(fromHex(envelope.secp256k1.publicKeyHex));
          const expectedSignerMatches = expected.expectedEvmSigner
            ? recoveredEvmAddress.toLowerCase() === expected.expectedEvmSigner.toLowerCase()
            : true;
          secp256k1Valid =
            recoveredEvmAddress === claimedAddr &&
            recoveredEvmAddress === pubkeyDerivedAddr &&
            expectedSignerMatches;
        }
      }
    }
  } catch {
    secp256k1Valid = false;
  }
  if (!secp256k1Valid) {
    codes.push("CLASSICAL_SIGNATURE_INVALID");
  }

  // 2. Verify FIPS-204 ML-DSA-87 signature (2,592B pubkey + 4,627B signature) over raw formatted bytes
  let mldsa87Valid = false;
  let pubkeyHashMatches = false;
  if (!envelope.mldsa87 || !envelope.mldsa87.signatureHex) {
    codes.push("QUANTUM_DOWNGRADE_CLASSICAL_ONLY");
    codes.push("PQC_SIGNATURE_MISSING");
  } else {
    try {
      const pqPk = fromHex(envelope.mldsa87.publicKeyHex);
      const pqSig = fromHex(envelope.mldsa87.signatureHex);
      if (pqPk.length !== 2592 || pqSig.length !== 4627) {
        codes.push("QUANTUM_DOWNGRADE_WEAK_ALGORITHM");
      } else {
        const actualHash = bytesToHex(pubkeyHash(pqPk, 32));
        const claimedHashMatches = actualHash === envelope.mldsa87.pubkeyHashHex.toLowerCase();
        const expectedHashMatches = expected.expectedPqPubkeyHashHex
          ? actualHash === expected.expectedPqPubkeyHashHex.toLowerCase()
          : true;
        pubkeyHashMatches = claimedHashMatches && expectedHashMatches;
        if (!pubkeyHashMatches) {
          codes.push("PUBKEY_HASH_MISMATCH");
        }
        mldsa87Valid = mldsa87.verify(pqPk, formatted, pqSig);
        if (!mldsa87Valid) {
          codes.push("PQC_SIGNATURE_INVALID");
        }
      }
    } catch {
      mldsa87Valid = false;
      codes.push("PQC_SIGNATURE_INVALID");
    }
  }

  const valid =
    codes.length === 0 &&
    formatValid &&
    secp256k1Valid &&
    mldsa87Valid &&
    pubkeyHashMatches;

  return {
    valid,
    formatValid,
    secp256k1Valid,
    mldsa87Valid,
    pubkeyHashMatches,
    recoveredEvmAddress,
    messageKeccak256Hex: computedKeccakHex,
    codes,
  };
}
