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
