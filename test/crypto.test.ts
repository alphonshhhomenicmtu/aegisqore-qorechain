// SPDX-License-Identifier: Apache-2.0

import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  computeIntentCommitment,
  computePolicyHash,
  formatQorechainAuthMessage,
  fromHex,
  generateHybridAgentIdentity,
  pqcKeygen,
  pqcSignBytes,
  pqcVerifyBytes,
  signAuthenticatedMessage,
  signHybridIntent,
  toPublicIdentity,
  verifyAuthenticatedMessage,
  verifyHybridEnvelope,
} from "../src/crypto.js";
import { createDefaultPolicy } from "../src/mcp/server.js";
import type { TransactionIntent } from "../src/types.js";

function makeIntent(policyHashHex: string, from: string): TransactionIntent {
  return {
    agentId: "agent-treasury-01",
    policyHashHex,
    chainId: "qorechain-diana",
    evmChainId: 9800,
    from,
    to: "0x000000000000000000000000000000000000dEaD",
    valueUqor: "250000",
    calldataHex: "0x",
    nonce: 1,
    expiresAtUnix: Math.floor(Date.now() / 1000) + 600,
    memo: "unit-test-intent",
  };
}

describe("QoreGuard Hybrid Post-Quantum Cryptography", () => {
  it("generates FIPS-204 ML-DSA-87 + secp256k1 identity with canonical key sizes and verifies hybrid envelope", () => {
    const id = generateHybridAgentIdentity("agent-treasury-01", {
      pqAlgorithm: "ml-dsa-87",
      classicalAlgorithm: "secp256k1",
    });
    expect(fromHex(id.pqPublicKeyHex).length).toBe(2592);
    expect(id.pqPubkeyHashHex.length).toBe(64);
    expect(id.evmAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);

    const policy = createDefaultPolicy("testnet", id.pqPubkeyHashHex);
    const policyHashHex = computePolicyHash(policy);
    const envelope = signHybridIntent(id, makeIntent(policyHashHex, id.evmAddress));

    expect(envelope.pqc).toBeDefined();
    expect(fromHex(envelope.pqc!.signatureHex).length).toBe(4627);
    expect(envelope.signBytesVersion).toBe("v2");

    const res = verifyHybridEnvelope(envelope, policy);
    expect(res.valid).toBe(true);
    expect(res.classicalValid).toBe(true);
    expect(res.pqcValid).toBe(true);
    expect(res.commitmentMatches).toBe(true);
    expect(res.pubkeyHashMatches).toBe(true);
    expect(res.downgradeDetected).toBe(false);
    expect(res.codes).toEqual([]);
  });

  it("supports ML-DSA-65 + ed25519 hybrid signing when policy allows L3", () => {
    const id = generateHybridAgentIdentity("agent-treasury-01", {
      pqAlgorithm: "ml-dsa-65",
      classicalAlgorithm: "ed25519",
    });
    const policy = {
      ...createDefaultPolicy("testnet", id.pqPubkeyHashHex),
      minPqAlgorithm: "ml-dsa-65" as const,
    };
    const envelope = signHybridIntent(id, makeIntent(computePolicyHash(policy), id.evmAddress));
    const res = verifyHybridEnvelope(envelope, policy);
    expect(res.valid).toBe(true);
    expect(res.classicalValid).toBe(true);
    expect(res.pqcValid).toBe(true);
  });

  it("supports FIPS-205 SLH-DSA-SHA2-128f stateless hash-based post-quantum signatures", () => {
    const id = generateHybridAgentIdentity("agent-treasury-01", {
      pqAlgorithm: "slh-dsa-sha2-128f",
      classicalAlgorithm: "secp256k1",
    });
    const policy = {
      ...createDefaultPolicy("testnet", id.pqPubkeyHashHex),
      minPqAlgorithm: "slh-dsa-sha2-128f" as const,
    };
    const envelope = signHybridIntent(id, makeIntent(computePolicyHash(policy), id.evmAddress));
    expect(fromHex(envelope.pqc!.signatureHex).length).toBe(17088);
    const res = verifyHybridEnvelope(envelope, policy);
    expect(res.valid).toBe(true);
    expect(res.pqcValid).toBe(true);
  });

  it("rejects classical-only quantum downgrade and missing PQC extension", () => {
    const id = generateHybridAgentIdentity("agent-treasury-01");
    const policy = createDefaultPolicy("testnet", id.pqPubkeyHashHex);
    const downgraded = signHybridIntent(id, makeIntent(computePolicyHash(policy), id.evmAddress), {
      signatureTier: "classical-only",
    });
    const res = verifyHybridEnvelope(downgraded, policy);
    expect(res.valid).toBe(false);
    expect(res.downgradeDetected).toBe(true);
    expect(res.codes).toContain("QUANTUM_DOWNGRADE_CLASSICAL_ONLY");
    expect(res.codes).toContain("PQC_SIGNATURE_MISSING");
  });

  it("rejects legacy v1 sign-bytes downgrade on a v2 QoreChain network", () => {
    const id = generateHybridAgentIdentity("agent-treasury-01");
    const policy = createDefaultPolicy("testnet", id.pqPubkeyHashHex);
    const v1Env = signHybridIntent(id, makeIntent(computePolicyHash(policy), id.evmAddress), {
      signBytesVersion: "v1",
    });
    const res = verifyHybridEnvelope(v1Env, policy);
    expect(res.valid).toBe(false);
    expect(res.downgradeDetected).toBe(true);
    expect(res.codes).toContain("QUANTUM_DOWNGRADE_SIGN_BYTES_V1");
  });

  it("rejects ML-DSA-44 algorithm downgrade when policy mandates ML-DSA-87", () => {
    const weakId = generateHybridAgentIdentity("agent-treasury-01", { pqAlgorithm: "ml-dsa-44" });
    const policy = createDefaultPolicy("testnet", weakId.pqPubkeyHashHex);
    const env = signHybridIntent(weakId, makeIntent(computePolicyHash(policy), weakId.evmAddress));
    const res = verifyHybridEnvelope(env, policy);
    expect(res.valid).toBe(false);
    expect(res.downgradeDetected).toBe(true);
    expect(res.codes).toContain("QUANTUM_DOWNGRADE_WEAK_ALGORITHM");
  });

  it("rejects single-bit tamper in ML-DSA-87 signature, classical signature, or commitment", () => {
    const id = generateHybridAgentIdentity("agent-treasury-01");
    const policy = createDefaultPolicy("testnet", id.pqPubkeyHashHex);
    const env = signHybridIntent(id, makeIntent(computePolicyHash(policy), id.evmAddress));

    // Flip 1 bit in PQC signature
    const pqSig = fromHex(env.pqc!.signatureHex);
    pqSig[0] = (pqSig[0] ?? 0) ^ 0x80;
    const resPq = verifyHybridEnvelope(
      { ...env, pqc: { ...env.pqc!, signatureHex: bytesToHex(pqSig) } },
      policy,
    );
    expect(resPq.valid).toBe(false);
    expect(resPq.pqcValid).toBe(false);
    expect(resPq.codes).toContain("PQC_SIGNATURE_INVALID");

    // Flip 1 bit in classical signature
    const clSig = fromHex(env.classical.signatureHex);
    clSig[0] = (clSig[0] ?? 0) ^ 0x01;
    const resCl = verifyHybridEnvelope(
      { ...env, classical: { ...env.classical, signatureHex: bytesToHex(clSig) } },
      policy,
    );
    expect(resCl.valid).toBe(false);
    expect(resCl.classicalValid).toBe(false);
    expect(resCl.codes).toContain("CLASSICAL_SIGNATURE_INVALID");

    // Mutate intent value without re-signing
    const resTamper = verifyHybridEnvelope(
      { ...env, intent: { ...env.intent, valueUqor: "999999" } },
      policy,
    );
    expect(resTamper.valid).toBe(false);
    expect(resTamper.commitmentMatches).toBe(false);
    expect(resTamper.codes).toContain("COMMITMENT_TAMPERED");
  });

  it("rejects pubkeyHash mismatch when an unregistered ML-DSA-87 key signs the intent", () => {
    const registered = generateHybridAgentIdentity("agent-treasury-01");
    const rogue = generateHybridAgentIdentity("agent-treasury-01");
    const policy = createDefaultPolicy("testnet", registered.pqPubkeyHashHex);
    const env = signHybridIntent(rogue, makeIntent(computePolicyHash(policy), rogue.evmAddress));
    const res = verifyHybridEnvelope(env, policy);
    expect(res.valid).toBe(false);
    expect(res.pubkeyHashMatches).toBe(false);
    expect(res.codes).toContain("PUBKEY_HASH_MISMATCH");

    // Also verify public identity projection strips secret keys
    const pub = toPublicIdentity(registered);
    expect("pqSecretKeyHex" in pub).toBe(false);
    expect("classicalSecretKeyHex" in pub).toBe(false);

    // Direct low-level pqcKeygen + pqcSignBytes + pqcVerifyBytes deterministic check
    const rawKp = pqcKeygen("ml-dsa-87");
    const msg = computeIntentCommitment(makeIntent(computePolicyHash(policy), registered.evmAddress)).commitmentBytes;
    const sig = pqcSignBytes("ml-dsa-87", rawKp.secretKey, msg);
    expect(pqcVerifyBytes("ml-dsa-87", rawKp.publicKey, msg, sig)).toBe(true);
  });

  it("signs and verifies official qorechain-msg-v1|<chainId>|<data> hybrid secp256k1 + ML-DSA-87 messages", () => {
    const id = generateHybridAgentIdentity("agent-treasury-01", {
      pqAlgorithm: "ml-dsa-87",
      classicalAlgorithm: "secp256k1",
    });

    const formatted = formatQorechainAuthMessage("qorechain-diana", "execute:vault-rebalance:250000uqor");
    expect(new TextDecoder().decode(formatted)).toBe(
      "qorechain-msg-v1|qorechain-diana|execute:vault-rebalance:250000uqor",
    );
    expect(() => formatQorechainAuthMessage("qorechain-diana|inject", "x")).toThrow();

    const signed = signAuthenticatedMessage(id, {
      chainId: "qorechain-diana",
      data: "execute:vault-rebalance:250000uqor",
    });
    expect(signed.format).toBe("qorechain-msg-v1");
    expect(signed.formattedMessageUtf8).toBe(
      "qorechain-msg-v1|qorechain-diana|execute:vault-rebalance:250000uqor",
    );
    expect(fromHex(signed.secp256k1.signatureHex).length).toBe(65);
    expect(fromHex(signed.mldsa87.publicKeyHex).length).toBe(2592);
    expect(fromHex(signed.mldsa87.signatureHex).length).toBe(4627);

    const verified = verifyAuthenticatedMessage(signed, {
      chainId: "qorechain-diana",
      expectedEvmSigner: id.evmAddress,
      expectedPqPubkeyHashHex: id.pqPubkeyHashHex,
    });
    expect(verified.valid).toBe(true);
    expect(verified.formatValid).toBe(true);
    expect(verified.secp256k1Valid).toBe(true);
    expect(verified.mldsa87Valid).toBe(true);
    expect(verified.pubkeyHashMatches).toBe(true);
    expect(verified.recoveredEvmAddress).toBe(id.evmAddress);

    // Rejects tampered payload, classical-only downgrade, wrong chainId, or flipped secp256k1 signature
    const tamperedData = verifyAuthenticatedMessage({
      ...signed,
      dataHex: bytesToHex(new TextEncoder().encode("execute:vault-rebalance:999999uqor")),
    });
    expect(tamperedData.valid).toBe(false);
    expect(tamperedData.codes).toContain("COMMITMENT_TAMPERED");

    const strippedPqc = verifyAuthenticatedMessage({
      ...signed,
      mldsa87: { ...signed.mldsa87, signatureHex: "" },
    });
    expect(strippedPqc.valid).toBe(false);
    expect(strippedPqc.codes).toContain("QUANTUM_DOWNGRADE_CLASSICAL_ONLY");

    const wrongChain = verifyAuthenticatedMessage(signed, { chainId: "qorechain-vladi" });
    expect(wrongChain.valid).toBe(false);
    expect(wrongChain.codes).toContain("CHAIN_ID_MISMATCH");

    const badSecpBytes = fromHex(signed.secp256k1.signatureHex);
    badSecpBytes[0] = (badSecpBytes[0] ?? 0) ^ 0x01;
    const badSecp = verifyAuthenticatedMessage({
      ...signed,
      secp256k1: { ...signed.secp256k1, signatureHex: bytesToHex(badSecpBytes) },
    });
    expect(badSecp.valid).toBe(false);
    expect(badSecp.secp256k1Valid).toBe(false);
    expect(badSecp.codes).toContain("CLASSICAL_SIGNATURE_INVALID");
  });
});
