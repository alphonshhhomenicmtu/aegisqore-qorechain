// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateHybridAgentIdentity, signHybridIntent } from "../src/crypto.js";
import { createDefaultPolicy } from "../src/mcp/server.js";
import { MAX_AGENT_LINK_TTL_SEC } from "../src/networks.js";
import {
  createSignedAgentEnvelope,
  QoreGuardPolicyEngine,
  StaleEvaluationClockError,
  verifyAuditBundle,
} from "../src/policy-engine.js";
import type { QuantumAttackVector } from "../src/types.js";

const TARGET_ALLOWED = "0x000000000000000000000000000000000000dEaD";
const TARGET_SECOND = "0x1111111111111111111111111111111111111111";
const TARGET_DENIED = "0x0000000000000000000000000000000000000000";
const TARGET_UNKNOWN = "0x2222222222222222222222222222222222222222";

function setupEngine(overrides: Partial<ReturnType<typeof createDefaultPolicy>> = {}) {
  const id = generateHybridAgentIdentity("agent-treasury-01", { pqAlgorithm: "ml-dsa-87" });
  const policy = {
    ...createDefaultPolicy("testnet", id.pqPubkeyHashHex),
    ...overrides,
  };
  const engine = new QoreGuardPolicyEngine(policy);
  return { id, policy, engine };
}

describe("QoreGuardPolicyEngine — Scoped Policy, Velocity, Replay & Adversarial Breakers", () => {
  it("quotes side-effect-free ALLOW and commits nonce/spend atomically on verifyAndCommit", () => {
    const { id, engine } = setupEngine();
    const now = 1_760_000_000;
    const env = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "1000000",
      expiresAtUnix: now + 300,
    });

    const quote = engine.quoteDecision(env, { allowTestClock: true, nowUnix: now });
    expect(quote.verdict).toBe("ALLOW");
    expect(quote.committed).toBe(false);
    expect(engine.getLastNonce()).toBe(0);
    expect(engine.getAuditLog().length).toBe(0);

    const committed = engine.verifyAndCommit(env, { allowTestClock: true, nowUnix: now });
    expect(committed.verdict).toBe("ALLOW");
    expect(committed.committed).toBe(true);
    expect(engine.getLastNonce()).toBe(1);
    expect(engine.getAuditLog().length).toBe(1);
  });

  it("blocks single-transaction spending cap breach without consuming nonce", () => {
    const { id, engine } = setupEngine({ maxSingleTxUqor: "500000" });
    const now = 1_760_000_000;
    const overCap = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "500001",
      expiresAtUnix: now + 300,
    });

    const res = engine.verifyAndCommit(overCap, { allowTestClock: true, nowUnix: now });
    expect(res.verdict).toBe("DENY");
    expect(res.committed).toBe(false);
    expect(res.rejectionCodes).toContain("SPEND_CAP_EXCEEDED");
    expect(engine.getLastNonce()).toBe(0);
    expect(engine.getSpendHistoryCount()).toBe(0);
    // Blocked attempt is still captured in tamper-evident audit chain
    expect(engine.getAuditLog().length).toBe(1);
  });

  it("enforces rolling velocity spend window and recovers after window expires", () => {
    const { id, engine } = setupEngine({
      maxSingleTxUqor: "3000000",
      velocityWindows: [{ label: "5m_burst", windowSec: 300, maxSpendUqor: "5000000", maxTxCount: 10 }],
    });
    const t0 = 1_760_000_000;

    // Tx 1: 3M uqor -> ALLOW (3M/5M)
    const e1 = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "3000000", nonce: 1, expiresAtUnix: t0 + 1000 });
    expect(engine.verifyAndCommit(e1, { allowTestClock: true, nowUnix: t0 }).verdict).toBe("ALLOW");

    // Tx 2 at t0+60s: 2.5M uqor -> DENY (5.5M > 5M)
    const e2 = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "2500000", nonce: 2, expiresAtUnix: t0 + 1000 });
    const d2 = engine.verifyAndCommit(e2, { allowTestClock: true, nowUnix: t0 + 60 });
    expect(d2.verdict).toBe("DENY");
    expect(d2.rejectionCodes).toContain("VELOCITY_SPEND_EXCEEDED");

    // Same Tx 2 at t0+301s (window rolled past t0) -> ALLOW!
    const d2After = engine.verifyAndCommit(e2, { allowTestClock: true, nowUnix: t0 + 301 });
    expect(d2After.verdict).toBe("ALLOW");
    expect(engine.getLastNonce()).toBe(2);
  });

  it("enforces rolling velocity transaction-count cap", () => {
    const { id, engine } = setupEngine({
      velocityWindows: [{ label: "burst_count", windowSec: 60, maxSpendUqor: "999999999", maxTxCount: 2 }],
    });
    const t0 = 1_760_000_000;
    for (let n = 1; n <= 2; n++) {
      const e = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "100", nonce: n, expiresAtUnix: t0 + 300 });
      expect(engine.verifyAndCommit(e, { allowTestClock: true, nowUnix: t0 + n }).verdict).toBe("ALLOW");
    }
    const e3 = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "100", nonce: 3, expiresAtUnix: t0 + 300 });
    const d3 = engine.verifyAndCommit(e3, { allowTestClock: true, nowUnix: t0 + 10 });
    expect(d3.verdict).toBe("DENY");
    expect(d3.rejectionCodes).toContain("VELOCITY_COUNT_EXCEEDED");
  });

  it("enforces target allowlist and explicit denylist", () => {
    const { id, engine } = setupEngine();
    const now = 1_760_000_000;

    const eUnknown = createSignedAgentEnvelope(engine, id, { to: TARGET_UNKNOWN, valueUqor: "1000", expiresAtUnix: now + 300 });
    expect(engine.quoteDecision(eUnknown, { allowTestClock: true, nowUnix: now }).rejectionCodes).toContain("TARGET_NOT_ALLOWLISTED");

    const eDenied = createSignedAgentEnvelope(engine, id, { to: TARGET_DENIED, valueUqor: "1000", expiresAtUnix: now + 300 });
    expect(engine.quoteDecision(eDenied, { allowTestClock: true, nowUnix: now }).rejectionCodes).toContain("TARGET_DENYLISTED");

    const eSecond = createSignedAgentEnvelope(engine, id, { to: TARGET_SECOND, valueUqor: "1000", expiresAtUnix: now + 300 });
    expect(engine.quoteDecision(eSecond, { allowTestClock: true, nowUnix: now }).verdict).toBe("ALLOW");
  });

  it("blocks forbidden EVM calldata selectors (approve / setApprovalForAll) and enforces allowedSelectors", () => {
    const { id, engine } = setupEngine({
      allowedSelectors: ["0xa9059cbb"], // ERC-20 transfer only
      forbiddenSelectors: ["0x095ea7b3", "0xa22cb465"],
    });
    const now = 1_760_000_000;

    const approveCall = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "0",
      calldataHex: "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111",
      expiresAtUnix: now + 300,
    });
    const dApprove = engine.quoteDecision(approveCall, { allowTestClock: true, nowUnix: now });
    expect(dApprove.verdict).toBe("DENY");
    expect(dApprove.rejectionCodes).toContain("SELECTOR_FORBIDDEN");
    expect(dApprove.rejectionCodes).toContain("SELECTOR_NOT_ALLOWED");

    const transferCall = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "0",
      calldataHex: "0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111",
      expiresAtUnix: now + 300,
    });
    expect(engine.quoteDecision(transferCall, { allowTestClock: true, nowUnix: now }).verdict).toBe("ALLOW");
  });

  it("enforces IQoreAI risk level threshold and anomaly flag", () => {
    const { id, engine } = setupEngine({ maxAiRiskLevel: 2 });
    const now = 1_760_000_000;
    const env = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "10000", expiresAtUnix: now + 300 });

    const highRisk = engine.quoteDecision(env, {
      allowTestClock: true, nowUnix: now,
      aiSignal: { riskScore: 88, riskLevel: 3, anomalyFlagged: true, source: "onchain-precompile" },
    });
    expect(highRisk.verdict).toBe("DENY");
    expect(highRisk.rejectionCodes).toContain("AI_RISK_THRESHOLD_EXCEEDED");
    expect(highRisk.rejectionCodes).toContain("AI_ANOMALY_FLAGGED");

    const safe = engine.quoteDecision(env, {
      allowTestClock: true, nowUnix: now,
      aiSignal: { riskScore: 12, riskLevel: 1, anomalyFlagged: false, source: "onchain-precompile" },
    });
    expect(safe.verdict).toBe("ALLOW");
  });

  it("blocks nonce replay and out-of-order skipped nonces under strict sequential mode", () => {
    const { id, engine } = setupEngine({ requireStrictSequentialNonce: true });
    const now = 1_760_000_000;

    // Nonce 2 before nonce 1 -> NONCE_OUT_OF_ORDER
    const eSkip = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "100", nonce: 2, expiresAtUnix: now + 300 });
    expect(engine.verifyAndCommit(eSkip, { allowTestClock: true, nowUnix: now }).rejectionCodes).toContain("NONCE_OUT_OF_ORDER");

    // Nonce 1 -> ALLOW
    const e1 = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "100", nonce: 1, expiresAtUnix: now + 300 });
    expect(engine.verifyAndCommit(e1, { allowTestClock: true, nowUnix: now }).verdict).toBe("ALLOW");

    // Replaying nonce 1 -> NONCE_REPLAY
    const dReplay = engine.verifyAndCommit(e1, { allowTestClock: true, nowUnix: now });
    expect(dReplay.verdict).toBe("DENY");
    expect(dReplay.rejectionCodes).toContain("NONCE_REPLAY");
  });

  it("blocks expired intent, wrong chainId, wrong policyHash, and wrong agentId", () => {
    const { id, engine } = setupEngine();
    const now = 1_760_000_000;

    const expired = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "100", expiresAtUnix: now - 10 });
    expect(engine.quoteDecision(expired, { allowTestClock: true, nowUnix: now }).rejectionCodes).toContain("INTENT_EXPIRED");

    const wrongChain = signHybridIntent(id, {
      agentId: "wrong-agent",
      policyHashHex: "f".repeat(64),
      chainId: "qorechain-vladi",
      evmChainId: 9801,
      from: id.evmAddress,
      to: TARGET_ALLOWED,
      valueUqor: "100",
      calldataHex: "0x",
      nonce: 1,
      expiresAtUnix: now + 300,
    });
    const d = engine.quoteDecision(wrongChain, { allowTestClock: true, nowUnix: now });
    expect(d.verdict).toBe("DENY");
    expect(d.rejectionCodes).toContain("CHAIN_ID_MISMATCH");
    expect(d.rejectionCodes).toContain("POLICY_HASH_MISMATCH");
    expect(d.rejectionCodes).toContain("AGENT_ID_MISMATCH");
  });

  it("blocks all 6 adversarial quantum-downgrade, tamper, and replay attack vectors", () => {
    const { id, engine } = setupEngine();
    const now = 1_760_000_000;
    const valid = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "150000",
      expiresAtUnix: now + 600,
    });

    const vectors: QuantumAttackVector[] = [
      "strip_pqc_to_classical_only",
      "downgrade_sign_bytes_v2_to_v1",
      "downgrade_algorithm_to_mldsa44",
      "tamper_commitment_amount",
      "tamper_pqc_signature_byte",
      "replay_consumed_nonce",
    ];

    for (const vector of vectors) {
      const sim = engine.simulateQuantumDowngradeAttack(valid, vector, { allowTestClock: true, nowUnix: now });
      expect(sim.blocked, `vector ${vector} should be blocked`).toBe(true);
      expect(sim.decision.verdict).toBe("DENY");
    }
    // Shadow simulation must never mutate production engine state
    expect(engine.getLastNonce()).toBe(0);
    expect(engine.getAuditLog().length).toBe(0);
  });

  it("exports SHAKE-256 hash-chained & ML-DSA-87 attested audit bundle and catches tampering", () => {
    const { id, engine } = setupEngine();
    const now = 1_760_000_000;

    // Entry 1: ALLOW
    const e1 = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "100000", nonce: 1, expiresAtUnix: now + 300 });
    engine.verifyAndCommit(e1, { allowTestClock: true, nowUnix: now });
    // Entry 2: DENY (classical downgrade)
    const downgraded = signHybridIntent(id, { ...e1.intent, nonce: 2 }, { signatureTier: "classical-only" });
    engine.verifyAndCommit(downgraded, { allowTestClock: true, nowUnix: now + 5 });

    const bundle = engine.exportAuditBundle(id, now + 10);
    expect(bundle.entryCount).toBe(2);
    expect(bundle.allowedCount).toBe(1);
    expect(bundle.deniedCount).toBe(1);
    expect(bundle.blockedDowngradeCount).toBe(1);
    expect(bundle.attestation?.pqAlgorithm).toBe("ml-dsa-87");

    const okCheck = verifyAuditBundle(bundle);
    expect(okCheck.valid).toBe(true);
    expect(okCheck.chainIntact).toBe(true);
    expect(okCheck.attestationValid).toBe(true);

    // Tamper entry hash -> chainIntact=false
    const tamperedChain = {
      ...bundle,
      entries: [
        { ...bundle.entries[0]!, entryHashHex: "a".repeat(64) },
        ...bundle.entries.slice(1),
      ],
    };
    const badChain = verifyAuditBundle(tamperedChain);
    expect(badChain.valid).toBe(false);
    expect(badChain.chainIntact).toBe(false);

    // Tamper exportedAtUnix without re-signing -> ML-DSA-87 attestation fails
    const tamperedAtt = { ...bundle, exportedAtUnix: bundle.exportedAtUnix + 1 };
    const badAtt = verifyAuditBundle(tamperedAtt);
    expect(badAtt.valid).toBe(false);
    expect(badAtt.attestationValid).toBe(false);
  });

  it("enforces 30-day max owner-to-agent link TTL, rejects expired/revoked links, and restores execution on renewAgentLink()", () => {
    const owner = "0x9999999999999999999999999999999999999999";
    const t0 = 1_760_000_000;

    // Exceeding 30 days on policy construction throws RangeError
    expect(() =>
      setupEngine({
        agentLink: {
          ownerAddress: owner,
          linkedAtUnix: t0,
          expiresAtUnix: t0 + MAX_AGENT_LINK_TTL_SEC + 1,
        },
      }),
    ).toThrow(RangeError);

    const { id, engine } = setupEngine({
      agentLink: {
        ownerAddress: owner,
        linkedAtUnix: t0,
        expiresAtUnix: t0 + MAX_AGENT_LINK_TTL_SEC,
      },
    });

    // Cannot renew > 30 days or from wrong owner
    expect(() => engine.renewAgentLink(owner, t0 + MAX_AGENT_LINK_TTL_SEC + 10, t0, true)).toThrow(RangeError);
    expect(() => engine.renewAgentLink("0x1234", t0 + 86_400, t0, true)).toThrow();

    // Past 30-day TTL -> AGENT_LINK_EXPIRED
    const expiredAt = t0 + MAX_AGENT_LINK_TTL_SEC + 1;
    const env1 = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "200000",
      nonce: 1,
      expiresAtUnix: expiredAt + 600,
    });
    const denied = engine.verifyAndCommit(env1, { allowTestClock: true, nowUnix: expiredAt });
    expect(denied.verdict).toBe("DENY");
    expect(denied.rejectionCodes).toContain("AGENT_LINK_EXPIRED");
    expect(engine.getLastNonce()).toBe(0);

    // Owner renews within 30 days -> execution immediately succeeds!
    engine.renewAgentLink(owner, expiredAt + 14 * 86_400, expiredAt, true);
    const restored = engine.verifyAndCommit(env1, { allowTestClock: true, nowUnix: expiredAt + 1 });
    expect(restored.verdict).toBe("ALLOW");
    expect(engine.getLastNonce()).toBe(1);

    // Revoking blocks execution until owner re-links via renewAgentLink
    engine.revokeAgentLink(owner);
    const env2 = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "100000",
      nonce: 2,
      expiresAtUnix: expiredAt + 600,
    });
    expect(engine.quoteDecision(env2, { allowTestClock: true, nowUnix: expiredAt + 2 }).rejectionCodes).toContain("AGENT_REVOKED");
    engine.renewAgentLink(owner, expiredAt + 30 * 86_400, expiredAt + 2, true);
    expect(engine.verifyAndCommit(env2, { allowTestClock: true, nowUnix: expiredAt + 3 }).verdict).toBe("ALLOW");
  });

  it("enforces Scoped EVM Window bounds (startBlock, endBlock, maxTxCount, maxTotalValue, allowedTargets)", () => {
    const { id, engine } = setupEngine();
    const now = 1_760_000_000;
    engine.openScopedEvmWindow({
      startBlock: 100,
      endBlock: 110,
      maxTxCount: 2,
      maxTotalValueUqor: "1500000",
      allowedTargets: [TARGET_ALLOWED],
    });

    const e1 = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "1000000", nonce: 1, expiresAtUnix: now + 600 });
    // Out-of-window block (99 < 100)
    expect(engine.quoteDecision(e1, { allowTestClock: true, nowUnix: now, blockNumber: 99 }).rejectionCodes).toContain(
      "SCOPED_EVM_BLOCK_OUT_OF_RANGE",
    );

    // Target outside window's allowedTargets (even though TARGET_SECOND is globally allowlisted)
    const eTarget = createSignedAgentEnvelope(engine, id, { to: TARGET_SECOND, valueUqor: "100000", nonce: 1, expiresAtUnix: now + 600 });
    expect(engine.quoteDecision(eTarget, { allowTestClock: true, nowUnix: now, blockNumber: 105 }).rejectionCodes).toContain(
      "TARGET_NOT_ALLOWLISTED",
    );

    // Tx 1 (1M uqor) at block 105 -> ALLOW
    expect(engine.verifyAndCommit(e1, { allowTestClock: true, nowUnix: now, blockNumber: 105 }).verdict).toBe("ALLOW");

    // Tx 2 of 600k uqor -> 1.6M > 1.5M -> SCOPED_EVM_VALUE_EXCEEDED
    const eOverVal = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "600000", nonce: 2, expiresAtUnix: now + 600 });
    expect(engine.quoteDecision(eOverVal, { allowTestClock: true, nowUnix: now, blockNumber: 106 }).rejectionCodes).toContain(
      "SCOPED_EVM_VALUE_EXCEEDED",
    );

    // Tx 2 of 500k uqor -> 1.5M <= 1.5M, count=2 <= 2 -> ALLOW
    const e2 = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "500000", nonce: 2, expiresAtUnix: now + 600 });
    expect(engine.verifyAndCommit(e2, { allowTestClock: true, nowUnix: now, blockNumber: 106 }).verdict).toBe("ALLOW");

    // Tx 3 of 0 uqor -> count=3 > 2 -> SCOPED_EVM_TX_COUNT_EXCEEDED
    const e3 = createSignedAgentEnvelope(engine, id, { to: TARGET_ALLOWED, valueUqor: "0", nonce: 3, expiresAtUnix: now + 600 });
    expect(engine.quoteDecision(e3, { allowTestClock: true, nowUnix: now, blockNumber: 107 }).rejectionCodes).toContain(
      "SCOPED_EVM_TX_COUNT_EXCEEDED",
    );
  });

  it("rejects a stale nowUnix that would un-expire an intent unless allowTestClock is set", () => {
    const { id, engine } = setupEngine();
    const historical = 1_700_000_000;
    const env = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "1000",
      expiresAtUnix: historical + 60,
    });

    expect(() => engine.quoteDecision(env, { nowUnix: historical })).toThrow(StaleEvaluationClockError);
    expect(() => engine.verifyAndCommit(env, { nowUnix: historical })).toThrow(StaleEvaluationClockError);
    expect(engine.getLastNonce()).toBe(0);

    const live = engine.quoteDecision(env);
    expect(live.verdict).toBe("DENY");
    expect(live.rejectionCodes).toContain("INTENT_EXPIRED");

    const injected = engine.quoteDecision(env, { nowUnix: historical, allowTestClock: true });
    expect(injected.verdict).toBe("ALLOW");
    expect(injected.evaluatedAtUnix).toBe(historical);
  });

  it("rejects a future nowUnix that would delay intent expiry", () => {
    const { id, engine } = setupEngine();
    const wall = Math.floor(Date.now() / 1000);
    const env = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "1000",
      expiresAtUnix: wall - 5,
    });
    expect(() => engine.quoteDecision(env, { nowUnix: wall + 86_400 })).toThrow(StaleEvaluationClockError);
    const atWall = engine.quoteDecision(env);
    expect(atWall.rejectionCodes).toContain("INTENT_EXPIRED");
  });

  it("clamps a near-now caller timestamp to the wall clock so a small backdate cannot un-expire", () => {
    const { id, engine } = setupEngine();
    const wall = Math.floor(Date.now() / 1000);
    const env = createSignedAgentEnvelope(engine, id, {
      to: TARGET_ALLOWED,
      valueUqor: "1000",
      expiresAtUnix: wall - 2,
    });
    const decision = engine.quoteDecision(env, { nowUnix: wall - 10 });
    expect(decision.rejectionCodes).toContain("INTENT_EXPIRED");
    expect(decision.evaluatedAtUnix).toBeGreaterThanOrEqual(wall);
    expect(decision.evaluatedAtUnix).toBeLessThanOrEqual(wall + 2);
  });

  it("renewAgentLink rejects a backdated nowUnix without test-clock injection", () => {
    const owner = "0x9999999999999999999999999999999999999999";
    const wall = Math.floor(Date.now() / 1000);
    const { engine } = setupEngine({
      agentLink: {
        ownerAddress: owner,
        linkedAtUnix: wall - 100,
        expiresAtUnix: wall + 1_000,
      },
    });
    expect(() => engine.renewAgentLink(owner, wall + 86_400, 1_700_000_000)).toThrow(StaleEvaluationClockError);
    expect(() => engine.getAgentLinkStatus(1_700_000_000)).toThrow(StaleEvaluationClockError);
    expect(engine.getAgentLinkStatus().expired).toBe(false);
  });
});
