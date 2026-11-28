// SPDX-License-Identifier: Apache-2.0
//
// QoreGuard Stateful Post-Quantum AI Agent Policy Engine:
// - Scoped spending caps & rolling velocity windows (spend + tx count)
// - Target allowlist / denylist + 4-byte EVM calldata selector firewall
// - QoreChain IQoreAI risk/anomaly preflight gating
// - Monotonic anti-replay nonce tracking
// - Anti-quantum-downgrade guard (ML-DSA-87 / SLH-DSA + v2 hybrid sign bytes)
// - Tamper-evident SHAKE-256 hash-chained & ML-DSA-87 attested audit ledger

import { bytesToHex } from "@noble/hashes/utils.js";
import { pubkeyHash } from "@qorechain/pqc";
import {
  computeIntentCommitment,
  computePolicyHash,
  frameFields,
  fromHex,
  pqcKeygen,
  pqcSignBytes,
  pqcVerifyBytes,
  shake256Hex,
  signHybridIntent,
  verifyHybridEnvelope,
} from "./crypto.js";
import { MAX_AGENT_LINK_TTL_SEC, QOREGUARD_DOMAINS } from "./networks.js";
import type {
  AgentLinkLease,
  AgentPolicy,
  AiPreflightSignal,
  AttackSimulationResult,
  AuditBundle,
  AuditLogEntry,
  GuardRejectionCode,
  HybridAgentIdentity,
  HybridSignedEnvelope,
  PolicyDecision,
  QuantumAttackVector,
  ScopedEvmWindowRule,
} from "./types.js";

const GENESIS_CHAIN_HASH = "0".repeat(64);

interface SpendEvent {
  readonly timestampUnix: number;
  readonly valueUqor: bigint;
  readonly nonce: number;
}

export class StaleEvaluationClockError extends Error {
  readonly code = "STALE_EVALUATION_CLOCK";

  constructor(message: string) {
    super(message);
    this.name = "StaleEvaluationClockError";
  }
}

/** Caller timestamps inside this skew are clamped to the wall clock. Beyond it, they are rejected. */
export const EVAL_CLOCK_SKEW_SEC = 30;

export interface EvaluateOptions {
  readonly nowUnix?: number;
  readonly blockNumber?: number;
  readonly aiSignal?: AiPreflightSignal;
  /**
   * Unit-test only. When true, `nowUnix` is used as given.
   * Production MCP and SDK callers must leave this unset so expiry follows the wall clock.
   */
  readonly allowTestClock?: boolean;
}

/**
 * Production clock for policy evaluation.
 * Omits the caller timestamp by default. A supplied `nowUnix` is clamped to the
 * wall clock inside `EVAL_CLOCK_SKEW_SEC` and rejected when it is stale or future
 * enough to bypass expiry, unless `allowTestClock` is set.
 */
export function resolveEvaluationNowUnix(options: EvaluateOptions = {}): number {
  const wall = Math.floor(Date.now() / 1000);
  if (options.nowUnix === undefined) return wall;
  if (!Number.isInteger(options.nowUnix)) {
    throw new StaleEvaluationClockError("nowUnix must be an integer UNIX timestamp in seconds");
  }
  if (options.allowTestClock === true) return options.nowUnix;
  const delta = options.nowUnix - wall;
  if (delta < -EVAL_CLOCK_SKEW_SEC || delta > EVAL_CLOCK_SKEW_SEC) {
    throw new StaleEvaluationClockError(
      `Caller nowUnix ${options.nowUnix} is ${Math.abs(delta)}s from wall clock ${wall} (limit ${EVAL_CLOCK_SKEW_SEC}s). ` +
        "Stale or future clocks cannot bypass expiry. Omit nowUnix, or set allowTestClock only inside unit tests.",
    );
  }
  return wall;
}

function parseNonNegativeBigInt(raw: string): bigint | null {
  if (!/^\d+$/.test(raw.trim())) return null;
  try {
    return BigInt(raw.trim());
  } catch {
    return null;
  }
}

function extractSelector(calldataHex: string): string | null {
  const clean = (calldataHex || "").trim().toLowerCase();
  if (!clean || clean === "0x") return null;
  if (!clean.startsWith("0x") || clean.length < 10) return null;
  return clean.slice(0, 10);
}

function normalizeAddress(addr: string): string {
  return addr.trim().toLowerCase();
}

export class QoreGuardPolicyEngine {
  public readonly policy: AgentPolicy;
  public readonly policyHashHex: string;

  private lastNonce = 0;
  private readonly consumedNonces = new Set<number>();
  private readonly spendHistory: SpendEvent[] = [];
  private readonly auditEntries: AuditLogEntry[] = [];
  private chainHeadHashHex: string = GENESIS_CHAIN_HASH;

  private activeLink: AgentLinkLease | null = null;
  private revoked = false;
  private activeScopedWindow: ScopedEvmWindowRule | null = null;
  private scopedWindowTxCount = 0;
  private scopedWindowTotalValue = 0n;

  constructor(policy: AgentPolicy) {
    if (
      policy.agentLink &&
      (policy.agentLink.expiresAtUnix <= policy.agentLink.linkedAtUnix ||
        policy.agentLink.expiresAtUnix - policy.agentLink.linkedAtUnix > MAX_AGENT_LINK_TTL_SEC)
    ) {
      throw new RangeError(
        `Owner-to-agent link TTL must be in (0, ${MAX_AGENT_LINK_TTL_SEC}] seconds (<= 30 days)`,
      );
    }
    this.policy = policy;
    this.policyHashHex = computePolicyHash(policy);
    this.activeLink = policy.agentLink ? { ...policy.agentLink } : null;
    this.activeScopedWindow = policy.scopedEvmWindow ? { ...policy.scopedEvmWindow } : null;
  }

  /** Links or renews an owner-to-agent lease, enforcing MAX_AGENT_LINK_TTL_SEC (30 days). */
  public renewAgentLink(
    ownerAddress: string,
    newExpiresAtUnix: number,
    nowUnix?: number,
    allowTestClock = false,
  ): AgentLinkLease {
    const resolvedNow = resolveEvaluationNowUnix(
      nowUnix === undefined ? { allowTestClock } : { nowUnix, allowTestClock },
    );
    if (!ownerAddress.trim()) {
      throw new Error("ownerAddress is required");
    }
    if (this.activeLink && normalizeAddress(this.activeLink.ownerAddress) !== normalizeAddress(ownerAddress)) {
      throw new Error("Only the linked policy owner may renew the agent link");
    }
    const ttl = newExpiresAtUnix - resolvedNow;
    if (ttl <= 0 || ttl > MAX_AGENT_LINK_TTL_SEC) {
      throw new RangeError(
        `Renewal TTL (${ttl}s) must be > 0 and <= ${MAX_AGENT_LINK_TTL_SEC}s (30 days max)`,
      );
    }
    this.activeLink = {
      ownerAddress,
      linkedAtUnix: resolvedNow,
      expiresAtUnix: newExpiresAtUnix,
    };
    this.revoked = false;
    return { ...this.activeLink };
  }

  /** Immediately revokes the owner-to-agent link until the owner explicitly re-links. */
  public revokeAgentLink(ownerAddress: string): void {
    if (this.activeLink && normalizeAddress(this.activeLink.ownerAddress) !== normalizeAddress(ownerAddress)) {
      throw new Error("Only the linked policy owner may revoke the agent link");
    }
    this.revoked = true;
  }

  public getAgentLinkStatus(nowUnix?: number, allowTestClock = false): {
    readonly configured: boolean;
    readonly revoked: boolean;
    readonly expired: boolean;
    readonly lease: AgentLinkLease | null;
    readonly maxTtlSec: number;
  } {
    const resolvedNow = resolveEvaluationNowUnix(
      nowUnix === undefined ? { allowTestClock } : { nowUnix, allowTestClock },
    );
    return {
      configured: this.activeLink !== null,
      revoked: this.revoked,
      expired: this.activeLink !== null && resolvedNow > this.activeLink.expiresAtUnix,
      lease: this.activeLink ? { ...this.activeLink } : null,
      maxTtlSec: MAX_AGENT_LINK_TTL_SEC,
    };
  }

  /** Opens or replaces a Scoped EVM Window (blocks, tx count, total value, allowed targets). */
  public openScopedEvmWindow(window: ScopedEvmWindowRule): void {
    if (window.endBlock < window.startBlock || window.maxTxCount <= 0) {
      throw new RangeError("Invalid ScopedEvmWindowRule: require endBlock >= startBlock and maxTxCount > 0");
    }
    const maxVal = parseNonNegativeBigInt(window.maxTotalValueUqor);
    if (maxVal === null || maxVal <= 0n) {
      throw new RangeError("Invalid ScopedEvmWindowRule: maxTotalValueUqor must be a positive integer string");
    }
    this.activeScopedWindow = { ...window };
    this.scopedWindowTxCount = 0;
    this.scopedWindowTotalValue = 0n;
  }

  public closeScopedEvmWindow(): void {
    this.activeScopedWindow = null;
  }

  public getScopedEvmWindowState(): {
    readonly active: boolean;
    readonly rule: ScopedEvmWindowRule | null;
    readonly usedTxCount: number;
    readonly usedTotalValueUqor: string;
  } {
    return {
      active: this.activeScopedWindow !== null,
      rule: this.activeScopedWindow ? { ...this.activeScopedWindow } : null,
      usedTxCount: this.scopedWindowTxCount,
      usedTotalValueUqor: this.scopedWindowTotalValue.toString(),
    };
  }

  public getLastNonce(): number {
    return this.lastNonce;
  }

  public getAuditLog(): readonly AuditLogEntry[] {
    return this.auditEntries;
  }

  public getSpendHistoryCount(): number {
    return this.spendHistory.length;
  }

  private computeVelocitySnapshot(nowUnix: number): PolicyDecision["velocitySnapshot"] {
    return this.policy.velocityWindows.map((w) => {
      const cutoff = nowUnix - w.windowSec;
      let sum = 0n;
      let count = 0;
      for (const ev of this.spendHistory) {
        if (ev.timestampUnix >= cutoff) {
          sum += ev.valueUqor;
          count += 1;
        }
      }
      return {
        label: w.label,
        windowSpendUqor: sum.toString(),
        maxSpendUqor: w.maxSpendUqor,
        windowTxCount: count,
        maxTxCount: w.maxTxCount,
      };
    });
  }

  private evaluateInternal(
    envelope: HybridSignedEnvelope,
    commit: boolean,
    options: EvaluateOptions = {},
  ): PolicyDecision {
    const nowUnix = resolveEvaluationNowUnix(options);
    const { intent } = envelope;
    const codes: GuardRejectionCode[] = [];
    const reasons: string[] = [];

    // 1. Cryptographic & anti-quantum-downgrade verification
    const cryptoRes = verifyHybridEnvelope(envelope, this.policy);
    for (const c of cryptoRes.codes) {
      codes.push(c);
      reasons.push(`Crypto/anti-downgrade check failed: ${c}`);
    }

    // 2. Domain, chain, policy, agent, and expiration binding
    if (intent.chainId !== this.policy.chainId || intent.evmChainId !== this.policy.evmChainId) {
      codes.push("CHAIN_ID_MISMATCH");
      reasons.push(
        `Chain mismatch: got ${intent.chainId}/${intent.evmChainId}, expected ${this.policy.chainId}/${this.policy.evmChainId}`,
      );
    }
    if (intent.policyHashHex.toLowerCase() !== this.policyHashHex.toLowerCase()) {
      codes.push("POLICY_HASH_MISMATCH");
      reasons.push("Intent policyHashHex does not match active QoreGuard policy");
    }
    if (intent.agentId !== this.policy.agentId) {
      codes.push("AGENT_ID_MISMATCH");
      reasons.push(`Agent ID mismatch: got "${intent.agentId}", expected "${this.policy.agentId}"`);
    }
    if (intent.expiresAtUnix < nowUnix) {
      codes.push("INTENT_EXPIRED");
      reasons.push(`Intent expired at ${intent.expiresAtUnix} (now=${nowUnix})`);
    }

    // 2b. Owner-to-agent 30-day link lease & revocation enforcement
    if (this.revoked) {
      codes.push("AGENT_REVOKED");
      reasons.push("Owner-to-agent link has been revoked");
    }
    if (this.activeLink) {
      if (this.activeLink.expiresAtUnix - this.activeLink.linkedAtUnix > MAX_AGENT_LINK_TTL_SEC) {
        codes.push("AGENT_LINK_TTL_EXCEEDED");
        reasons.push(`Agent link lease exceeds 30-day MAX_AGENT_LINK_TTL_SEC (${MAX_AGENT_LINK_TTL_SEC}s)`);
      }
      if (nowUnix > this.activeLink.expiresAtUnix) {
        codes.push("AGENT_LINK_EXPIRED");
        reasons.push(
          `Owner-to-agent 30-day link expired at ${this.activeLink.expiresAtUnix} (now=${nowUnix}); call renewAgentLink()`,
        );
      }
    }

    // 3. Monotonic replay nonce enforcement
    if (!Number.isInteger(intent.nonce) || intent.nonce <= 0) {
      codes.push("NONCE_OUT_OF_ORDER");
      reasons.push(`Nonce must be a positive integer, got ${intent.nonce}`);
    } else if (this.consumedNonces.has(intent.nonce) || intent.nonce <= this.lastNonce) {
      codes.push("NONCE_REPLAY");
      reasons.push(`Replay detected: nonce ${intent.nonce} <= last consumed nonce ${this.lastNonce}`);
    } else if (this.policy.requireStrictSequentialNonce && intent.nonce !== this.lastNonce + 1) {
      codes.push("NONCE_OUT_OF_ORDER");
      reasons.push(`Strict sequential nonce required: expected ${this.lastNonce + 1}, got ${intent.nonce}`);
    }

    // 4. Target allowlist / denylist and EVM calldata selector firewall
    const toNorm = normalizeAddress(intent.to);
    const denySet = new Set(this.policy.denylistedTargets.map(normalizeAddress));
    if (denySet.has(toNorm)) {
      codes.push("TARGET_DENYLISTED");
      reasons.push(`Target ${intent.to} is explicitly denylisted`);
    }
    if (this.policy.allowlistedTargets.length > 0) {
      const allowSet = new Set(this.policy.allowlistedTargets.map(normalizeAddress));
      if (!allowSet.has(toNorm)) {
        codes.push("TARGET_NOT_ALLOWLISTED");
        reasons.push(`Target ${intent.to} is not in policy allowlist`);
      }
    }

    const selector = extractSelector(intent.calldataHex);
    if (selector) {
      if (this.policy.forbiddenSelectors?.map((s) => s.toLowerCase()).includes(selector)) {
        codes.push("SELECTOR_FORBIDDEN");
        reasons.push(`Calldata selector ${selector} is forbidden by policy`);
      }
      if (
        this.policy.allowedSelectors &&
        this.policy.allowedSelectors.length > 0 &&
        !this.policy.allowedSelectors.map((s) => s.toLowerCase()).includes(selector)
      ) {
        codes.push("SELECTOR_NOT_ALLOWED");
        reasons.push(`Calldata selector ${selector} is not in allowedSelectors`);
      }
    }

    // 5. Spending cap & rolling velocity windows
    const valueBn = parseNonNegativeBigInt(intent.valueUqor);
    const maxSingleBn = parseNonNegativeBigInt(this.policy.maxSingleTxUqor);
    const velocitySnapshot = this.computeVelocitySnapshot(nowUnix);
    if (valueBn === null || maxSingleBn === null) {
      codes.push("INVALID_VALUE");
      reasons.push(`Invalid uqor value: ${intent.valueUqor}`);
    } else {
      if (valueBn > maxSingleBn) {
        codes.push("SPEND_CAP_EXCEEDED");
        reasons.push(`Single-tx spend ${valueBn} uqor exceeds cap ${maxSingleBn} uqor`);
      }
      for (const snap of velocitySnapshot) {
        const curSpend = BigInt(snap.windowSpendUqor);
        const capSpend = BigInt(snap.maxSpendUqor);
        if (curSpend + valueBn > capSpend) {
          codes.push("VELOCITY_SPEND_EXCEEDED");
          reasons.push(
            `Velocity window "${snap.label}" spend ${curSpend + valueBn} uqor exceeds limit ${capSpend} uqor`,
          );
        }
        if (snap.windowTxCount + 1 > snap.maxTxCount) {
          codes.push("VELOCITY_COUNT_EXCEEDED");
          reasons.push(
            `Velocity window "${snap.label}" tx count ${snap.windowTxCount + 1} exceeds limit ${snap.maxTxCount}`,
          );
        }
      }
    }

    // 5b. Scoped EVM Window bounds (startBlock, endBlock, maxTxCount, maxTotalValue, allowedTargets)
    if (this.activeScopedWindow) {
      const win = this.activeScopedWindow;
      const evalBlock = options.blockNumber ?? intent.blockNumber;
      if (evalBlock === undefined || evalBlock < win.startBlock || evalBlock > win.endBlock) {
        codes.push("SCOPED_EVM_BLOCK_OUT_OF_RANGE");
        reasons.push(
          `Block ${evalBlock ?? "unspecified"} is outside Scoped EVM Window [${win.startBlock}, ${win.endBlock}]`,
        );
      }
      if (this.scopedWindowTxCount + 1 > win.maxTxCount) {
        codes.push("SCOPED_EVM_TX_COUNT_EXCEEDED");
        reasons.push(
          `Scoped EVM Window tx count ${this.scopedWindowTxCount + 1} exceeds maxTxCount ${win.maxTxCount}`,
        );
      }
      const maxWinVal = parseNonNegativeBigInt(win.maxTotalValueUqor);
      if (valueBn !== null && maxWinVal !== null && this.scopedWindowTotalValue + valueBn > maxWinVal) {
        codes.push("SCOPED_EVM_VALUE_EXCEEDED");
        reasons.push(
          `Scoped EVM Window cumulative value ${this.scopedWindowTotalValue + valueBn} exceeds ${maxWinVal}`,
        );
      }
      if (win.allowedTargets && win.allowedTargets.length > 0) {
        const winAllow = new Set(win.allowedTargets.map(normalizeAddress));
        if (!winAllow.has(toNorm) && !codes.includes("TARGET_NOT_ALLOWLISTED")) {
          codes.push("TARGET_NOT_ALLOWLISTED");
          reasons.push(`Target ${intent.to} is not permitted in active Scoped EVM Window`);
        }
      }
    }

    // 6. Optional QoreChain IQoreAI risk/anomaly gate
    if (options.aiSignal) {
      if (options.aiSignal.anomalyFlagged) {
        codes.push("AI_ANOMALY_FLAGGED");
        reasons.push(`IQoreAI anomaly detector flagged tx (score=${options.aiSignal.riskScore})`);
      }
      if (
        this.policy.maxAiRiskLevel !== undefined &&
        options.aiSignal.riskLevel > this.policy.maxAiRiskLevel
      ) {
        codes.push("AI_RISK_THRESHOLD_EXCEEDED");
        reasons.push(
          `IQoreAI risk level ${options.aiSignal.riskLevel} exceeds policy max ${this.policy.maxAiRiskLevel}`,
        );
      }
    }

    const uniqueCodes = Array.from(new Set(codes));
    const verdict: "ALLOW" | "DENY" = uniqueCodes.length === 0 ? "ALLOW" : "DENY";
    const committed = commit && verdict === "ALLOW";

    if (committed && valueBn !== null) {
      this.consumedNonces.add(intent.nonce);
      this.lastNonce = Math.max(this.lastNonce, intent.nonce);
      this.spendHistory.push({
        timestampUnix: nowUnix,
        valueUqor: valueBn,
        nonce: intent.nonce,
      });
      if (this.activeScopedWindow) {
        this.scopedWindowTxCount += 1;
        this.scopedWindowTotalValue += valueBn;
      }
    }

    const decisionDigestHex = shake256Hex(
      frameFields([
        "qoreguard-decision-v1",
        this.policyHashHex,
        intent.agentId,
        String(intent.nonce),
        verdict,
        uniqueCodes.join(","),
        cryptoRes.computedCommitmentHex,
        String(nowUnix),
      ]),
      32,
    );

    const decision: PolicyDecision = {
      decisionId: `dec_${decisionDigestHex.slice(0, 16)}`,
      verdict,
      committed,
      evaluatedAtUnix: nowUnix,
      policyId: this.policy.policyId,
      policyHashHex: this.policyHashHex,
      agentId: intent.agentId,
      nonce: intent.nonce,
      valueUqor: intent.valueUqor,
      to: intent.to,
      signatureTier: envelope.signatureTier,
      pqAlgorithm: envelope.pqc?.algorithm ?? "none",
      signBytesVersion: envelope.signBytesVersion,
      rejectionCodes: uniqueCodes,
      reasons,
      crypto: cryptoRes,
      velocitySnapshot: committed ? this.computeVelocitySnapshot(nowUnix) : velocitySnapshot,
      aiSignal: options.aiSignal,
      decisionDigestHex,
    };

    if (commit) {
      const seq = this.auditEntries.length + 1;
      const prevEntryHashHex = this.chainHeadHashHex;
      const entryHashHex = shake256Hex(
        frameFields([
          QOREGUARD_DOMAINS.auditBundle,
          String(seq),
          String(nowUnix),
          prevEntryHashHex,
          decision.decisionDigestHex,
        ]),
        32,
      );
      this.auditEntries.push({
        seq,
        timestampUnix: nowUnix,
        decision,
        prevEntryHashHex,
        entryHashHex,
      });
      this.chainHeadHashHex = entryHashHex;
    }

    return decision;
  }

  /** Dry-run policy & PQ signature quote with zero state mutation. */
  public quoteDecision(envelope: HybridSignedEnvelope, options?: EvaluateOptions): PolicyDecision {
    return this.evaluateInternal(envelope, false, options);
  }

  /** Verifies and atomically commits nonce/spend/audit state on ALLOW (and logs DENY). */
  public verifyAndCommit(envelope: HybridSignedEnvelope, options?: EvaluateOptions): PolicyDecision {
    return this.evaluateInternal(envelope, true, options);
  }

  /**
   * Simulates a concrete adversarial quantum-downgrade, tamper, or replay attack
   * against a valid hybrid envelope without polluting production spend state.
   */
  public simulateQuantumDowngradeAttack(
    validEnvelope: HybridSignedEnvelope,
    vector: QuantumAttackVector,
    options: EvaluateOptions = {},
  ): AttackSimulationResult {
    const shadow = new QoreGuardPolicyEngine(this.policy);
    // Replicate current nonce & spend state into the isolated shadow engine
    shadow.lastNonce = this.lastNonce;
    for (const n of this.consumedNonces) shadow.consumedNonces.add(n);
    shadow.spendHistory.push(...this.spendHistory);

    let mutated: HybridSignedEnvelope = structuredClone(validEnvelope);
    let description = "";
    let expectedCodes: GuardRejectionCode[] = [];

    switch (vector) {
      case "strip_pqc_to_classical_only": {
        description = "Adversary strips ML-DSA-87 layer and submits classical-only ECDSA/Ed25519 signature.";
        expectedCodes = ["QUANTUM_DOWNGRADE_CLASSICAL_ONLY", "PQC_SIGNATURE_MISSING"];
        const { pqc: _removed, ...rest } = mutated;
        mutated = { ...rest, signatureTier: "classical-only" };
        break;
      }
      case "downgrade_sign_bytes_v2_to_v1": {
        description = "Adversary downgrades QoreChain v2 domain-separated sign-bytes to legacy v1 framing.";
        expectedCodes = ["QUANTUM_DOWNGRADE_SIGN_BYTES_V1"];
        mutated = { ...mutated, signBytesVersion: "v1" };
        break;
      }
      case "downgrade_algorithm_to_mldsa44": {
        description = "Adversary swaps FIPS-204 ML-DSA-87 (L5) for weaker ML-DSA-44 (L2) below policy floor.";
        expectedCodes = ["QUANTUM_DOWNGRADE_WEAK_ALGORITHM"];
        const weak = pqcKeygen("ml-dsa-44");
        const weakSig = pqcSignBytes("ml-dsa-44", weak.secretKey, fromHex(validEnvelope.hybridSignBytesHex));
        mutated = {
          ...mutated,
          pqc: {
            algorithm: "ml-dsa-44",
            publicKeyHex: bytesToHex(weak.publicKey),
            pubkeyHashHex: weak.pubkeyHashHex,
            signatureHex: bytesToHex(weakSig),
          },
        };
        break;
      }
      case "tamper_commitment_amount": {
        description = "MITM tampers transfer valueUqor after hybrid ML-DSA-87 signature generation.";
        expectedCodes = ["COMMITMENT_TAMPERED"];
        const inflated = (BigInt(mutated.intent.valueUqor) + 1_000_000n).toString();
        mutated = {
          ...mutated,
          intent: { ...mutated.intent, valueUqor: inflated },
        };
        break;
      }
      case "tamper_pqc_signature_byte": {
        description = "Adversary flips 1 bit inside the 4,627-byte ML-DSA-87 post-quantum signature.";
        expectedCodes = ["PQC_SIGNATURE_INVALID"];
        if (mutated.pqc) {
          const sigBytes = fromHex(mutated.pqc.signatureHex);
          if (sigBytes.length > 10) {
            sigBytes[10] = (sigBytes[10] ?? 0) ^ 0x01;
          }
          mutated = {
            ...mutated,
            pqc: { ...mutated.pqc, signatureHex: bytesToHex(sigBytes) },
          };
        }
        break;
      }
      case "replay_consumed_nonce": {
        description = "Adversary replays a previously authorized ML-DSA-87 hybrid transaction envelope.";
        expectedCodes = ["NONCE_REPLAY"];
        // First authorize once in the shadow engine, then replay the exact envelope
        const first = shadow.verifyAndCommit(validEnvelope, options);
        if (first.verdict !== "ALLOW") {
          // Ensure nonce is marked consumed even if caller passed an already-spent envelope
          shadow.consumedNonces.add(validEnvelope.intent.nonce);
          shadow.lastNonce = Math.max(shadow.lastNonce, validEnvelope.intent.nonce);
        }
        break;
      }
    }

    const decision = shadow.quoteDecision(mutated, options);
    const blocked =
      decision.verdict === "DENY" &&
      expectedCodes.every((code) => decision.rejectionCodes.includes(code));

    return {
      vector,
      description,
      blocked,
      expectedCodes,
      observedCodes: decision.rejectionCodes,
      decision,
    };
  }

  /** Exports a canonical SHAKE-256 hash-chained & optionally ML-DSA-87 attested audit bundle. */
  public exportAuditBundle(
    attestationIdentity?: HybridAgentIdentity,
    nowUnix = Math.floor(Date.now() / 1000),
  ): AuditBundle {
    let allowedCount = 0;
    let deniedCount = 0;
    let blockedDowngradeCount = 0;
    for (const entry of this.auditEntries) {
      if (entry.decision.verdict === "ALLOW") allowedCount += 1;
      else deniedCount += 1;
      if (entry.decision.crypto.downgradeDetected) blockedDowngradeCount += 1;
    }

    const base: AuditBundle = {
      version: "qoreguard-audit-v1",
      exportedAtUnix: nowUnix,
      policyId: this.policy.policyId,
      policyHashHex: this.policyHashHex,
      network: this.policy.network,
      chainId: this.policy.chainId,
      evmChainId: this.policy.evmChainId,
      entryCount: this.auditEntries.length,
      allowedCount,
      deniedCount,
      blockedDowngradeCount,
      chainHeadHashHex: this.chainHeadHashHex,
      entries: [...this.auditEntries],
    };

    if (!attestationIdentity) return base;

    const msg = computeAuditBundleAttestationBytes(base);
    const sig = pqcSignBytes(
      attestationIdentity.pqAlgorithm,
      fromHex(attestationIdentity.pqSecretKeyHex),
      msg,
    );
    return {
      ...base,
      attestation: {
        domain: QOREGUARD_DOMAINS.auditBundle,
        pqAlgorithm: attestationIdentity.pqAlgorithm,
        pqPublicKeyHex: attestationIdentity.pqPublicKeyHex,
        pqPubkeyHashHex: attestationIdentity.pqPubkeyHashHex,
        signatureHex: bytesToHex(sig),
      },
    };
  }
}

export function computeAuditBundleAttestationBytes(bundle: AuditBundle): Uint8Array {
  return frameFields([
    QOREGUARD_DOMAINS.auditBundle,
    bundle.version,
    bundle.policyId,
    bundle.policyHashHex,
    bundle.chainId,
    String(bundle.evmChainId),
    String(bundle.entryCount),
    bundle.chainHeadHashHex,
    String(bundle.exportedAtUnix),
  ]);
}

/**
 * Independently verifies a QoreGuard AuditBundle's hash chain AND ML-DSA-87/SLH-DSA attestation.
 */
export function verifyAuditBundle(bundle: AuditBundle): {
  valid: boolean;
  chainIntact: boolean;
  attestationValid: boolean | null;
  errors: string[];
} {
  const errors: string[] = [];
  let prev = GENESIS_CHAIN_HASH;
  let chainIntact = true;

  if (bundle.entryCount !== bundle.entries.length) {
    chainIntact = false;
    errors.push(`entryCount mismatch: declared ${bundle.entryCount}, actual ${bundle.entries.length}`);
  }

  for (let i = 0; i < bundle.entries.length; i++) {
    const e = bundle.entries[i]!;
    if (e.seq !== i + 1) {
      chainIntact = false;
      errors.push(`sequence discontinuity at index ${i}: got ${e.seq}`);
    }
    if (e.prevEntryHashHex !== prev) {
      chainIntact = false;
      errors.push(`broken prevEntryHashHex at seq=${e.seq}`);
    }
    const recomputed = shake256Hex(
      frameFields([
        QOREGUARD_DOMAINS.auditBundle,
        String(e.seq),
        String(e.timestampUnix),
        e.prevEntryHashHex,
        e.decision.decisionDigestHex,
      ]),
      32,
    );
    if (recomputed !== e.entryHashHex) {
      chainIntact = false;
      errors.push(`tampered entryHashHex at seq=${e.seq}`);
    }
    prev = e.entryHashHex;
  }

  if (prev !== bundle.chainHeadHashHex) {
    chainIntact = false;
    errors.push("chainHeadHashHex does not match final audit entry hash");
  }

  let attestationValid: boolean | null = null;
  if (bundle.attestation) {
    try {
      const pk = fromHex(bundle.attestation.pqPublicKeyHex);
      const actualHash = bytesToHex(pubkeyHash(pk, 32));
      if (actualHash !== bundle.attestation.pqPubkeyHashHex.toLowerCase()) {
        attestationValid = false;
        errors.push("attestation pqPubkeyHashHex mismatch");
      } else {
        const msg = computeAuditBundleAttestationBytes(bundle);
        attestationValid = pqcVerifyBytes(
          bundle.attestation.pqAlgorithm,
          pk,
          msg,
          fromHex(bundle.attestation.signatureHex),
        );
        if (!attestationValid) {
          errors.push("attestation post-quantum signature verification failed");
        }
      }
    } catch {
      attestationValid = false;
      errors.push("malformed attestation signature or public key");
    }
  }

  const valid = chainIntact && (attestationValid === null || attestationValid) && errors.length === 0;
  return { valid, chainIntact, attestationValid, errors };
}

/**
 * Helper to build a valid signed envelope directly bound to a policy engine's
 * policyHashHex and next available nonce (useful for CLI/scripts/tests).
 */
export function createSignedAgentEnvelope(
  engine: QoreGuardPolicyEngine,
  identity: HybridAgentIdentity,
  params: {
    to: string;
    valueUqor: string;
    calldataHex?: string;
    nonce?: number;
    expiresAtUnix?: number;
    memo?: string;
    signBytesVersion?: "v1" | "v2";
  },
): HybridSignedEnvelope {
  const nowUnix = Math.floor(Date.now() / 1000);
  const intent = {
    agentId: engine.policy.agentId,
    policyHashHex: engine.policyHashHex,
    chainId: engine.policy.chainId,
    evmChainId: engine.policy.evmChainId,
    from: identity.evmAddress,
    to: params.to,
    valueUqor: params.valueUqor,
    calldataHex: params.calldataHex ?? "0x",
    nonce: params.nonce ?? engine.getLastNonce() + 1,
    expiresAtUnix: params.expiresAtUnix ?? nowUnix + 300,
    memo: params.memo,
  };
  // Sanity-check commitment builds cleanly
  computeIntentCommitment(intent);
  return signHybridIntent(identity, intent, {
    signBytesVersion: params.signBytesVersion ?? engine.policy.requiredSignBytesVersion,
    signatureTier: "hybrid-pqc",
  });
}
