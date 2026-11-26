import { describe, expect, it } from "vitest";
import {
  DEFAULT_POLICY,
  QORECHAIN_DIANA,
  buildHybridSignBytes,
  evaluateGuardRequest,
  sha256Hex,
  type AgentActionRequest,
} from "../src/qoreGuardEngine.js";

async function makeValidRequest(nonce = "nonce-1001"): Promise<AgentActionRequest> {
  const req: AgentActionRequest = {
    id: "req-test-1",
    label: "Valid PQ Action",
    mcpTool: "qore_transfer_scoped",
    targetAddress: DEFAULT_POLICY.allowedTargets[0],
    amountQor: 10,
    nonce,
    signatureScheme: "ML-DSA-87+secp256k1",
    payloadSummary: "Test scoped transfer",
    expectedDigest: "",
    providedDigest: "",
    timestamp: "2026-11-27T00:00:00.000Z",
  };
  const digest = await sha256Hex(
    buildHybridSignBytes(QORECHAIN_DIANA.chainId, req)
  );
  req.expectedDigest = digest;
  req.providedDigest = digest;
  return req;
}

describe("QoreGuard PQ Policy & 5-Scenario Adversarial Breaker Lab", () => {
  it("approves valid ML-DSA-87+secp256k1 request within scoped limits", async () => {
    const req = await makeValidRequest();
    const res = await evaluateGuardRequest(DEFAULT_POLICY, req, new Set());
    expect(res.allowed).toBe(true);
    expect(res.code).toBe("APPROVED");
    expect(res.receiptHash).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it("Scenario 1: blocks Quantum Downgrade Attack (ECDSA-only)", async () => {
    const req = await makeValidRequest();
    req.signatureScheme = "ECDSA-only";
    const res = await evaluateGuardRequest(DEFAULT_POLICY, req, new Set());
    expect(res.allowed).toBe(false);
    expect(res.code).toBe("QUANTUM_DOWNGRADE_BLOCKED");
  });

  it("Scenario 2: blocks Replay Nonce Reuse", async () => {
    const req = await makeValidRequest("nonce-reused");
    const res = await evaluateGuardRequest(
      DEFAULT_POLICY,
      req,
      new Set(["nonce-reused"])
    );
    expect(res.allowed).toBe(false);
    expect(res.code).toBe("REPLAY_NONCE_BLOCKED");
  });

  it("Scenario 3: blocks Policy Cap Breach", async () => {
    const req = await makeValidRequest();
    req.amountQor = DEFAULT_POLICY.perTxCapQor + 10;
    const digest = await sha256Hex(
      buildHybridSignBytes(QORECHAIN_DIANA.chainId, req)
    );
    req.expectedDigest = digest;
    req.providedDigest = digest;

    const res = await evaluateGuardRequest(DEFAULT_POLICY, req, new Set());
    expect(res.allowed).toBe(false);
    expect(res.code).toBe("POLICY_CAP_EXCEEDED");
  });

  it("Scenario 4: blocks Tampered PQ Digest", async () => {
    const req = await makeValidRequest();
    req.providedDigest = `0x${"f".repeat(64)}`;
    const res = await evaluateGuardRequest(DEFAULT_POLICY, req, new Set());
    expect(res.allowed).toBe(false);
    expect(res.code).toBe("TAMPERED_PQ_DIGEST");
  });

  it("Scenario 5: blocks Rogue Tool Injection and unauthorized target", async () => {
    const req = await makeValidRequest();
    req.mcpTool = "qore_unrestricted_drain";
    req.targetAddress = "0xDEAD00000000000000000000000000000000BEEF";
    const digest = await sha256Hex(
      buildHybridSignBytes(QORECHAIN_DIANA.chainId, req)
    );
    req.expectedDigest = digest;
    req.providedDigest = digest;

    const res = await evaluateGuardRequest(DEFAULT_POLICY, req, new Set());
    expect(res.allowed).toBe(false);
    expect(res.code).toBe("ROGUE_TOOL_OR_TARGET_BLOCKED");
  });

  it("blocks execution when scoped EVM window has expired", async () => {
    const req = await makeValidRequest();
    const res = await evaluateGuardRequest(
      { ...DEFAULT_POLICY, windowBlocksRemaining: 0 },
      req,
      new Set()
    );
    expect(res.allowed).toBe(false);
    expect(res.code).toBe("EVM_WINDOW_EXPIRED");
  });
});
