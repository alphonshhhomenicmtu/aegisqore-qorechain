// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateHybridAgentIdentity } from "../src/crypto.js";
import { createDefaultPolicy } from "../src/mcp/server.js";
import { createSignedAgentEnvelope, QoreGuardPolicyEngine } from "../src/policy-engine.js";
import {
  executeTurnkeyGuardedTx,
  fetchAiPreflightSignal,
  probeQoreXNetwork,
} from "../src/testnet-client.js";

describe("QoreX Testnet Probe & Turnkey Guarded Transaction Runner", () => {
  it("reports honest offline simulation mode with real local ML-DSA-87 self-test", async () => {
    const report = await probeQoreXNetwork({ network: "testnet", offline: true });
    expect(report.mode).toBe("simulated");
    expect(report.chainId).toBe("qorechain-diana");
    expect(report.expectedEvmChainId).toBe(9800);
    expect(report.localMlDsa87SelfTest.valid).toBe(true);
    expect(report.localMlDsa87SelfTest.pubkeyBytes).toBe(2592);
    expect(report.localMlDsa87SelfTest.signatureBytes).toBe(4627);
    expect(report.fallbackReason).toBeTruthy();
  });

  it("falls back cleanly to simulated mode when RPC is unreachable", async () => {
    const failingFetch: typeof fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    const report = await probeQoreXNetwork({
      network: "testnet",
      evmRpcUrl: "http://127.0.0.1:1",
      rpcUrl: "http://127.0.0.1:1",
      timeoutMs: 500,
      fetchImpl: failingFetch,
    });
    expect(report.mode).toBe("simulated");
    expect(report.observedEvmChainId).toBeNull();
    expect(report.consensusStatus.reachable).toBe(false);
    expect(report.fallbackReason).toContain("EVM JSON-RPC unreachable");
  });

  it("parses live QoreX EVM JSON-RPC and consensus /status responses via injected fetch", async () => {
    const mockFetch: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith("/status")) {
        return new Response(
          JSON.stringify({
            result: {
              node_info: { network: "qorechain-diana" },
              sync_info: { latest_block_height: "10800982", latest_block_hash: "D532F86D", catching_up: false },
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      const body = JSON.parse(String(init?.body ?? "{}")) as { id: number; method: string };
      let result: unknown = "0x";
      if (body.method === "eth_chainId") result = "0x2648";
      else if (body.method === "eth_blockNumber") result = "0xa4cf56";
      else if (body.method === "eth_gasPrice") result = "0x3b9aca00";
      else if (body.method === "eth_call") {
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32000, message: "feature unavailable" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const report = await probeQoreXNetwork({
      network: "testnet",
      evmRpcUrl: "https://mock-evm.qore.host",
      rpcUrl: "https://mock-rpc.qore.host",
      fetchImpl: mockFetch,
    });
    expect(report.mode).toBe("live");
    expect(report.observedEvmChainId).toBe(9800);
    expect(report.evmBlockNumber).toBe("10800982");
    expect(report.consensusStatus.reachable).toBe(true);
    expect(report.consensusStatus.network).toBe("qorechain-diana");
  });

  it("blocks policy-violating tx before broadcast and runs dry-run simulation on ALLOW", async () => {
    const id = generateHybridAgentIdentity("agent-treasury-01", { pqAlgorithm: "ml-dsa-87" });
    const policy = createDefaultPolicy("testnet", id.pqPubkeyHashHex);
    const engine = new QoreGuardPolicyEngine(policy);

    // 1. Over-cap tx is blocked BEFORE broadcast even if a key were passed
    const overCap = createSignedAgentEnvelope(engine, id, {
      to: "0x000000000000000000000000000000000000dEaD",
      valueUqor: "99999999",
    });
    const blocked = await executeTurnkeyGuardedTx({ engine, envelope: overCap, dryRun: false });
    expect(blocked.mode).toBe("blocked-by-policy");
    expect(blocked.decision.verdict).toBe("DENY");
    expect(blocked.decision.rejectionCodes).toContain("SPEND_CAP_EXCEEDED");

    // 2. Valid tx with dryRun=true / no key returns honest simulation fallback
    const valid = createSignedAgentEnvelope(engine, id, {
      to: "0x000000000000000000000000000000000000dEaD",
      valueUqor: "100000",
    });
    const sim = await executeTurnkeyGuardedTx({ engine, envelope: valid, dryRun: true });
    expect(sim.mode).toBe("simulated-dry-run");
    expect(sim.decision.verdict).toBe("ALLOW");
    expect(sim.decision.committed).toBe(true);
  });

  it("evaluates deterministic local AI risk heuristic when offline", async () => {
    const risky = await fetchAiPreflightSignal({
      sender: "0x1111111111111111111111111111111111111111",
      valueUqor: 200_000_000n,
      calldataHex: "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111",
      offline: true,
    });
    expect(risky.source).toBe("local-heuristic");
    expect(risky.anomalyFlagged).toBe(true);
    expect(risky.riskLevel).toBeGreaterThanOrEqual(3);
  });
});
