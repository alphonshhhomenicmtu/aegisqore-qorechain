// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  QOREGUARD_REGISTRY_ABI,
  QOREGUARD_REGISTRY_BYTECODE,
  QOREGUARD_REGISTRY_BYTECODE_BYTES,
} from "../src/contracts/registry-artifact.js";
import { deployPolicyRegistry } from "../src/registry-deployer.js";

describe("QoreGuardPolicyRegistry Deployer & Dry-Run Gas Estimator", () => {
  it("bundles valid compiled QoreGuardPolicyRegistry creation bytecode and ABI", () => {
    expect(QOREGUARD_REGISTRY_BYTECODE.startsWith("0x")).toBe(true);
    expect(QOREGUARD_REGISTRY_BYTECODE_BYTES).toBeGreaterThan(2000);
    expect(QOREGUARD_REGISTRY_BYTECODE_BYTES).toBeLessThan(24576);
    const fnNames = QOREGUARD_REGISTRY_ABI.filter((x) => x.type === "function").map((x) => x.name);
    expect(fnNames).toContain("registerAgentPolicy");
    expect(fnNames).toContain("authorizeAction");
    expect(fnNames).toContain("evaluateAndLogAction");
    expect(fnNames).toContain("revokeAgent");
  });

  it("estimates deployment gas via eth_estimateGas against mocked QoreX EVM 9800 RPC", async () => {
    const mockFetch: typeof fetch = async (_input, init) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as { id: number; method: string };
      let result: string = "0x0";
      if (body.method === "eth_chainId") result = "0x2648";
      else if (body.method === "eth_blockNumber") result = "0xa4cf56";
      else if (body.method === "eth_gasPrice") result = "0x1a3185c500";
      else if (body.method === "eth_estimateGas") result = "0x249f00"; // 2,400,000 gas
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const report = await deployPolicyRegistry({
      network: "testnet",
      evmRpcUrl: "https://mock-evm.qore.host",
      dryRun: true,
      fetchImpl: mockFetch,
    });
    expect(report.mode).toBe("dry-run-live-estimate");
    expect(report.observedEvmChainId).toBe(9800);
    expect(report.estimatedGas).toBe("2400000");
    expect(Number(report.estimatedCostQor)).toBeGreaterThan(0);
  });

  it("falls back honestly to dry-run-simulated when RPC is unreachable", async () => {
    const failingFetch: typeof fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    const report = await deployPolicyRegistry({
      network: "testnet",
      evmRpcUrl: "http://127.0.0.1:1",
      dryRun: true,
      timeoutMs: 500,
      fetchImpl: failingFetch,
    });
    expect(report.mode).toBe("dry-run-simulated");
    expect(report.observedEvmChainId).toBeNull();
  });
});
