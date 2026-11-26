// SPDX-License-Identifier: Apache-2.0

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import { refuseSecretInputs, SecretInputError } from "../src/guard.js";
import { createQoreGuardMcpServer } from "../src/mcp/server.js";
import { createSignedAgentEnvelope } from "../src/policy-engine.js";

describe("qoreguard-mcp Server (InMemory MCP Client/Server Round-Trip)", () => {
  let client: Client | null = null;

  afterEach(async () => {
    if (client) {
      await client.close();
      client = null;
    }
  });

  async function connectMcp() {
    const handle = createQoreGuardMcpServer({ defaultNetwork: "testnet", offlineProbe: true });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await handle.server.connect(serverTransport);
    client = new Client({ name: "qoreguard-test-client", version: "1.0.0" });
    await client.connect(clientTransport);
    return { client, handle };
  }

  it("registers all 6 QoreGuard MCP tools cleanly", async () => {
    const { client: c } = await connectMcp();
    const { tools } = await c.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "export_audit_bundle",
      "probe_qorex_network",
      "quote_policy_decision",
      "register_agent_policy",
      "simulate_quantum_downgrade_attack",
      "verify_pq_tx",
    ]);
  });

  it("quotes, verifies/commits a hybrid ML-DSA-87 tx, and rejects replay via MCP tools", async () => {
    const { client: c, handle } = await connectMcp();
    const env = createSignedAgentEnvelope(handle.getEngine(), handle.demoIdentity, {
      to: "0x000000000000000000000000000000000000dEaD",
      valueUqor: "500000",
    });

    const qRes = await c.callTool({ name: "quote_policy_decision", arguments: { envelope: env } });
    expect(qRes.isError).toBeFalsy();
    const qBody = qRes.structuredContent as { verdict: string; nextExpectedNonce: number };
    expect(qBody.verdict).toBe("ALLOW");
    expect(qBody.nextExpectedNonce).toBe(1);

    const vRes = await c.callTool({ name: "verify_pq_tx", arguments: { envelope: env, commit: true } });
    expect(vRes.isError).toBeFalsy();
    const vBody = vRes.structuredContent as { ok: boolean; lastConsumedNonce: number };
    expect(vBody.ok).toBe(true);
    expect(vBody.lastConsumedNonce).toBe(1);

    // Replay same envelope -> blocked with NONCE_REPLAY
    const replayRes = await c.callTool({ name: "verify_pq_tx", arguments: { envelope: env, commit: true } });
    const replayBody = replayRes.structuredContent as {
      ok: boolean;
      decision: { rejectionCodes: string[] };
    };
    expect(replayBody.ok).toBe(false);
    expect(replayBody.decision.rejectionCodes).toContain("NONCE_REPLAY");
  });

  it("runs simulate_quantum_downgrade_attack across all 6 vectors via MCP", async () => {
    const { client: c } = await connectMcp();
    const res = await c.callTool({ name: "simulate_quantum_downgrade_attack", arguments: {} });
    expect(res.isError).toBeFalsy();
    const body = res.structuredContent as { totalVectors: number; blockedCount: number; allBlocked: boolean };
    expect(body.totalVectors).toBe(6);
    expect(body.blockedCount).toBe(6);
    expect(body.allBlocked).toBe(true);
  });

  it("exports an attested SHAKE-256 + ML-DSA-87 audit bundle via MCP", async () => {
    const { client: c, handle } = await connectMcp();
    const env = createSignedAgentEnvelope(handle.getEngine(), handle.demoIdentity, {
      to: "0x000000000000000000000000000000000000dEaD",
      valueUqor: "123456",
    });
    await c.callTool({ name: "verify_pq_tx", arguments: { envelope: env, commit: true } });

    const expRes = await c.callTool({ name: "export_audit_bundle", arguments: { attest: true } });
    expect(expRes.isError).toBeFalsy();
    const body = expRes.structuredContent as {
      bundle: { entryCount: number; allowedCount: number };
      verification: { valid: boolean; chainIntact: boolean; attestationValid: boolean };
    };
    expect(body.bundle.entryCount).toBe(1);
    expect(body.bundle.allowedCount).toBe(1);
    expect(body.verification.valid).toBe(true);
    expect(body.verification.chainIntact).toBe(true);
    expect(body.verification.attestationValid).toBe(true);
  });

  it("probes QoreX network (offline deterministic mode) and registers a new agent policy via MCP", async () => {
    const { client: c } = await connectMcp();

    const probe = await c.callTool({ name: "probe_qorex_network", arguments: { network: "testnet", offline: true } });
    expect(probe.isError).toBeFalsy();
    const pBody = probe.structuredContent as {
      mode: string;
      chainId: string;
      expectedEvmChainId: number;
      localMlDsa87SelfTest: { valid: boolean; pubkeyBytes: number; signatureBytes: number };
    };
    expect(pBody.mode).toBe("simulated");
    expect(pBody.chainId).toBe("qorechain-diana");
    expect(pBody.expectedEvmChainId).toBe(9800);
    expect(pBody.localMlDsa87SelfTest.valid).toBe(true);
    expect(pBody.localMlDsa87SelfTest.pubkeyBytes).toBe(2592);
    expect(pBody.localMlDsa87SelfTest.signatureBytes).toBe(4627);

    const reg = await c.callTool({
      name: "register_agent_policy",
      arguments: {
        policyId: "custom-policy-v2",
        agentId: "agent-alpha",
        network: "testnet",
        minPqAlgorithm: "ml-dsa-87",
        maxSingleTxUqor: "2000000",
        allowlistedTargets: ["0x000000000000000000000000000000000000dEaD"],
      },
    });
    expect(reg.isError).toBeFalsy();
    const rBody = reg.structuredContent as { policyId: string; policyHashHex: string; evmChainId: number };
    expect(rBody.policyId).toBe("custom-policy-v2");
    expect(rBody.policyHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(rBody.evmChainId).toBe(9800);
  });

  it("refuses secret keys and BIP-39 recovery phrases in MCP tool inputs", async () => {
    expect(() => refuseSecretInputs({ privateKey: "0xdeadbeef" })).toThrow(SecretInputError);
    expect(() =>
      refuseSecretInputs({
        memo: "abandon ability able about above absent absorb abstract absurd abuse access accident",
      }),
    ).toThrow(SecretInputError);

    const { client: c, handle } = await connectMcp();
    const env = createSignedAgentEnvelope(handle.getEngine(), handle.demoIdentity, {
      to: "0x000000000000000000000000000000000000dEaD",
      valueUqor: "1000",
      memo: "abandon ability able about above absent absorb abstract absurd abuse access accident",
    });
    const res = await c.callTool({ name: "quote_policy_decision", arguments: { envelope: env } });
    expect(res.isError).toBe(true);
    const txt = (res.content as Array<{ text: string }>)[0]?.text ?? "";
    expect(txt).toContain("SECRET_INPUT_REFUSED");
  });
});
