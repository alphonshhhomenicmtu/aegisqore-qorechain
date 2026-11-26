// SPDX-License-Identifier: Apache-2.0
//
// QoreGuard MCP Server (`qoreguard-mcp`): compatible with @qorechain/mcp
// conventions (structuredContent + JSON content + secret-refusal guard + stable
// error codes) exposing post-quantum AI agent guard tools over MCP.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { generateHybridAgentIdentity, toPublicIdentity } from "../crypto.js";
import { refuseSecretInputs, SecretInputError } from "../guard.js";
import { getQoreNetwork, type QoreNetworkName } from "../networks.js";
import {
  createSignedAgentEnvelope,
  QoreGuardPolicyEngine,
  verifyAuditBundle,
} from "../policy-engine.js";
import { probeQoreXNetwork } from "../testnet-client.js";
import type {
  AgentPolicy,
  HybridAgentIdentity,
  HybridSignedEnvelope,
  PqAlgorithm,
  QuantumAttackVector,
} from "../types.js";

export const MCP_SERVER_NAME = "qoreguard-mcp";
export const MCP_SERVER_VERSION = "1.0.0";

export const MCP_SERVER_INSTRUCTIONS =
  "QoreGuard Post-Quantum AI Agent Policy & Verification MCP Server for QoreChain / QoreX. " +
  "Verifies hybrid classical + ML-DSA-87 (FIPS-204) / SLH-DSA (FIPS-205) agent transactions, " +
  "enforces scoped spending caps, rolling velocity windows, target allowlists, monotonic nonces, " +
  "and anti-quantum-downgrade guards (qorechain-pqc-hybrid-v2), simulates quantum downgrade attacks, " +
  "and exports SHAKE-256 hash-chained & ML-DSA-87 attested audit bundles. " +
  "Never pass private keys or recovery phrases to any tool.";

const PQ_ALG_ENUM = z.enum(["ml-dsa-87", "ml-dsa-65", "ml-dsa-44", "slh-dsa-sha2-128f", "slh-dsa-sha2-128s"]);
const CLASSICAL_ALG_ENUM = z.enum(["secp256k1", "ed25519"]);
const NETWORK_ENUM = z.enum(["testnet", "mainnet", "localnet"]);
const ATTACK_VECTOR_ENUM = z.enum([
  "strip_pqc_to_classical_only",
  "downgrade_sign_bytes_v2_to_v1",
  "downgrade_algorithm_to_mldsa44",
  "tamper_commitment_amount",
  "tamper_pqc_signature_byte",
  "replay_consumed_nonce",
]);

const EnvelopeSchema = z.object({
  signatureTier: z.enum(["hybrid-pqc", "classical-only", "shake-only"]),
  signBytesVersion: z.enum(["v1", "v2"]),
  intent: z.object({
    agentId: z.string().min(1),
    policyHashHex: z.string().min(1),
    chainId: z.string().min(1),
    evmChainId: z.number().int().positive(),
    from: z.string().min(1),
    to: z.string().min(1),
    valueUqor: z.string().regex(/^\d+$/),
    calldataHex: z.string().default("0x"),
    nonce: z.number().int(),
    expiresAtUnix: z.number().int(),
    memo: z.string().optional(),
  }),
  commitmentHex: z.string().min(1),
  hybridSignBytesHex: z.string().min(1),
  classical: z.object({
    algorithm: CLASSICAL_ALG_ENUM,
    publicKeyHex: z.string().min(1),
    signatureHex: z.string().min(1),
  }),
  pqc: z
    .object({
      algorithm: PQ_ALG_ENUM,
      publicKeyHex: z.string().min(1),
      pubkeyHashHex: z.string().min(1),
      signatureHex: z.string().min(1),
    })
    .optional(),
});

const AiSignalSchema = z
  .object({
    riskScore: z.number().min(0),
    riskLevel: z.number().int().min(0),
    anomalyFlagged: z.boolean(),
    source: z.enum(["onchain-precompile", "local-heuristic"]),
  })
  .optional();

export interface QoreGuardMcpOptions {
  readonly defaultNetwork?: QoreNetworkName;
  readonly engine?: QoreGuardPolicyEngine;
  readonly attestationIdentity?: HybridAgentIdentity;
  readonly offlineProbe?: boolean;
}

export function createDefaultPolicy(
  network: QoreNetworkName = "testnet",
  registeredPqPubkeyHashHex?: string,
): AgentPolicy {
  const net = getQoreNetwork(network);
  return {
    policyId: `qoreguard-default-${network}`,
    agentId: "agent-treasury-01",
    network,
    chainId: net.chainId,
    evmChainId: net.evmChainId,
    requireHybridPqc: true,
    minPqAlgorithm: "ml-dsa-87",
    requiredSignBytesVersion: "v2",
    registeredPqPubkeyHashHex,
    maxSingleTxUqor: "5000000", // 5 QOR
    velocityWindows: [
      { label: "5m_burst", windowSec: 300, maxSpendUqor: "10000000", maxTxCount: 5 },
      { label: "24h_daily", windowSec: 86_400, maxSpendUqor: "50000000", maxTxCount: 50 },
    ],
    allowlistedTargets: [
      "0x000000000000000000000000000000000000dEaD",
      "0x1111111111111111111111111111111111111111",
    ],
    denylistedTargets: ["0x0000000000000000000000000000000000000000"],
    forbiddenSelectors: [
      "0x095ea7b3", // approve(address,uint256)
      "0xa22cb465", // setApprovalForAll(address,bool)
    ],
    maxAiRiskLevel: 2,
    requireStrictSequentialNonce: true,
  };
}

function okResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
  };
}

function errorResult(code: string, message: string, details?: unknown) {
  const errObj: Record<string, unknown> = { error: { code, message, ...(details ? { details } : {}) } };
  return {
    isError: true,
    content: [{ type: "text" as const, text: JSON.stringify(errObj, null, 2) }],
  };
}

async function safeToolCall(
  input: unknown,
  handler: () => Promise<Record<string, unknown>>,
) {
  try {
    refuseSecretInputs(input);
    const out = await handler();
    return okResult(out);
  } catch (err) {
    if (err instanceof SecretInputError) {
      return errorResult(err.code, err.message);
    }
    const msg = err instanceof Error ? err.message : String(err);
    return errorResult("INTERNAL_ERROR", msg);
  }
}

export interface QoreGuardMcpHandle {
  readonly server: McpServer;
  readonly getEngine: () => QoreGuardPolicyEngine;
  readonly demoIdentity: HybridAgentIdentity;
}

/**
 * Creates a configured QoreGuard MCP server exposing all post-quantum agent guard tools.
 */
export function createQoreGuardMcpServer(options: QoreGuardMcpOptions = {}): QoreGuardMcpHandle {
  const defaultNetwork = options.defaultNetwork ?? "testnet";
  const demoIdentity =
    options.attestationIdentity ?? generateHybridAgentIdentity("agent-treasury-01", { pqAlgorithm: "ml-dsa-87" });
  let activeEngine =
    options.engine ?? new QoreGuardPolicyEngine(createDefaultPolicy(defaultNetwork, demoIdentity.pqPubkeyHashHex));

  const server = new McpServer(
    {
      name: MCP_SERVER_NAME,
      title: "QoreGuard Post-Quantum Agent Guard",
      version: MCP_SERVER_VERSION,
    },
    {
      instructions: MCP_SERVER_INSTRUCTIONS,
    },
  );

  // 1. verify_pq_tx
  server.registerTool(
    "verify_pq_tx",
    {
      title: "Verify Post-Quantum Agent Transaction",
      description:
        "Verifies a hybrid classical + ML-DSA-87/SLH-DSA signed transaction envelope against the active QoreGuard policy (anti-quantum-downgrade, spending caps, velocity windows, allowlist, monotonic nonce) and optionally commits the authorized state to the tamper-evident audit ledger.",
      inputSchema: {
        envelope: EnvelopeSchema,
        commit: z.boolean().default(true).describe("If true, commits nonce/spend/audit state on ALLOW and records DENY attempts."),
        nowUnix: z.number().int().optional().describe("Optional evaluation timestamp in UNIX seconds."),
        aiSignal: AiSignalSchema,
      },
      annotations: {
        title: "Verify Post-Quantum Agent Transaction",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async (args) =>
      safeToolCall(args, async () => {
        const env = args.envelope as HybridSignedEnvelope;
        const decision = args.commit
          ? activeEngine.verifyAndCommit(env, { nowUnix: args.nowUnix, aiSignal: args.aiSignal })
          : activeEngine.quoteDecision(env, { nowUnix: args.nowUnix, aiSignal: args.aiSignal });
        return {
          ok: decision.verdict === "ALLOW",
          decision,
          lastConsumedNonce: activeEngine.getLastNonce(),
        };
      }),
  );

  // 2. quote_policy_decision
  server.registerTool(
    "quote_policy_decision",
    {
      title: "Quote Policy Decision (Dry-Run)",
      description:
        "Side-effect-free pre-flight evaluation of a hybrid post-quantum transaction envelope against active QoreGuard spending caps, rolling velocity windows, allowlist/selector firewall, and anti-downgrade rules.",
      inputSchema: {
        envelope: EnvelopeSchema,
        nowUnix: z.number().int().optional(),
        aiSignal: AiSignalSchema,
      },
      annotations: {
        title: "Quote Policy Decision",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (args) =>
      safeToolCall(args, async () => {
        const decision = activeEngine.quoteDecision(args.envelope as HybridSignedEnvelope, {
          nowUnix: args.nowUnix,
          aiSignal: args.aiSignal,
        });
        return {
          verdict: decision.verdict,
          decision,
          policyHashHex: activeEngine.policyHashHex,
          nextExpectedNonce: activeEngine.getLastNonce() + 1,
        };
      }),
  );

  // 3. simulate_quantum_downgrade_attack
  server.registerTool(
    "simulate_quantum_downgrade_attack",
    {
      title: "Simulate Quantum Downgrade & Tamper Attacks",
      description:
        "Runs deterministic adversarial simulations (strip PQC to classical-only, downgrade v2->v1 sign bytes, downgrade ML-DSA-87->ML-DSA-44, tamper commitment amount, flip signature bit, replay consumed nonce) in an isolated shadow engine to verify QoreGuard blocks every vector.",
      inputSchema: {
        vectors: z
          .array(ATTACK_VECTOR_ENUM)
          .min(1)
          .optional()
          .describe("Specific attack vectors to run. Omit to run all 6 vectors."),
        envelope: EnvelopeSchema.optional().describe("Optional valid envelope to mutate; if omitted, generates a fresh compliant ML-DSA-87 envelope."),
      },
      annotations: {
        title: "Simulate Quantum Downgrade Attacks",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (args) =>
      safeToolCall(args, async () => {
        const allVectors: QuantumAttackVector[] = [
          "strip_pqc_to_classical_only",
          "downgrade_sign_bytes_v2_to_v1",
          "downgrade_algorithm_to_mldsa44",
          "tamper_commitment_amount",
          "tamper_pqc_signature_byte",
          "replay_consumed_nonce",
        ];
        const chosen = (args.vectors as QuantumAttackVector[] | undefined) ?? allVectors;
        const baseEnvelope: HybridSignedEnvelope =
          (args.envelope as HybridSignedEnvelope | undefined) ??
          createSignedAgentEnvelope(activeEngine, demoIdentity, {
            to: activeEngine.policy.allowlistedTargets[0] ?? "0x000000000000000000000000000000000000dEaD",
            valueUqor: "100000",
            memo: "qoreguard-simulation-baseline",
          });

        const results = chosen.map((v) => activeEngine.simulateQuantumDowngradeAttack(baseEnvelope, v));
        const blockedCount = results.filter((r) => r.blocked).length;
        return {
          totalVectors: results.length,
          blockedCount,
          allBlocked: blockedCount === results.length,
          policyId: activeEngine.policy.policyId,
          results,
        };
      }),
  );

  // 4. export_audit_bundle
  server.registerTool(
    "export_audit_bundle",
    {
      title: "Export Tamper-Evident PQ Audit Bundle",
      description:
        "Exports the SHAKE-256 hash-chained audit ledger of all evaluated and blocked agent transactions, optionally attested with an ML-DSA-87 post-quantum signature, and includes an independent integrity verification check.",
      inputSchema: {
        attest: z.boolean().default(true).describe("Sign the exported audit bundle head with ML-DSA-87."),
      },
      annotations: {
        title: "Export Audit Bundle",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (args) =>
      safeToolCall(args, async () => {
        const bundle = activeEngine.exportAuditBundle(args.attest ? demoIdentity : undefined);
        const verification = verifyAuditBundle(bundle);
        return {
          bundle,
          verification,
        };
      }),
  );

  // 5. probe_qorex_network
  server.registerTool(
    "probe_qorex_network",
    {
      title: "Probe QoreX / QoreChain Network & PQC Precompiles",
      description:
        "Read-only probe of QoreChain testnet (qorechain-diana, EVM 9800) or mainnet (qorechain-vladi, EVM 9801), checking EVM RPC, consensus status, and live PQC/AI precompiles (0x...0A01, 0x...0A02, 0x...0B01, 0x...0C01) with honest offline fallback.",
      inputSchema: {
        network: NETWORK_ENUM.optional(),
        offline: z.boolean().optional(),
      },
      annotations: {
        title: "Probe QoreX Network",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (args) =>
      safeToolCall(args, async () => {
        const report = await probeQoreXNetwork({
          network: (args.network as QoreNetworkName | undefined) ?? defaultNetwork,
          offline: args.offline ?? options.offlineProbe ?? false,
        });
        return report as unknown as Record<string, unknown>;
      }),
  );

  // 6. register_agent_policy
  server.registerTool(
    "register_agent_policy",
    {
      title: "Register Scoped Post-Quantum Agent Policy",
      description:
        "Replaces the active QoreGuard policy with a new scoped post-quantum policy (spending caps, velocity windows, allowlisted targets, minimum PQ algorithm) and returns its deterministic SHAKE-256 policyHashHex and public demo identity metadata.",
      inputSchema: {
        policyId: z.string().min(1),
        agentId: z.string().min(1),
        network: NETWORK_ENUM.default(defaultNetwork),
        minPqAlgorithm: PQ_ALG_ENUM.default("ml-dsa-87"),
        maxSingleTxUqor: z.string().regex(/^\d+$/),
        allowlistedTargets: z.array(z.string().min(1)).default([]),
        denylistedTargets: z.array(z.string().min(1)).default([]),
        registeredPqPubkeyHashHex: z.string().optional(),
        requireStrictSequentialNonce: z.boolean().default(true),
      },
      annotations: {
        title: "Register Agent Policy",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async (args) =>
      safeToolCall(args, async () => {
        const net = getQoreNetwork(args.network as QoreNetworkName);
        const policy: AgentPolicy = {
          policyId: args.policyId,
          agentId: args.agentId,
          network: net.name,
          chainId: net.chainId,
          evmChainId: net.evmChainId,
          requireHybridPqc: true,
          minPqAlgorithm: args.minPqAlgorithm as PqAlgorithm,
          requiredSignBytesVersion: net.signBytesVersion,
          registeredPqPubkeyHashHex: args.registeredPqPubkeyHashHex,
          maxSingleTxUqor: args.maxSingleTxUqor,
          velocityWindows: [
            { label: "5m_burst", windowSec: 300, maxSpendUqor: (BigInt(args.maxSingleTxUqor) * 3n).toString(), maxTxCount: 5 },
          ],
          allowlistedTargets: args.allowlistedTargets,
          denylistedTargets: args.denylistedTargets,
          forbiddenSelectors: ["0x095ea7b3", "0xa22cb465"],
          maxAiRiskLevel: 2,
          requireStrictSequentialNonce: args.requireStrictSequentialNonce,
        };
        activeEngine = new QoreGuardPolicyEngine(policy);
        return {
          policyId: policy.policyId,
          policyHashHex: activeEngine.policyHashHex,
          network: net.name,
          chainId: net.chainId,
          evmChainId: net.evmChainId,
          attestationIdentity: toPublicIdentity(demoIdentity),
        };
      }),
  );

  return {
    server,
    getEngine: () => activeEngine,
    demoIdentity,
  };
}
