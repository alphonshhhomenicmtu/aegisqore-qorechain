// SPDX-License-Identifier: Apache-2.0
//
// Turnkey env-var-driven QoreGuard transaction script (zero hardcoded keys).
// Defaults to dry-run simulation unless QOREGUARD_DRY_RUN=false and
// QOREGUARD_PRIVATE_KEY are explicitly set in the operator's local environment.

import type { Address, Hex } from "viem";
import { generateHybridAgentIdentity } from "../crypto.js";
import { createDefaultPolicy } from "../mcp/server.js";
import type { QoreNetworkName } from "../networks.js";
import { createSignedAgentEnvelope, QoreGuardPolicyEngine, verifyAuditBundle } from "../policy-engine.js";
import { executeTurnkeyGuardedTx, fetchAiPreflightSignal } from "../testnet-client.js";

async function main(): Promise<void> {
  const network = (process.env.QOREGUARD_NETWORK ?? "testnet") as QoreNetworkName;
  const to = (process.env.QOREGUARD_TO ?? "0x000000000000000000000000000000000000dEaD") as Address;
  const valueUqor = process.env.QOREGUARD_VALUE_UQOR ?? "100000";
  const dryRun = process.env.QOREGUARD_DRY_RUN !== "false";
  const offline = process.env.QOREGUARD_OFFLINE === "true";

  // Fresh ephemeral ML-DSA-87 + secp256k1 agent session identity (never prints private keys)
  const identity = generateHybridAgentIdentity("agent-treasury-01", { pqAlgorithm: "ml-dsa-87" });
  const basePolicy = createDefaultPolicy(network, identity.pqPubkeyHashHex);
  const policy = {
    ...basePolicy,
    allowlistedTargets: Array.from(new Set([...basePolicy.allowlistedTargets, to])),
  };
  const engine = new QoreGuardPolicyEngine(policy);

  const envelope = createSignedAgentEnvelope(engine, identity, {
    to,
    valueUqor,
    calldataHex: "0x",
    memo: "qoreguard-turnkey-transfer",
  });

  const aiSignal = await fetchAiPreflightSignal({
    network,
    evmRpcUrl: process.env.QOREGUARD_EVM_RPC_URL,
    sender: identity.evmAddress as Address,
    valueUqor: BigInt(valueUqor),
    calldataHex: "0x" as Hex,
    offline,
  });

  const result = await executeTurnkeyGuardedTx({
    engine,
    envelope,
    privateKeyHex: process.env.QOREGUARD_PRIVATE_KEY,
    evmRpcUrl: process.env.QOREGUARD_EVM_RPC_URL,
    dryRun,
    aiSignal,
  });

  const bundle = engine.exportAuditBundle(identity);
  const bundleCheck = verifyAuditBundle(bundle);

  process.stdout.write(
    `${JSON.stringify(
      {
        mode: result.mode,
        network: result.network,
        txHash: result.txHash ?? null,
        explorerUrl: result.explorerUrl ?? null,
        note: result.note,
        decision: {
          decisionId: result.decision.decisionId,
          verdict: result.decision.verdict,
          pqAlgorithm: result.decision.pqAlgorithm,
          signBytesVersion: result.decision.signBytesVersion,
          commitmentHex: result.decision.crypto.computedCommitmentHex,
        },
        aiSignal,
        auditBundleIntegrity: bundleCheck,
      },
      null,
      2,
    )}\n`,
  );
}

main().catch((err: unknown) => {
  process.stderr.write(`turnkey-tx failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
