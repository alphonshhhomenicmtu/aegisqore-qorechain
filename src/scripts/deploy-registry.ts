// SPDX-License-Identifier: Apache-2.0
//
// Turnkey QoreGuardPolicyRegistry deployment & live EVM 9800 gas-estimation CLI.
// Uses QOREX_PRIVATE_KEY from environment only (never hardcoded, never logged).
//
// Usage:
//   node dist/scripts/deploy-registry.js --dry-run
//   QOREX_PRIVATE_KEY=0x... node dist/scripts/deploy-registry.js --broadcast

import { parseArgs } from "node:util";
import type { QoreNetworkName } from "../networks.js";
import { deployPolicyRegistry } from "../registry-deployer.js";

async function main(): Promise<void> {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      "dry-run": { type: "boolean", default: true },
      broadcast: { type: "boolean", default: false },
      network: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
    },
    strict: true,
    allowPositionals: false,
  });

  if (values.help) {
    process.stdout.write(
      "Usage: deploy-registry [--dry-run | --broadcast] [--network testnet|mainnet|localnet]\n" +
        "  --dry-run    Estimate deployment gas against live QoreX EVM (default; no key needed)\n" +
        "  --broadcast  Deploy QoreGuardPolicyRegistry using env QOREX_PRIVATE_KEY\n",
    );
    return;
  }

  const network = (values.network ?? process.env.QOREGUARD_NETWORK ?? "testnet") as QoreNetworkName;
  const dryRun = values.broadcast ? false : values["dry-run"];

  const report = await deployPolicyRegistry({
    network,
    evmRpcUrl: process.env.QOREGUARD_EVM_RPC_URL,
    dryRun,
    privateKeyHex: process.env.QOREX_PRIVATE_KEY,
  });

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`deploy-registry failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
