// SPDX-License-Identifier: Apache-2.0
//
// Live read-only probe against QoreChain Testnet (qorechain-diana, EVM 9800),
// verifying EVM RPC, consensus status, local ML-DSA-87, and on-chain PQC/AI precompiles.

import type { QoreNetworkName } from "../networks.js";
import { probeQoreXNetwork } from "../testnet-client.js";

async function main(): Promise<void> {
  const network = (process.env.QOREGUARD_NETWORK ?? "testnet") as QoreNetworkName;
  const offline = process.env.QOREGUARD_OFFLINE === "true";
  const report = await probeQoreXNetwork({
    network,
    evmRpcUrl: process.env.QOREGUARD_EVM_RPC_URL,
    rpcUrl: process.env.QOREGUARD_RPC_URL,
    offline,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`testnet-probe failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
