#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// CLI entry point for qoreguard-mcp (stdio MCP transport).

import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { QoreNetworkName } from "../networks.js";
import { createQoreGuardMcpServer, MCP_SERVER_NAME, MCP_SERVER_VERSION } from "./server.js";

const HELP = `${MCP_SERVER_NAME} ${MCP_SERVER_VERSION}: Post-Quantum AI Agent Guard MCP server for QoreChain / QoreX

Usage:
  qoreguard-mcp [--network testnet|mainnet|localnet] [--offline]
  qoreguard-mcp --help | --version
`;

async function main(): Promise<void> {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      network: { type: "string" },
      offline: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
    strict: true,
    allowPositionals: false,
  });

  if (values.help) {
    process.stdout.write(HELP);
    return;
  }
  if (values.version) {
    process.stdout.write(`${MCP_SERVER_VERSION}\n`);
    return;
  }

  const net = (values.network ?? "testnet") as QoreNetworkName;
  if (!["testnet", "mainnet", "localnet"].includes(net)) {
    process.stderr.write(`qoreguard-mcp: invalid --network "${net}"\n`);
    process.exit(2);
  }

  const { server } = createQoreGuardMcpServer({
    defaultNetwork: net,
    offlineProbe: values.offline,
  });
  await server.connect(new StdioServerTransport());
}

main().catch((err: unknown) => {
  process.stderr.write(`qoreguard-mcp: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
