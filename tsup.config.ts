import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "mcp/server": "src/mcp/server.ts",
    "mcp/bin": "src/mcp/bin.ts",
    "scripts/testnet-probe": "src/scripts/testnet-probe.ts",
    "scripts/turnkey-tx": "src/scripts/turnkey-tx.ts",
  },
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "node20",
  splitting: false,
});
