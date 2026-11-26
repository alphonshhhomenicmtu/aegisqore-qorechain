# AI Usage Disclosure — QoreGuard (Best AI-Native Build)

This document transparently discloses how AI tools and agents were used to design, build, test, and verify **QoreGuard** for the QoreChain Developer Fest.

## 1. AI-Native Architecture & Product Purpose

QoreGuard itself is an **AI-native security primitive**: its Model Context Protocol server (`qoreguard-mcp`) lets LLM coding and treasury agents inspect policies, quote spending/velocity impact, verify hybrid `ML-DSA-87 + secp256k1/ed25519` envelopes, run adversarial quantum-downgrade simulations, probe live QoreChain precompiles, and export ML-DSA-87 attested SHAKE-256 audit bundles—while refusing any private key or seed phrase accidentally passed into tool inputs.

## 2. How AI Was Used During Development

- **Upstream Ecosystem Grounding**: AI agents inspected the live public QoreChain repositories (`qorechain-sdk`, `qorechain-pqc`, and `qorechain-mcp`) to verify exact npm package versions (`@qorechain/pqc@0.2.3`), `qorechain-diana` / `qorechain-vladi` endpoints, EIP-155 chain IDs (`9800` / `9801`), EVM precompile addresses (`0x...0A01`–`0x...0C01`), and the reserved prefix-free domain separation table in `qorechain-pqc/DESIGN.md`.
- **Parallel Implementation**:
  - Core hybrid PQC cryptography, stateful policy engine, MCP server, and live QoreX testnet probe/turnkey scripts were implemented in strict TypeScript.
  - The interactive React/Vite console (`web/`), adversarial breaker lab, screenshots, and 108-second 1080p narrated demo video were developed in parallel and unified into this single monorepo.
- **Adversarial Test Generation**: AI generated comprehensive unit, integration, and adversarial breaker tests covering real FIPS-204 ML-DSA-87 / FIPS-205 SLH-DSA cryptography, rolling velocity windows, calldata selector filtering, replay attacks, MCP `InMemoryTransport` client/server round-trips, and secret-input refusal.

## 3. Independent Verification & Ground Truth Checks

Every AI-generated component was independently verified with deterministic tooling before publication:
- **TypeScript strict checks**: `npm run typecheck` passed with `0` errors in both root and `web/`.
- **Production builds**: `npm run build` (`tsup` ESM + `.d.ts` at root; `tsc -b && vite build` in `web/`) succeeded cleanly.
- **Automated tests**: `30/30` core Vitest tests + `7/7` web Vitest tests = **`37/37` PASS** (no mocked cryptography; real `@qorechain/pqc` and `@noble/post-quantum` sign/verify).
- **Live QoreX Testnet verification**: `npm run probe:testnet` verified a freshly signed ML-DSA-87 signature against live on-chain `IQorePQC.pqcVerify` (`0x...0A01`) on `qorechain-diana` (EVM `9800`), returning `verified: true`.
- **Security hygiene**: Verified zero hardcoded keys, zero `.env` or `.mp4` leaks, and secret-refusal unit tests on MCP inputs.
