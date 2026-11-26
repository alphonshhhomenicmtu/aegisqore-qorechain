# QoreGuard — Post-Quantum AI Agent Policy Engine, MCP Server & Interactive Console for QoreChain / QoreX

**QoreGuard** is a unified, Apache-2.0 post-quantum security stack for autonomous AI agents operating on **QoreChain / QoreX** (`qorechain-diana`, EVM Chain ID `9800`). It pairs real NIST post-quantum cryptography (`@qorechain/pqc` FIPS-204 **ML-DSA-87 / ML-DSA-65**, FIPS-205 **SLH-DSA**, FIPS-202 **SHAKE-256**), a stateful policy & anti-quantum-downgrade engine, a 6-tool **Model Context Protocol** server (`qoreguard-mcp`), live QoreX Testnet precompile verification, and an interactive web console (`web/`).

- **Live GitHub Pages Demo**: [https://alphonshhhomenicmtu.github.io/qoreguard-qorechain/](https://alphonshhhomenicmtu.github.io/qoreguard-qorechain/)
- **1080p Demo Video (YouTube, 108s)**: [https://www.youtube.com/watch?v=La_8Dh7TA04](https://www.youtube.com/watch?v=La_8Dh7TA04)
- **1080p Demo Video Mirror (Google Drive)**: [https://drive.google.com/file/d/1luPFpSazP9o20nE1wC738ppocV_4eZUo/view?usp=sharing](https://drive.google.com/file/d/1luPFpSazP9o20nE1wC738ppocV_4eZUo/view?usp=sharing)
- **Public Repository**: [https://github.com/alphonshhhomenicmtu/qoreguard-qorechain](https://github.com/alphonshhhomenicmtu/qoreguard-qorechain)
- **AI Transparency**: See [AI_USAGE.md](AI_USAGE.md) (Best AI-Native Build submission) and [SUBMISSION_READY.md](SUBMISSION_READY.md).

---

## Live QoreX Testnet Verification Proof

Running `npm run probe:testnet` executes a real read-only probe against **QoreChain Testnet (`qorechain-diana`, EVM Chain ID `9800`)**, generating a fresh FIPS-204 **ML-DSA-87** keypair (`2,592`-byte public key, `4,627`-byte signature) via `@qorechain/pqc` and verifying it **both locally and on-chain** via QoreChain's live EVM precompile `IQorePQC.pqcVerify` (`0x0000000000000000000000000000000000000A01`):

- **Network**: `qorechain-diana` (`EVM Chain ID: 9800`, live verified block `10,801,339`, consensus height `10,801,340`)
- **`IQorePQC.pqcVerify` (`0x...0A01`)**: `available: true`, **`verified: true`** (`on-chain ML-DSA-87 verify=true`)
- **`IQorePQC.pqcKeyStatus` (`0x...0A02`)**: `available: true`
- **`IQoreConsensus.rlConsensusParams` (`0x...0C01`)**: `available: true` (`blockTime=5000, baseGasPrice=100, validators=4, epoch=1`)
- **Automated Test Suites**: **37 / 37 PASS** (`30/30` core Vitest including InMemory MCP client/server round-trip + `7/7` web Vitest)

---

## Visual Walkthrough

| Live Telemetry & Hybrid PQC Overview | Post-Quantum Policy Console & Adversarial Breaker Lab |
|---|---|
| ![Hero Telemetry](docs/screenshots/01-hero-telemetry.png) | ![Policy Console](docs/screenshots/03-policy-console.png) |
| ![PQC Comparison](docs/screenshots/02-pqc-comparison.png) | ![Adversarial Lab](docs/screenshots/04-adversarial-lab.png) |

---

## Monorepo Architecture

```text
qoreguard/
├── src/
│   ├── networks.ts              # Verified QoreChain testnet/mainnet/localnet presets, precompile ABIs (0x...0901-0C01), prefix-free domain strings
│   ├── types.ts                 # Strict TypeScript contracts for policies, hybrid envelopes, decisions, and audit bundles
│   ├── crypto.ts                # FIPS-204 ML-DSA-87/65/44 (@qorechain/pqc) + FIPS-205 SLH-DSA + secp256k1/ed25519 + hybridSignBytes('v2')
│   ├── policy-engine.ts         # Stateful spending caps, sliding velocity windows, allowlist/selector firewall, anti-replay, 6-vector attack simulator, SHAKE-256 + ML-DSA-87 audit ledger
│   ├── guard.ts                 # Secret-input refusal guard (blocks private keys / BIP-39 mnemonics in MCP tool calls)
│   ├── testnet-client.ts        # Live QoreX read-only RPC/precompile probe + env-var-driven turnkey guarded tx runner (honest simulation fallback)
│   ├── mcp/
│   │   ├── server.ts            # 6-tool qoreguard-mcp server aligned with @qorechain/mcp conventions
│   │   └── bin.ts               # Stdio CLI entry point for MCP clients
│   └── scripts/
│       ├── testnet-probe.ts     # `npm run probe:testnet` live QoreX read-only probe
│       └── turnkey-tx.ts        # `npm run tx:turnkey` env-var-driven guarded tx / dry-run demo
├── test/                        # 30 Vitest tests (crypto, policy-engine, MCP InMemory round-trip, testnet-client)
├── web/                         # Interactive React 19 + Vite 6 + TypeScript console deployed to GitHub Pages (7 Vitest tests)
├── docs/screenshots/            # Captured high-resolution UI screenshots
├── AI_USAGE.md                  # AI-assisted engineering disclosure (Best AI-Native Build)
└── SUBMISSION_READY.md          # Complete QoreChain Developer Fest submission checklist & evidence
```

---

## MCP Tools (`qoreguard-mcp`)

Aligned with `@qorechain/mcp` (`structuredContent` + JSON content + secret-input refusal):

| Tool | Purpose |
|---|---|
| `verify_pq_tx` | Verifies hybrid classical + ML-DSA-87/SLH-DSA envelopes against active policy and commits nonce/spend/audit state on `ALLOW`. |
| `quote_policy_decision` | Side-effect-free pre-flight quote returning `ALLOW`/`DENY`, remaining caps, velocity snapshot, and rejection codes. |
| `simulate_quantum_downgrade_attack` | Runs 6 deterministic adversarial vectors in an isolated shadow engine (strip PQC, v2→v1 sign-bytes downgrade, ML-DSA-87→44 downgrade, commitment amount tamper, signature bit-flip, nonce replay). |
| `export_audit_bundle` | Exports the SHAKE-256 hash-chained & ML-DSA-87 attested audit bundle with independent `verifyAuditBundle` confirmation. |
| `probe_qorex_network` | Live read-only probe of QoreChain Testnet/Mainnet RPC, consensus status, and PQC/AI/Consensus EVM precompiles. |
| `register_agent_policy` | Registers a scoped PQ agent policy and returns its deterministic SHAKE-256 `policyHashHex`. |

---

## Quickstart & Reproducibility

### Core SDK, Policy Engine & MCP Server (`30 / 30` Vitest PASS)

```bash
npm install
npm run typecheck
npm run build
npm test
```

### Live QoreX Testnet Probe & Turnkey Guarded Tx Runner

```bash
# Live read-only probe against qorechain-diana (EVM 9800) + on-chain IQorePQC.pqcVerify (0x...0A01)
npm run probe:testnet

# Offline deterministic simulation fallback
QOREGUARD_OFFLINE=true npm run probe:testnet

# Turnkey guarded tx dry-run (zero hardcoded keys; set QOREGUARD_PRIVATE_KEY + QOREGUARD_DRY_RUN=false for live broadcast)
npm run tx:turnkey

# Start MCP stdio server
node dist/mcp/bin.js --network testnet
```

### Interactive Web Console (`7 / 7` Vitest PASS)

```bash
cd web
npm install
npm run typecheck
npm test
npm run build
```

---

## Credits & Open-Source Libraries

QoreGuard builds directly on the official QoreChain developer ecosystem and audited open-source cryptography libraries:
- [`@qorechain/pqc`](https://github.com/qorechain/qorechain-pqc), [`qorechain-sdk`](https://github.com/qorechain/qorechain-sdk), and [`qorechain-mcp`](https://github.com/qorechain/qorechain-mcp) (QoreChain Association)
- `@noble/post-quantum`, `@noble/curves`, `@noble/hashes` (Paul Miller)
- `@modelcontextprotocol/sdk`, `viem`, `zod`, `React`, `Vite`, `Vitest`, `tsup`

## License

Apache-2.0 (see [LICENSE](LICENSE)).
