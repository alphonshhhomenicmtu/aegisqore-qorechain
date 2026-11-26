# QoreGuard — QoreChain Developer Fest Submission Ready Package

## 1. Project Metadata & Live Links

- **Project Name**: QoreGuard — Post-Quantum AI Agent Policy Engine, MCP Server & Interactive Console
- **Primary Track**: **Post-Quantum AI Agents** ($1,500 1st / $750 2nd)
- **Special Award Opt-In**: **Best AI-Native Build** ($500 — see [AI_USAGE.md](AI_USAGE.md)) + **Top-Quality Floor** (7 × $250, ≥70/100)
- **License**: Apache-2.0 ([LICENSE](LICENSE))
- **Target Network**: QoreChain Testnet `qorechain-diana` (EVM Chain ID `9800`)
- **Public GitHub Repository**: https://github.com/alphonshhhomenicmtu/qoreguard-qorechain
- **Live GitHub Pages Demo**: https://alphonshhhomenicmtu.github.io/qoreguard-qorechain/
- **Featured Cover Image (`1200×630`)**: [docs/cover-image.png](docs/cover-image.png)
- **1080p Demo Video (YouTube, 108s < 3 min)**: https://www.youtube.com/watch?v=La_8Dh7TA04
- **1080p Demo Video Mirror (Google Drive)**: https://drive.google.com/file/d/1luPFpSazP9o20nE1wC738ppocV_4eZUo/view?usp=sharing

---

## 2. Live QoreX Testnet & Cryptographic Verification Evidence

- **Live On-Chain PQC Precompile Proof (`npm run probe:testnet`)**:
  - Network: `qorechain-diana`, EVM Chain ID `9800`, observed live EVM block `10,801,339` / consensus block `10,801,340`.
  - Real `@qorechain/pqc` FIPS-204 **ML-DSA-87** signature (`2,592`-byte public key, `4,627`-byte signature) verified **on-chain** via `IQorePQC.pqcVerify` (`0x0000000000000000000000000000000000000A01`) returning **`verified: true`**.
  - Live `IQorePQC.pqcKeyStatus` (`0x...0A02`) and `IQoreConsensus.rlConsensusParams` (`0x...0C01`) confirmed reachable on testnet.
- **Turnkey Guarded Transaction Runner (`npm run tx:turnkey`)**:
  - Environment-variable driven (`QOREGUARD_PRIVATE_KEY`, `QOREGUARD_DRY_RUN`, `QOREGUARD_TO`, `QOREGUARD_VALUE_UQOR`), zero hardcoded keys, enforcing the hybrid ML-DSA-87 policy engine prior to broadcast with honest `simulated-dry-run` fallback and ML-DSA-87 attested SHAKE-256 audit bundles.
- **On-Chain QoreX EVM 9800 Smart Contract (`contracts/QoreGuardPolicyRegistry.sol`)**:
  - Direct Solidity integration with QoreChain native precompiles `IQorePQCVerify` (`0x...0A01`), `IQorePQCKeyStatus` (`0x...0A02`), `IQoreAIRiskScore` (`0x...0B01`), and `IQoreAIAnomalyCheck` (`0x...0B02`).
  - **30-Day Owner-to-Agent Link TTL (`MAX_LINK_TTL = 30 days`)**: Enforces mandatory renewal/re-linking at least every 30 days (`linkExpiresAt`, `renewAgentLink()`, `relinkAgentKey()`, `REASON_AGENT_LINK_EXPIRED`).
  - **On-Chain Scoped EVM Windows (`openScopedEvmWindow`)**: Enforces `[startBlock, endBlock]`, `maxTxCount`, `maxTotalValue`, and window-scoped `allowedTargets` (`REASON_SCOPED_BLOCK_OUT_OF_RANGE`, `REASON_SCOPED_TX_COUNT_EXCEEDED`, `REASON_SCOPED_VALUE_CAP_EXCEEDED`).
  - **Official Authenticated Messaging (`qorechain-msg-v1|<chainId>|<data>`)**: Prefix-free framing (`formatAuthenticatedMessage`) + hybrid `secp256k1` (`ecrecover` with EIP-2 low-S check) + `ML-DSA-87` (`0x...0A01`) verification (`verifyAuthenticatedMessage`, `verifyAgentAuthenticatedMessage`) mirrored byte-for-byte in `src/crypto.ts` (`signAuthenticatedMessage`, `verifyAuthenticatedMessage`).
  - Per-agent ML-DSA-87 pubkey hash, single-tx spend cap, O(1) two-epoch sliding-window daily cap, target/selector allowlist & default forbidden `approve`/`setApprovalForAll` firewall, strict monotonic anti-replay nonce, emergency owner revocation, and `PolicyApproved` / `PolicyRejected` / `AgentRevoked` commitment events.
  - **Foundry Suite (`contracts/test/QoreGuardPolicyRegistry.t.sol`)**: **`18 / 18` PASS** (using `vm.etch` precompile mocks + 256-run spend-cap fuzzing + 30d TTL/renewal + Scoped EVM Window + `qorechain-msg-v1` tests).
  - **Slither Static Analysis (`0.11.6`, 102 detectors)**: **`0 High / 0 Medium / 0 Optimization`**.
  - **Live QoreX EVM 9800 Dry-Run Deployment Gas Estimate (`npm run deploy:registry -- --dry-run`)**: **`3,480,337` gas** (`0.3915379125 QOR` at `112.5 gwei`, live block `10,802,524`, `15,896`-byte Solc `0.8.28` `paris` bytecode, SHA-256 `7c304cb19182a0168484b348a6e968912d3863bae10fc6b56a7c5c7787c2cdce`).
- **Automated Verification (`62 / 62` PASS)**:
  - On-Chain Contract (Foundry): `forge test -vv` → **18 / 18 PASS** + Slither **0 High / 0 Medium**.
  - Core SDK + Policy Engine + MCP Server + Registry Deployer: `npm run typecheck`, `npm run build`, `npm test` → **36 / 36 Vitest PASS**.
  - Interactive Web Console (`web/`): `npm run typecheck`, `npm test`, `npm run build` → **8 / 8 Vitest PASS**, deployed live to GitHub Pages (`0` console errors, `0` page errors).

---

## 3. 1:1 Mapping to Post-Quantum AI Agents Track Requirements

| Official Track Requirement | QoreGuard Implementation (On-Chain Solidity + Core SDK + MCP + Web Console) |
|---|---|
| **Scoped EVM Window (`startBlock`, `endBlock`, `maxTxCount`, `maxTotalValue`, `allowedTargets`)** | Enforced both on-chain (`openScopedEvmWindow`, `closeScopedEvmWindow` in `QoreGuardPolicyRegistry.sol`) and in `QoreGuardPolicyEngine.openScopedEvmWindow()`, reverting cleanly on out-of-window blocks (`SCOPED_BLOCK_OUT_OF_RANGE`), tx count breaches (`SCOPED_TX_COUNT_EXCEEDED`), value breaches (`SCOPED_TOTAL_VALUE_EXCEEDED`), or non-window targets. |
| **Transaction, Value, Duration & Target Limits** | `maxSingleTxAmount` / `maxSingleTxUqor`, O(1) two-epoch sliding daily cap + rolling `velocityWindows` (`maxSpendUqor`, `maxTxCount`), strict `allowedTargets` / `denylistedTargets`, and 4-byte EVM calldata selector firewall blocking `approve` (`0x095ea7b3`) and `setApprovalForAll` (`0xa22cb465`). |
| **Smart-Account Spending Rules & 30-Day Owner Link Lease** | Owner's offline authority binds `pqPubkeyHash` and enforces `MAX_LINK_TTL = 30 days` (`MAX_AGENT_LINK_TTL_SEC = 2,592,000s`); expired links revert (`AGENT_LINK_TTL_EXPIRED` / `AGENT_LINK_EXPIRED`), and owner `renewAgentLink()` / `relinkAgentKey()` / `revokeAgent()` manage linking, revocation, and <=30-day renewal. |
| **Authenticated Post-Quantum Messaging (`qorechain-msg-v1\|<chainId>\|<data>`)** | Exact official `qorechain-msg-v1|<chainId>|<data>` hybrid `secp256k1 + ML-DSA-87` signer & verifier in `src/crypto.ts` (`signAuthenticatedMessage`, `verifyAuthenticatedMessage`) and on-chain `QoreGuardPolicyRegistry.sol` (`formatAuthenticatedMessage`, `verifyAuthenticatedMessage`, `verifyAgentAuthenticatedMessage`), plus `hybridSignBytes("v2", ...)` (`qorechain-pqc-hybrid-v2`) anti-downgrade transaction envelopes. |
| **AI-Native Agent Interface (MCP)** | 6-tool `qoreguard-mcp` server (`verify_pq_tx`, `quote_policy_decision`, `simulate_quantum_downgrade_attack`, `export_audit_bundle`, `probe_qorex_network`, `register_agent_policy`) with secret-input refusal (`SECRET_INPUT_REFUSED`). |

---

## 4. Adversarial Security Suite Summary

- **Core Policy Engine 6-Vector Breaker Suite**:
  1. `strip_pqc_to_classical_only` → blocked (`QUANTUM_DOWNGRADE_CLASSICAL_ONLY`, `PQC_SIGNATURE_MISSING`)
  2. `downgrade_sign_bytes_v2_to_v1` → blocked (`QUANTUM_DOWNGRADE_SIGN_BYTES_V1`)
  3. `downgrade_algorithm_to_mldsa44` → blocked (`QUANTUM_DOWNGRADE_WEAK_ALGORITHM`)
  4. `tamper_commitment_amount` → blocked (`COMMITMENT_TAMPERED`)
  5. `tamper_pqc_signature_byte` → blocked (`PQC_SIGNATURE_INVALID`)
  6. `replay_consumed_nonce` → blocked (`NONCE_REPLAY`)
- **Web Console 5-Scenario Interactive Breaker Lab**: Quantum Downgrade, Replay Nonce Reuse, Policy Cap Breach, Tampered PQ Digest, and Rogue Tool Injection with exportable JSON audit receipts.

---

## 5. Submission Readiness Checklist

- [x] Unified public GitHub repository under Apache-2.0 (`alphonshhhomenicmtu/qoreguard-qorechain`)
- [x] Live GitHub Pages deployment verified (`HTTP 200` + live JS/CSS asset check)
- [x] 1080p demo video ≤ 3 min uploaded to YouTube (`108s`) + public Google Drive mirror
- [x] `README.md` with live QoreX Testnet evidence, `1200×630` featured cover image (`docs/cover-image.png`), screenshots, quickstart, and open-source credits
- [x] `AI_USAGE.md` documenting AI-native workflow and human/automated verification
- [x] On-chain `QoreGuardPolicyRegistry.sol` verified (`18/18` Foundry PASS, Slither `0 High / 0 Medium`, live EVM 9800 dry-run `3,480,337` gas)
- [x] Zero hardcoded secrets / private keys, zero non-English artifacts, 62/62 automated tests passing
