# QoreGuard — QoreChain Developer Fest Submission Ready Package

## 1. Project Metadata & Live Links

- **Project Name**: QoreGuard — Post-Quantum AI Agent Policy Engine, MCP Server & Interactive Console
- **Primary Track**: **Post-Quantum AI Agents** ($1,500 1st / $750 2nd)
- **Special Award Opt-In**: **Best AI-Native Build** ($500 — see [AI_USAGE.md](AI_USAGE.md)) + **Top-Quality Floor** (7 × $250, ≥70/100)
- **License**: Apache-2.0 ([LICENSE](LICENSE))
- **Target Network**: QoreChain Testnet `qorechain-diana` (EVM Chain ID `9800`)
- **Public GitHub Repository**: https://github.com/alphonshhhomenicmtu/qoreguard-qorechain
- **Live GitHub Pages Demo**: https://alphonshhhomenicmtu.github.io/qoreguard-qorechain/
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
- **Automated Verification (`37 / 37` PASS)**:
  - Core SDK + Policy Engine + MCP Server: `npm run typecheck`, `npm run build`, `npm test` → **30 / 30 Vitest PASS** across `crypto`, `policy-engine`, `mcp-server` (full `InMemoryTransport` client/server round-trip), and `testnet-client`.
  - Interactive Web Console (`web/`): `npm run typecheck`, `npm test`, `npm run build` → **7 / 7 Vitest PASS**, deployed live to GitHub Pages.

---

## 3. 1:1 Mapping to Post-Quantum AI Agents Track Requirements

| Official Track Requirement | QoreGuard Implementation (Core Engine + MCP + Web Console) |
|---|---|
| **Scoped EVM Window & Session Bounds** | Intent expiration (`expiresAtUnix`), rolling time-window velocity budgets (`velocityWindows`), and `AgentGuardPolicy.windowBlocksRemaining` (`EVM_WINDOW_EXPIRED` / `INTENT_EXPIRED`) require fresh owner authorization once expired. |
| **Transaction, Value, Duration & Target Limits** | `maxSingleTxUqor`, rolling window `maxSpendUqor` & `maxTxCount`, strict `allowlistedTargets` / `denylistedTargets`, 4-byte EVM calldata selector firewall blocking `approve` (`0x095ea7b3`) and `setApprovalForAll` (`0xa22cb465`), plus web console `perTxCapQor`, `dailyCapQor`, `allowedTools`. |
| **Smart-Account / Agent Spending Rules** | Offline master authority binds `registeredPqPubkeyHashHex` (SHAKE-256 pay-to-pubkey-hash) and `policyHashHex`; strict monotonic nonces block replays (`NONCE_REPLAY`) and gaps (`NONCE_OUT_OF_ORDER`). |
| **Authenticated Post-Quantum Messaging** | Real FIPS-204 **ML-DSA-87** (plus **ML-DSA-65** & FIPS-205 **SLH-DSA**) co-signed with `secp256k1`/`ed25519` over official QoreChain `hybridSignBytes("v2", ...)` (`qorechain-pqc-hybrid-v2`) with length-prefixed SHAKE-256 commitments and anti-downgrade rejection (`QUANTUM_DOWNGRADE_CLASSICAL_ONLY`, `QUANTUM_DOWNGRADE_SIGN_BYTES_V1`, `QUANTUM_DOWNGRADE_WEAK_ALGORITHM`). |
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
- [x] `README.md` with live QoreX Testnet evidence, screenshots, quickstart, and open-source credits
- [x] `AI_USAGE.md` documenting AI-native workflow and human/automated verification
- [x] Zero hardcoded secrets / private keys, zero non-English artifacts, 37/37 automated tests passing
