# QoreGuard — 1080p Demo Video Narration Script (108s / < 3 min)

1. **[00:00 – 00:12] Title & Problem**
   Autonomous AI treasury agents are vulnerable to two threats: classical ECDSA key recovery on Q-Day, and prompt-injected or unconstrained MCP tool calls. QoreGuard solves both on QoreChain (`qorechain-diana`, EVM Chain ID 9800).

2. **[00:12 – 00:24] Live QoreX Telemetry & Hero**
   The QoreGuard Command Center connects to QoreChain Diana's REST and RPC endpoints (`api-testnet.qore.host`, `rpc-testnet.qore.host`) and displays real-time block height and EVM window posture.

3. **[00:24 – 00:36] ML-DSA-87 vs ECDSA Quantum-Risk Comparison**
   While classical secp256k1 ECDSA (33-byte pubkey, 64-byte signature) breaks under Shor's algorithm, QoreGuard enforces NIST FIPS 204 ML-DSA-87 hybrid signing (`qorechain-msg-v1|qorechain-diana|...`) while keeping the owner's master PQ key offline.

4. **[00:36 – 00:48] Architecture: Scoped EVM Window & Policy Guard**
   Every AI agent operates inside an owner-authorized Scoped EVM Window with strict per-transaction caps, daily QOR budgets, remaining block bounds, contract allowlists, and MCP tool allowlists.

5. **[00:48 – 01:00] Interactive Policy Console & SHA-256 Receipt**
   Executing a valid 10 QOR scoped transfer updates the daily budget, decrements the remaining window blocks, and emits a deterministic SHA-256 tamper-evident receipt hash.

6. **[01:00 – 01:12] 5-Scenario Adversarial Breaker Lab**
   In the Adversarial Breaker Lab, we test five deterministic attacks: Quantum Downgrade (`ECDSA-only`), Replay Nonce Reuse, Policy Cap Breach, Tampered PQ Digest, and Rogue Tool Injection.

7. **[01:12 – 01:24] Threat Model & Deterministic Verification**
   Every attack is blocked before execution with an explicit machine-readable code (`QUANTUM_DOWNGRADE_BLOCKED`, `REPLAY_NONCE_BLOCKED`, `POLICY_CAP_EXCEEDED`, `TAMPERED_PQ_DIGEST`, `ROGUE_TOOL_OR_TARGET_BLOCKED`), backed by 7/7 passing Vitest unit tests.

8. **[01:24 – 01:36] Full Console Overview**
   Zero-secret browser architecture, inline SVG favicon, and instant JSON receipt export make QoreGuard ready for QoreChain's Post-Quantum AI Agents track.

9. **[01:36 – 01:48] Closing & Build Before Q-Day**
   QoreGuard — Post-Quantum AI Agent Treasury & MCP Guard. Built for QoreChain Developer Fest (`qorechain-diana`, EVM 9800).
