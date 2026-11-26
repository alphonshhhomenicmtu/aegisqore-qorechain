import { useState } from "react";
import {
  DEFAULT_POLICY,
  QORECHAIN_DIANA,
  VERIFIED_DIANA_SNAPSHOT,
  buildHybridSignBytes,
  evaluateGuardRequest,
  fetchQoreTestnetTelemetry,
  sha256Hex,
  type AgentActionRequest,
  type AgentGuardPolicy,
  type GuardDecision,
  type TelemetrySnapshot,
} from "./qoreGuardEngine.ts";

interface TraceEntry {
  request: AgentActionRequest;
  decision: GuardDecision;
}

export default function App() {
  const [policy, setPolicy] = useState<AgentGuardPolicy>(DEFAULT_POLICY);
  const [usedNonces, setUsedNonces] = useState<Set<string>>(
    () => new Set(["nonce-0001-consumed"])
  );
  const [traces, setTraces] = useState<TraceEntry[]>([]);
  const [telemetry, setTelemetry] = useState<TelemetrySnapshot>(
    VERIFIED_DIANA_SNAPSHOT
  );
  const [seq, setSeq] = useState<number>(2);
  const [exportStatus, setExportStatus] = useState<string>("");

  async function refreshTelemetry(): Promise<void> {
    const snap = await fetchQoreTestnetTelemetry();
    setTelemetry(snap);
    if (snap.source === "verified-diana-snapshot") {
      setExportStatus(
        "Direct browser fetch blocked by *.qore.host CORS; using CLI-verified Diana snapshot (#10,801,813). Run `npm run probe:testnet` locally for direct RPC."
      );
    }
  }

  function resetConsole(): void {
    setPolicy(DEFAULT_POLICY);
    setUsedNonces(new Set(["nonce-0001-consumed"]));
    setTraces([]);
    setSeq(2);
    setExportStatus("");
  }

  async function runScenario(
    scenario:
      | "valid"
      | "quantum-downgrade"
      | "replay-nonce"
      | "policy-cap-breach"
      | "tampered-digest"
      | "rogue-tool"
  ): Promise<void> {
    const nextNonce =
      scenario === "replay-nonce"
        ? "nonce-0001-consumed"
        : `nonce-${String(seq).padStart(4, "0")}`;
    if (scenario !== "replay-nonce") {
      setSeq((s) => s + 1);
    }

    const baseReq: AgentActionRequest = {
      id: `req-${Date.now()}`,
      label:
        scenario === "valid"
          ? "Valid Scoped PQ Transfer"
          : scenario === "quantum-downgrade"
            ? "Scenario 1: Quantum Downgrade Attack"
            : scenario === "replay-nonce"
              ? "Scenario 2: Replay Nonce Reuse"
              : scenario === "policy-cap-breach"
                ? "Scenario 3: Policy Cap Breach"
                : scenario === "tampered-digest"
                  ? "Scenario 4: Tampered PQ Digest"
                  : "Scenario 5: Rogue Tool Injection",
      mcpTool:
        scenario === "rogue-tool" ? "qore_unrestricted_drain" : "qore_transfer_scoped",
      targetAddress:
        scenario === "rogue-tool"
          ? "0xDEAD00000000000000000000000000000000BEEF"
          : policy.allowedTargets[0],
      amountQor: scenario === "policy-cap-breach" ? policy.perTxCapQor + 50 : 10,
      nonce: nextNonce,
      signatureScheme:
        scenario === "quantum-downgrade" ? "ECDSA-only" : "ML-DSA-87+secp256k1",
      payloadSummary: "Scoped AI Treasury Rebalance on qorechain-diana",
      expectedDigest: "",
      providedDigest: "",
      timestamp: new Date().toISOString(),
    };

    const signBytes = buildHybridSignBytes(QORECHAIN_DIANA.chainId, baseReq);
    const expectedDigest = await sha256Hex(signBytes);
    baseReq.expectedDigest = expectedDigest;
    baseReq.providedDigest =
      scenario === "tampered-digest"
        ? `0x${"f".repeat(64)}`
        : expectedDigest;

    const decision = await evaluateGuardRequest(policy, baseReq, usedNonces);
    if (decision.allowed) {
      setUsedNonces((prev) => new Set(prev).add(baseReq.nonce));
      setPolicy((prev) => ({
        ...prev,
        spentTodayQor: prev.spentTodayQor + baseReq.amountQor,
        windowBlocksRemaining: Math.max(0, prev.windowBlocksRemaining - 1),
      }));
    }

    setTraces((prev) => [{ request: baseReq, decision }, ...prev].slice(0, 20));
  }

  function exportLatestReceipt(): void {
    if (traces.length === 0) {
      setExportStatus("Run a scenario first to generate a SHA-256 receipt.");
      return;
    }
    const latest = traces[0];
    const payload = JSON.stringify(
      {
        product: "QoreGuard",
        chainId: QORECHAIN_DIANA.chainId,
        evmChainId: QORECHAIN_DIANA.evmChainId,
        policy: {
          agentName: policy.agentName,
          ownerQorAddress: policy.ownerQorAddress,
          perTxCapQor: policy.perTxCapQor,
          dailyCapQor: policy.dailyCapQor,
          requirePqHybrid: policy.requirePqHybrid,
        },
        request: latest.request,
        decision: latest.decision,
      },
      null,
      2
    );
    const blob = new Blob([payload], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `qoreguard-receipt-${latest.decision.receiptHash.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setExportStatus(`Exported receipt ${latest.decision.receiptHash.slice(0, 16)}...`);
  }

  return (
    <div className="shell">
      {/* Live QoreX Testnet / PQ Telemetry Strip */}
      <div className="telemetry-strip">
        <div className="telemetry-items">
          <span className="badge badge-blue">{telemetry.chainId}</span>
          <span className="mono">EVM ID: {QORECHAIN_DIANA.evmChainId}</span>
          <span className="mono">Height: #{telemetry.latestHeight.toLocaleString("en-US")}</span>
          <span className="badge badge-green">0x0A01 pqcVerify: true</span>
          <span className="mono muted">Source: {telemetry.source}</span>
        </div>
        <button onClick={() => void refreshTelemetry()}>
          Probe Live RPC (Opt-In)
        </button>
      </div>

      {/* Header */}
      <header className="header-card">
        <div>
          <h1>QoreGuard — Post-Quantum AI Agent Treasury &amp; MCP Guard</h1>
          <p>
            QoreChain Developer Fest (Post-Quantum AI Agents) &bull; Scoped EVM
            Window &bull; ML-DSA-87 + secp256k1 Hybrid Signing
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <a
            href="qoreguard-deck.pdf"
            target="_blank"
            rel="noreferrer"
            className="btn-primary"
            style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", padding: "8px 14px", borderRadius: 8 }}
          >
            Pitch Deck (PDF)
          </a>
          <button className="btn-primary" onClick={exportLatestReceipt}>
            Export SHA-256 Receipt
          </button>
          <button onClick={resetConsole}>Reset Guard</button>
        </div>
      </header>
      {exportStatus && (
        <p className="muted mono" style={{ marginTop: -8, marginBottom: 14 }}>
          {exportStatus}
        </p>
      )}

      <main className="grid">
        {/* ML-DSA-87 vs ECDSA Quantum-Risk Comparison Panel */}
        <section className="card col-6">
          <div className="card-head">
            <h2>ML-DSA-87 vs ECDSA Quantum-Risk Comparison</h2>
            <span className="badge badge-green">NIST FIPS 204</span>
          </div>
          <table className="cmp-table">
            <thead>
              <tr>
                <th>Property</th>
                <th>ECDSA (secp256k1)</th>
                <th>ML-DSA-87 Hybrid</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Shor&apos;s Algorithm</td>
                <td>
                  <span className="badge badge-red">Broken on Q-Day</span>
                </td>
                <td>
                  <span className="badge badge-green">Quantum-Resistant</span>
                </td>
              </tr>
              <tr>
                <td>Public Key Size</td>
                <td className="mono">33 bytes</td>
                <td className="mono">2,592 bytes</td>
              </tr>
              <tr>
                <td>Signature Size</td>
                <td className="mono">64 bytes</td>
                <td className="mono">4,627 bytes</td>
              </tr>
              <tr>
                <td>QoreChain Policy</td>
                <td className="muted">Blocked when hybrid enforced</td>
                <td className="mono">qorechain-msg-v1|...</td>
              </tr>
              <tr>
                <td>Owner Key Posture</td>
                <td className="muted">Exposed if hot-linked</td>
                <td className="muted">Offline; agent scoped</td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* Interactive AI Agent Policy Console */}
        <section className="card col-6">
          <div className="card-head">
            <h2>AI Agent Policy Console (Scoped EVM Window)</h2>
            <span
              className={`badge ${
                policy.requirePqHybrid ? "badge-green" : "badge-amber"
              }`}
            >
              {policy.requirePqHybrid ? "PQ Hybrid Enforced" : "Downgrade Risk"}
            </span>
          </div>

          <div className="kv-grid">
            <div className="kv-box">
              <div className="kv-label">Agent ID</div>
              <div className="kv-val">{policy.agentName}</div>
            </div>
            <div className="kv-box">
              <div className="kv-label">Window Blocks Left</div>
              <div className="kv-val">{policy.windowBlocksRemaining} blocks</div>
            </div>
            <div className="kv-box">
              <div className="kv-label">Per-Tx Cap / Daily Budget</div>
              <div className="kv-val">
                {policy.perTxCapQor} QOR / {policy.spentTodayQor} of{" "}
                {policy.dailyCapQor} QOR
              </div>
            </div>
            <div className="kv-box">
              <div className="kv-label">Allowed MCP Tools</div>
              <div className="kv-val">{policy.allowedTools.join(", ")}</div>
            </div>
            <div className="kv-box" style={{ gridColumn: "span 2" }}>
              <div className="kv-label">Target Contract Allowlist</div>
              <div className="kv-val">{policy.allowedTargets.join(" | ")}</div>
            </div>
          </div>

          <div className="controls-row">
            <label className="muted" style={{ fontSize: "0.82rem" }}>
              Per-Tx Cap (QOR):
            </label>
            <input
              type="number"
              min={1}
              max={500}
              value={policy.perTxCapQor}
              onChange={(e) =>
                setPolicy((p) => ({
                  ...p,
                  perTxCapQor: Math.max(1, Number(e.target.value) || 1),
                }))
              }
            />
            <button
              onClick={() =>
                setPolicy((p) => ({
                  ...p,
                  requirePqHybrid: !p.requirePqHybrid,
                }))
              }
            >
              {policy.requirePqHybrid
                ? "Disable PQ Guard (Test)"
                : "Enforce ML-DSA-87 Hybrid"}
            </button>
          </div>
        </section>

        {/* 5-Scenario Adversarial Breaker Lab */}
        <section className="card col-12">
          <div className="card-head">
            <h2>5-Scenario Adversarial Breaker Lab</h2>
            <span className="badge badge-amber">Deterministic PQ Guard</span>
          </div>

          <div className="lab-grid">
            <button
              className="lab-btn btn-success"
              onClick={() => void runScenario("valid")}
            >
              <strong>Baseline: Valid PQ Action</strong>
              <span>10 QOR scoped transfer with ML-DSA-87+secp256k1</span>
            </button>
            <button
              className="lab-btn"
              onClick={() => void runScenario("quantum-downgrade")}
            >
              <strong>1. Quantum Downgrade Attack</strong>
              <span>Forces ECDSA-only signature against PQ policy</span>
            </button>
            <button
              className="lab-btn"
              onClick={() => void runScenario("replay-nonce")}
            >
              <strong>2. Replay Nonce Reuse</strong>
              <span>Re-submits already consumed nonce-0001-consumed</span>
            </button>
            <button
              className="lab-btn"
              onClick={() => void runScenario("policy-cap-breach")}
            >
              <strong>3. Policy Cap Breach</strong>
              <span>Requests transfer exceeding perTxCapQor</span>
            </button>
            <button
              className="lab-btn"
              onClick={() => void runScenario("tampered-digest")}
            >
              <strong>4. Tampered PQ Digest</strong>
              <span>Mutates SHA-256 sign-bytes digest post-signing</span>
            </button>
            <button
              className="lab-btn"
              onClick={() => void runScenario("rogue-tool")}
            >
              <strong>5. Rogue Tool Injection</strong>
              <span>Invokes unapproved drain tool &amp; unknown target</span>
            </button>
          </div>

          <div className="trace-list">
            {traces.length === 0 && (
              <div className="muted">
                No guard evaluations yet. Trigger any scenario above to inspect
                PQ signature verification and SHA-256 tamper-evident receipts.
              </div>
            )}
            {traces.map(({ request, decision }) => (
              <div
                key={request.id}
                className={`trace-item ${decision.allowed ? "ok" : "blocked"}`}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: 8,
                  }}
                >
                  <div>
                    <span
                      className={`badge ${
                        decision.allowed ? "badge-green" : "badge-red"
                      }`}
                      style={{ marginRight: 8 }}
                    >
                      {decision.allowed ? "PASS" : "BLOCKED"}
                    </span>
                    <strong>{request.label}</strong>
                  </div>
                  <span className="mono muted">{decision.code}</span>
                </div>
                <div className="muted" style={{ marginTop: 6, fontSize: "0.84rem" }}>
                  {decision.reason}
                </div>
                <div className="mono muted" style={{ marginTop: 6, fontSize: "0.76rem" }}>
                  SignBytes: {decision.signBytesPrefix}
                </div>
                <div className="mono muted" style={{ fontSize: "0.76rem" }}>
                  SHA-256 Receipt: {decision.receiptHash}
                </div>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
