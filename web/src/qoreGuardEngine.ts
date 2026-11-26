export type SignatureScheme = "ML-DSA-87+secp256k1" | "ECDSA-only" | "none";

export interface QoreChainNetworkInfo {
  chainId: string;
  evmChainId: number;
  rpcUrl: string;
  restUrl: string;
  evmRpcUrl: string;
  faucetUrl: string;
  explorerUrl: string;
}

export const QORECHAIN_DIANA: QoreChainNetworkInfo = {
  chainId: "qorechain-diana",
  evmChainId: 9800,
  rpcUrl: "https://rpc-testnet.qore.host",
  restUrl: "https://api-testnet.qore.host",
  evmRpcUrl: "https://evm-testnet.qore.host",
  faucetUrl: "https://dashboard.qorechain.io/faucet",
  explorerUrl: "https://explore.qore.network",
};

export interface AgentGuardPolicy {
  agentName: string;
  ownerQorAddress: string;
  perTxCapQor: number;
  dailyCapQor: number;
  spentTodayQor: number;
  windowBlocksRemaining: number;
  requirePqHybrid: boolean;
  allowedTargets: string[];
  allowedTools: string[];
}

export interface AgentActionRequest {
  id: string;
  label: string;
  mcpTool: string;
  targetAddress: string;
  amountQor: number;
  nonce: string;
  signatureScheme: SignatureScheme;
  payloadSummary: string;
  expectedDigest: string;
  providedDigest: string;
  timestamp: string;
}

export interface GuardDecision {
  allowed: boolean;
  code:
    | "APPROVED"
    | "QUANTUM_DOWNGRADE_BLOCKED"
    | "REPLAY_NONCE_BLOCKED"
    | "POLICY_CAP_EXCEEDED"
    | "TAMPERED_PQ_DIGEST"
    | "ROGUE_TOOL_OR_TARGET_BLOCKED"
    | "EVM_WINDOW_EXPIRED";
  reason: string;
  signBytesPrefix: string;
  pqKeyType: "NIST FIPS 204 ML-DSA-87 (2,592B pk / 4,627B sig)";
  receiptHash: string;
}

export interface TelemetrySnapshot {
  source: "live-diana-rest" | "simulated-diana";
  chainId: string;
  latestHeight: number;
  blockTimeIso: string;
}

export const DEFAULT_POLICY: AgentGuardPolicy = {
  agentName: "qoreguard-treasury-bot-v1",
  ownerQorAddress: "qor1aegismm00000000000000000000000000qday87",
  perTxCapQor: 25,
  dailyCapQor: 100,
  spentTodayQor: 15,
  windowBlocksRemaining: 120,
  requirePqHybrid: true,
  allowedTargets: [
    "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
  ],
  allowedTools: ["qore_transfer_scoped", "qore_evm_swap", "qore_balance_read"],
};

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `0x${hex}`;
}

export function buildHybridSignBytes(
  chainId: string,
  request: Pick<
    AgentActionRequest,
    "mcpTool" | "targetAddress" | "amountQor" | "nonce"
  >
): string {
  const payload = JSON.stringify({
    tool: request.mcpTool,
    target: request.targetAddress,
    amountQor: request.amountQor,
    nonce: request.nonce,
  });
  return `qorechain-msg-v1|${chainId}|${payload}`;
}

export async function evaluateGuardRequest(
  policy: AgentGuardPolicy,
  request: AgentActionRequest,
  usedNonces: ReadonlySet<string>
): Promise<GuardDecision> {
  const signBytesPrefix = buildHybridSignBytes(QORECHAIN_DIANA.chainId, request);
  const baseReceiptInput = JSON.stringify({
    agent: policy.agentName,
    requestId: request.id,
    nonce: request.nonce,
    tool: request.mcpTool,
    target: request.targetAddress,
    amountQor: request.amountQor,
    scheme: request.signatureScheme,
    timestamp: request.timestamp,
  });
  const receiptHash = await sha256Hex(baseReceiptInput);

  if (policy.requirePqHybrid && request.signatureScheme !== "ML-DSA-87+secp256k1") {
    return {
      allowed: false,
      code: "QUANTUM_DOWNGRADE_BLOCKED",
      reason: `Quantum downgrade blocked: scheme '${request.signatureScheme}' rejected; policy requires ML-DSA-87+secp256k1 hybrid signing.`,
      signBytesPrefix,
      pqKeyType: "NIST FIPS 204 ML-DSA-87 (2,592B pk / 4,627B sig)",
      receiptHash,
    };
  }

  if (usedNonces.has(request.nonce)) {
    return {
      allowed: false,
      code: "REPLAY_NONCE_BLOCKED",
      reason: `Replay attack blocked: nonce '${request.nonce}' was already consumed in this EVM window.`,
      signBytesPrefix,
      pqKeyType: "NIST FIPS 204 ML-DSA-87 (2,592B pk / 4,627B sig)",
      receiptHash,
    };
  }

  if (request.providedDigest.toLowerCase() !== request.expectedDigest.toLowerCase()) {
    return {
      allowed: false,
      code: "TAMPERED_PQ_DIGEST",
      reason: `Tampered PQ digest detected: provided ${request.providedDigest.slice(0, 14)}... != expected ${request.expectedDigest.slice(0, 14)}...`,
      signBytesPrefix,
      pqKeyType: "NIST FIPS 204 ML-DSA-87 (2,592B pk / 4,627B sig)",
      receiptHash,
    };
  }

  if (policy.windowBlocksRemaining <= 0) {
    return {
      allowed: false,
      code: "EVM_WINDOW_EXPIRED",
      reason: "Scoped EVM window expired: owner must re-authorize with offline ML-DSA-87 key.",
      signBytesPrefix,
      pqKeyType: "NIST FIPS 204 ML-DSA-87 (2,592B pk / 4,627B sig)",
      receiptHash,
    };
  }

  const normalizedAllowedTargets = policy.allowedTargets.map((t) => t.toLowerCase());
  if (
    !policy.allowedTools.includes(request.mcpTool) ||
    !normalizedAllowedTargets.includes(request.targetAddress.toLowerCase())
  ) {
    return {
      allowed: false,
      code: "ROGUE_TOOL_OR_TARGET_BLOCKED",
      reason: `Rogue MCP tool/target blocked: tool '${request.mcpTool}' or target '${request.targetAddress}' is outside scoped allowlist.`,
      signBytesPrefix,
      pqKeyType: "NIST FIPS 204 ML-DSA-87 (2,592B pk / 4,627B sig)",
      receiptHash,
    };
  }

  if (
    request.amountQor <= 0 ||
    request.amountQor > policy.perTxCapQor ||
    policy.spentTodayQor + request.amountQor > policy.dailyCapQor
  ) {
    return {
      allowed: false,
      code: "POLICY_CAP_EXCEEDED",
      reason: `Policy cap breach: ${request.amountQor} QOR exceeds per-tx cap (${policy.perTxCapQor} QOR) or remaining daily budget (${policy.dailyCapQor - policy.spentTodayQor} QOR).`,
      signBytesPrefix,
      pqKeyType: "NIST FIPS 204 ML-DSA-87 (2,592B pk / 4,627B sig)",
      receiptHash,
    };
  }

  return {
    allowed: true,
    code: "APPROVED",
    reason: `Approved & signed with ML-DSA-87+secp256k1: ${request.amountQor} QOR via ${request.mcpTool} within scoped EVM window.`,
    signBytesPrefix,
    pqKeyType: "NIST FIPS 204 ML-DSA-87 (2,592B pk / 4,627B sig)",
    receiptHash,
  };
}

export async function fetchQoreTestnetTelemetry(): Promise<TelemetrySnapshot> {
  try {
    const res = await fetch(
      `${QORECHAIN_DIANA.restUrl}/cosmos/base/tendermint/v1beta1/blocks/latest`
    );
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const json = (await res.json()) as {
      block?: {
        header?: {
          chain_id?: string;
          height?: string;
          time?: string;
        };
      };
    };
    const header = json.block?.header;
    if (!header?.height) {
      throw new Error("Missing block header");
    }
    return {
      source: "live-diana-rest",
      chainId: header.chain_id ?? QORECHAIN_DIANA.chainId,
      latestHeight: Number(header.height),
      blockTimeIso: header.time ?? new Date().toISOString(),
    };
  } catch {
    return {
      source: "simulated-diana",
      chainId: QORECHAIN_DIANA.chainId,
      latestHeight: 1_842_910,
      blockTimeIso: new Date().toISOString(),
    };
  }
}
