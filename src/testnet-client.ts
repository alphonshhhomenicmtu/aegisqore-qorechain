// SPDX-License-Identifier: Apache-2.0
//
// Real QoreX / QoreChain Testnet read-only probe (EVM JSON-RPC + Consensus RPC
// + live IQorePQC 0x...0A01 / IQoreAI 0x...0B01 precompiles) and turnkey
// env-var-driven guarded tx broadcaster with honest simulation fallback.

import {
  createPublicClient,
  createWalletClient,
  defineChain,
  getAddress,
  http,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { pqcKeygen, pqcSignBytes, pqcVerifyBytes, toHexPrefixed } from "./crypto.js";
import {
  getQoreNetwork,
  IQORE_AI_ABI,
  IQORE_CONSENSUS_ABI,
  IQORE_PQC_ABI,
  QORE_PRECOMPILES,
  type QoreNetworkConfig,
  type QoreNetworkName,
} from "./networks.js";
import type { QoreGuardPolicyEngine } from "./policy-engine.js";
import type { AiPreflightSignal, HybridSignedEnvelope, PolicyDecision } from "./types.js";

export interface PrecompileProbeResult {
  readonly available: boolean;
  readonly verified?: boolean;
  readonly detail: string;
}

export interface QoreXProbeReport {
  readonly mode: "live" | "simulated";
  readonly network: QoreNetworkName;
  readonly chainId: string;
  readonly expectedEvmChainId: number;
  readonly observedEvmChainId: number | null;
  readonly evmBlockNumber: string | null;
  readonly gasPriceWei: string | null;
  readonly consensusStatus: {
    readonly reachable: boolean;
    readonly network?: string;
    readonly latestBlockHeight?: string;
    readonly latestBlockHash?: string;
    readonly catchingUp?: boolean;
    readonly error?: string;
  };
  readonly precompiles: {
    readonly pqcVerify0x0A01: PrecompileProbeResult;
    readonly pqcKeyStatus0x0A02: PrecompileProbeResult;
    readonly aiRiskScore0x0B01: PrecompileProbeResult;
    readonly rlConsensusParams0x0C01: PrecompileProbeResult;
  };
  readonly localMlDsa87SelfTest: {
    readonly valid: boolean;
    readonly pubkeyBytes: number;
    readonly signatureBytes: number;
  };
  readonly fallbackReason?: string;
  readonly probedAtIso: string;
}

export interface ProbeOptions {
  readonly network?: QoreNetworkName;
  readonly evmRpcUrl?: string;
  readonly rpcUrl?: string;
  readonly timeoutMs?: number;
  readonly offline?: boolean;
  readonly fetchImpl?: typeof fetch;
}

function buildViemChain(net: QoreNetworkConfig, evmRpcUrl: string) {
  return defineChain({
    id: net.evmChainId,
    name: `QoreChain ${net.name}`,
    nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
    rpcUrls: { default: { http: [evmRpcUrl] } },
    blockExplorers: { default: { name: "QoreScan", url: net.explorerUrl } },
  });
}

/**
 * Performs a read-only probe of QoreChain / QoreX (default: testnet qorechain-diana,
 * EVM chain ID 9800), including live on-chain ML-DSA-87 verification via the
 * IQorePQC precompile (0x...0A01) when available, with honest offline fallback.
 */
export async function probeQoreXNetwork(options: ProbeOptions = {}): Promise<QoreXProbeReport> {
  const network = options.network ?? "testnet";
  const net = getQoreNetwork(network);
  const evmRpcUrl = options.evmRpcUrl ?? net.endpoints.evmRpc;
  const rpcUrl = options.rpcUrl ?? net.endpoints.rpc;
  const timeoutMs = options.timeoutMs ?? 8_000;
  const fetchFn = options.fetchImpl ?? fetch;
  const probedAtIso = new Date().toISOString();

  // Always run a real local FIPS-204 ML-DSA-87 sign+verify self-test (no mocks)
  const kp = pqcKeygen("ml-dsa-87");
  const probeMessage = new TextEncoder().encode(`qoreguard-probe|${net.chainId}|${probedAtIso}`);
  const sig = pqcSignBytes("ml-dsa-87", kp.secretKey, probeMessage);
  const localOk = pqcVerifyBytes("ml-dsa-87", kp.publicKey, probeMessage, sig);
  const localSelfTest = {
    valid: localOk,
    pubkeyBytes: kp.publicKey.length,
    signatureBytes: sig.length,
  };

  if (options.offline) {
    return {
      mode: "simulated",
      network,
      chainId: net.chainId,
      expectedEvmChainId: net.evmChainId,
      observedEvmChainId: net.evmChainId,
      evmBlockNumber: "0",
      gasPriceWei: "1000000000",
      consensusStatus: { reachable: false, error: "offline simulation mode requested" },
      precompiles: {
        pqcVerify0x0A01: { available: false, verified: localOk, detail: "offline mode: verified locally via @qorechain/pqc ML-DSA-87" },
        pqcKeyStatus0x0A02: { available: false, detail: "offline mode: skipped eth_call" },
        aiRiskScore0x0B01: { available: false, detail: "offline mode: skipped eth_call" },
        rlConsensusParams0x0C01: { available: false, detail: "offline mode: skipped eth_call" },
      },
      localMlDsa87SelfTest: localSelfTest,
      fallbackReason: "Explicit offline simulation mode enabled",
      probedAtIso,
    };
  }

  const client = createPublicClient({
    chain: buildViemChain(net, evmRpcUrl),
    transport: http(evmRpcUrl, { timeout: timeoutMs, fetchFn }),
  });

  let observedEvmChainId: number | null = null;
  let evmBlockNumber: string | null = null;
  let gasPriceWei: string | null = null;
  let fallbackReason: string | undefined;

  try {
    const [cid, blk, gp] = await Promise.all([
      client.getChainId(),
      client.getBlockNumber(),
      client.getGasPrice(),
    ]);
    observedEvmChainId = cid;
    evmBlockNumber = blk.toString();
    gasPriceWei = gp.toString();
  } catch (err) {
    fallbackReason = `EVM JSON-RPC unreachable (${err instanceof Error ? err.message.split("\n")[0] : String(err)})`;
  }

  // Consensus RPC /status check
  let consensusStatus: QoreXProbeReport["consensusStatus"] = { reachable: false };
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetchFn(`${rpcUrl.replace(/\/$/, "")}/status`, { signal: ctrl.signal });
    clearTimeout(timer);
    if (res.ok) {
      const json = (await res.json()) as {
        result?: {
          node_info?: { network?: string };
          sync_info?: { latest_block_height?: string; latest_block_hash?: string; catching_up?: boolean };
        };
      };
      consensusStatus = {
        reachable: true,
        network: json.result?.node_info?.network,
        latestBlockHeight: json.result?.sync_info?.latest_block_height,
        latestBlockHash: json.result?.sync_info?.latest_block_hash,
        catchingUp: json.result?.sync_info?.catching_up,
      };
    } else {
      consensusStatus = { reachable: false, error: `HTTP ${res.status}` };
    }
  } catch (err) {
    consensusStatus = {
      reachable: false,
      error: err instanceof Error ? err.message.split("\n")[0] : String(err),
    };
  }

  const probePrecompile = async (
    label: string,
    fn: () => Promise<{ detail: string; verified?: boolean }>,
  ): Promise<PrecompileProbeResult> => {
    if (observedEvmChainId === null) {
      return { available: false, detail: `${label} skipped (EVM RPC offline)` };
    }
    try {
      const r = await fn();
      return { available: true, verified: r.verified, detail: r.detail };
    } catch (err) {
      return {
        available: false,
        detail: `${label} unavailable (${err instanceof Error ? err.message.split("\n")[0] : String(err)})`,
      };
    }
  };

  const [pqcVerifyRes, pqcStatusRes, aiRiskRes, rlParamsRes] = await Promise.all([
    probePrecompile("IQorePQC.pqcVerify", async () => {
      const valid = await client.readContract({
        address: getAddress(QORE_PRECOMPILES.pqcVerify),
        abi: IQORE_PQC_ABI,
        functionName: "pqcVerify",
        args: [toHexPrefixed(kp.publicKey), toHexPrefixed(sig), toHexPrefixed(probeMessage)],
      });
      return { verified: Boolean(valid), detail: `on-chain ML-DSA-87 verify=${String(valid)}` };
    }),
    probePrecompile("IQorePQC.pqcKeyStatus", async () => {
      const [registered, algorithmId, , possessionProven] = await client.readContract({
        address: getAddress(QORE_PRECOMPILES.pqcKeyStatus),
        abi: IQORE_PQC_ABI,
        functionName: "pqcKeyStatus",
        args: ["0x000000000000000000000000000000000000dEaD"],
      });
      return {
        detail: `registered=${registered}, algId=${algorithmId}, possessionProven=${possessionProven}`,
      };
    }),
    probePrecompile("IQoreAI.aiRiskScore", async () => {
      const [score, level] = await client.readContract({
        address: getAddress(QORE_PRECOMPILES.aiRiskScore),
        abi: IQORE_AI_ABI,
        functionName: "aiRiskScore",
        args: ["0x" as Hex],
      });
      return { detail: `score=${score.toString()}, level=${level}` };
    }),
    probePrecompile("IQoreConsensus.rlConsensusParams", async () => {
      const [blockTime, baseGasPrice, validatorSetSize, epoch] = await client.readContract({
        address: getAddress(QORE_PRECOMPILES.rlConsensusParams),
        abi: IQORE_CONSENSUS_ABI,
        functionName: "rlConsensusParams",
      });
      return {
        detail: `blockTime=${blockTime}, baseGasPrice=${baseGasPrice}, validators=${validatorSetSize}, epoch=${epoch}`,
      };
    }),
  ]);

  return {
    mode: observedEvmChainId !== null ? "live" : "simulated",
    network,
    chainId: net.chainId,
    expectedEvmChainId: net.evmChainId,
    observedEvmChainId,
    evmBlockNumber,
    gasPriceWei,
    consensusStatus,
    precompiles: {
      pqcVerify0x0A01: pqcVerifyRes,
      pqcKeyStatus0x0A02: pqcStatusRes,
      aiRiskScore0x0B01: aiRiskRes,
      rlConsensusParams0x0C01: rlParamsRes,
    },
    localMlDsa87SelfTest: localSelfTest,
    fallbackReason,
    probedAtIso,
  };
}

/**
 * Queries QoreChain's on-chain IQoreAI precompiles (0x...0B01/0x...0B02) if
 * reachable, falling back transparently to a deterministic local heuristic.
 */
export async function fetchAiPreflightSignal(params: {
  network?: QoreNetworkName;
  evmRpcUrl?: string;
  sender: Address;
  valueUqor: bigint;
  calldataHex: Hex;
  offline?: boolean;
}): Promise<AiPreflightSignal> {
  if (!params.offline) {
    try {
      const net = getQoreNetwork(params.network ?? "testnet");
      const evmRpc = params.evmRpcUrl ?? net.endpoints.evmRpc;
      const client = createPublicClient({
        chain: buildViemChain(net, evmRpc),
        transport: http(evmRpc, { timeout: 5_000 }),
      });
      const [[score, level], [, flagged]] = await Promise.all([
        client.readContract({
          address: getAddress(QORE_PRECOMPILES.aiRiskScore),
          abi: IQORE_AI_ABI,
          functionName: "aiRiskScore",
          args: [params.calldataHex],
        }),
        client.readContract({
          address: getAddress(QORE_PRECOMPILES.aiAnomalyCheck),
          abi: IQORE_AI_ABI,
          functionName: "aiAnomalyCheck",
          args: [getAddress(params.sender), params.valueUqor],
        }),
      ]);
      return {
        riskScore: Number(score),
        riskLevel: Number(level),
        anomalyFlagged: Boolean(flagged),
        source: "onchain-precompile",
      };
    } catch {
      // Fall through cleanly to local deterministic heuristic
    }
  }

  // Deterministic local heuristic when precompile is unavailable or offline
  const sel = params.calldataHex.slice(0, 10).toLowerCase();
  const riskySelector = sel === "0x095ea7b3" || sel === "0xa22cb465";
  const highValue = params.valueUqor > 100_000_000n; // > 100 QOR
  const riskScore = (riskySelector ? 75 : 10) + (highValue ? 20 : 0);
  const riskLevel = riskScore >= 70 ? 3 : riskScore >= 30 ? 2 : 1;
  return {
    riskScore,
    riskLevel,
    anomalyFlagged: riskySelector && highValue,
    source: "local-heuristic",
  };
}

export interface TurnkeyTxResult {
  readonly mode: "broadcast-live" | "simulated-dry-run" | "blocked-by-policy";
  readonly decision: PolicyDecision;
  readonly network: QoreNetworkName;
  readonly txHash?: string;
  readonly explorerUrl?: string;
  readonly note: string;
}

/**
 * Turnkey guarded transaction runner:
 * 1. Enforces QoreGuard hybrid ML-DSA-87 policy gate BEFORE touching EVM wallet.
 * 2. Never logs or prints private keys.
 * 3. Broadcasts ONLY when `dryRun === false` AND an env-provided private key exists;
 *    otherwise returns an honest deterministic simulation receipt.
 */
export async function executeTurnkeyGuardedTx(params: {
  engine: QoreGuardPolicyEngine;
  envelope: HybridSignedEnvelope;
  privateKeyHex?: string;
  evmRpcUrl?: string;
  dryRun?: boolean;
  aiSignal?: AiPreflightSignal;
}): Promise<TurnkeyTxResult> {
  const network = params.engine.policy.network;
  const net = getQoreNetwork(network);
  const decision = params.engine.verifyAndCommit(params.envelope, { aiSignal: params.aiSignal });

  if (decision.verdict === "DENY") {
    return {
      mode: "blocked-by-policy",
      decision,
      network,
      note: `Blocked before broadcast (${decision.rejectionCodes.join(", ")})`,
    };
  }

  const dryRun = params.dryRun ?? true;
  if (dryRun || !params.privateKeyHex) {
    return {
      mode: "simulated-dry-run",
      decision,
      network,
      note: params.privateKeyHex
        ? "QoreGuard policy ALLOW (dryRun=true). Set QOREGUARD_DRY_RUN=false to broadcast live on QoreX."
        : "QoreGuard policy ALLOW (simulation fallback: no QOREGUARD_PRIVATE_KEY env var provided).",
    };
  }

  const pk = (params.privateKeyHex.startsWith("0x")
    ? params.privateKeyHex
    : `0x${params.privateKeyHex}`) as Hex;
  const evmRpcUrl = params.evmRpcUrl ?? net.endpoints.evmRpc;
  const chain = buildViemChain(net, evmRpcUrl);
  const account = privateKeyToAccount(pk);
  const walletClient = createWalletClient({
    account,
    chain,
    transport: http(evmRpcUrl, { timeout: 15_000 }),
  });

  const txHash = await walletClient.sendTransaction({
    account,
    chain,
    to: getAddress(params.envelope.intent.to as Address),
    value: BigInt(params.envelope.intent.valueUqor),
    data: (params.envelope.intent.calldataHex || "0x") as Hex,
  });

  return {
    mode: "broadcast-live",
    decision,
    network,
    txHash,
    explorerUrl: `${net.explorerUrl}/tx/${txHash}`,
    note: "Verified by QoreGuard hybrid ML-DSA-87 policy engine and broadcast to QoreX EVM.",
  };
}
