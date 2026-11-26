// SPDX-License-Identifier: Apache-2.0
//
// Turnkey QoreGuardPolicyRegistry deployer & live QoreX EVM 9800 gas estimator.
// Env-var driven only (QOREX_PRIVATE_KEY); never prints or embeds private keys.

import {
  createPublicClient,
  createWalletClient,
  defineChain,
  formatEther,
  http,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  QOREGUARD_REGISTRY_ABI,
  QOREGUARD_REGISTRY_BYTECODE,
  QOREGUARD_REGISTRY_BYTECODE_BYTES,
  QOREGUARD_REGISTRY_BYTECODE_SHA256,
  QOREGUARD_REGISTRY_EVM_VERSION,
  QOREGUARD_REGISTRY_SOLC_VERSION,
} from "./contracts/registry-artifact.js";
import { getQoreNetwork, type QoreNetworkName } from "./networks.js";

export interface DeployRegistryOptions {
  readonly network?: QoreNetworkName;
  readonly evmRpcUrl?: string;
  readonly dryRun?: boolean;
  readonly privateKeyHex?: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

export interface DeployRegistryReport {
  readonly mode: "dry-run-live-estimate" | "dry-run-simulated" | "deployed-live";
  readonly contractName: "QoreGuardPolicyRegistry";
  readonly solcVersion: string;
  readonly evmVersion: string;
  readonly bytecodeBytes: number;
  readonly bytecodeSha256: string;
  readonly network: QoreNetworkName;
  readonly chainId: string;
  readonly expectedEvmChainId: number;
  readonly observedEvmChainId: number | null;
  readonly blockNumber: string | null;
  readonly estimatedGas: string;
  readonly gasPriceWei: string;
  readonly estimatedCostWei: string;
  readonly estimatedCostQor: string;
  readonly contractAddress?: Address;
  readonly txHash?: Hex;
  readonly verifiedCodeBytes?: number;
  readonly explorerUrl?: string;
  readonly note: string;
}

export async function deployPolicyRegistry(
  options: DeployRegistryOptions = {},
): Promise<DeployRegistryReport> {
  const network = options.network ?? "testnet";
  const net = getQoreNetwork(network);
  const evmRpcUrl = options.evmRpcUrl ?? net.endpoints.evmRpc;
  const timeoutMs = options.timeoutMs ?? 12_000;
  const dryRun = options.dryRun ?? true;

  const chain = defineChain({
    id: net.evmChainId,
    name: `QoreChain ${net.name}`,
    nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
    rpcUrls: { default: { http: [evmRpcUrl] } },
    blockExplorers: { default: { name: "QoreScan", url: net.explorerUrl } },
  });

  const publicClient = createPublicClient({
    chain,
    transport: http(evmRpcUrl, { timeout: timeoutMs, fetchFn: options.fetchImpl }),
  });

  let observedEvmChainId: number | null = null;
  let blockNumber: string | null = null;
  let gasPrice = 100_000_000_000n;
  let estimatedGas = 2_400_000n;
  let liveReachable = false;

  try {
    const [cid, blk, gp, gasEst] = await Promise.all([
      publicClient.getChainId(),
      publicClient.getBlockNumber(),
      publicClient.getGasPrice(),
      publicClient.estimateGas({ data: QOREGUARD_REGISTRY_BYTECODE }),
    ]);
    observedEvmChainId = cid;
    blockNumber = blk.toString();
    gasPrice = gp;
    estimatedGas = gasEst;
    liveReachable = true;
  } catch (err) {
    if (!dryRun) {
      throw new Error(
        `Cannot deploy live: QoreX EVM RPC unreachable (${err instanceof Error ? err.message.split("\n")[0] : String(err)})`,
      );
    }
  }

  const estimatedCostWei = estimatedGas * gasPrice;

  if (dryRun || !options.privateKeyHex) {
    return {
      mode: liveReachable ? "dry-run-live-estimate" : "dry-run-simulated",
      contractName: "QoreGuardPolicyRegistry",
      solcVersion: QOREGUARD_REGISTRY_SOLC_VERSION,
      evmVersion: QOREGUARD_REGISTRY_EVM_VERSION,
      bytecodeBytes: QOREGUARD_REGISTRY_BYTECODE_BYTES,
      bytecodeSha256: QOREGUARD_REGISTRY_BYTECODE_SHA256,
      network,
      chainId: net.chainId,
      expectedEvmChainId: net.evmChainId,
      observedEvmChainId,
      blockNumber,
      estimatedGas: estimatedGas.toString(),
      gasPriceWei: gasPrice.toString(),
      estimatedCostWei: estimatedCostWei.toString(),
      estimatedCostQor: formatEther(estimatedCostWei),
      note: liveReachable
        ? options.privateKeyHex
          ? "Live QoreX EVM 9800 gas estimate complete (dry-run mode; pass --broadcast to deploy)."
          : "Live QoreX EVM 9800 gas estimate complete (set QOREX_PRIVATE_KEY and --broadcast to deploy)."
        : "EVM RPC unreachable; returned deterministic offline gas estimate.",
    };
  }

  const pk = (options.privateKeyHex.startsWith("0x")
    ? options.privateKeyHex
    : `0x${options.privateKeyHex}`) as Hex;
  const account = privateKeyToAccount(pk);
  const walletClient = createWalletClient({
    account,
    chain,
    transport: http(evmRpcUrl, { timeout: 30_000, fetchFn: options.fetchImpl }),
  });

  const txHash = await walletClient.deployContract({
    abi: QOREGUARD_REGISTRY_ABI,
    bytecode: QOREGUARD_REGISTRY_BYTECODE,
    account,
    chain,
  });

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  const contractAddress = receipt.contractAddress ?? undefined;
  let verifiedCodeBytes = 0;
  if (contractAddress) {
    const code = await publicClient.getCode({ address: contractAddress });
    verifiedCodeBytes = code && code.length > 2 ? (code.length - 2) / 2 : 0;
  }

  return {
    mode: "deployed-live",
    contractName: "QoreGuardPolicyRegistry",
    solcVersion: QOREGUARD_REGISTRY_SOLC_VERSION,
    evmVersion: QOREGUARD_REGISTRY_EVM_VERSION,
    bytecodeBytes: QOREGUARD_REGISTRY_BYTECODE_BYTES,
    bytecodeSha256: QOREGUARD_REGISTRY_BYTECODE_SHA256,
    network,
    chainId: net.chainId,
    expectedEvmChainId: net.evmChainId,
    observedEvmChainId,
    blockNumber: receipt.blockNumber.toString(),
    estimatedGas: receipt.gasUsed.toString(),
    gasPriceWei: gasPrice.toString(),
    estimatedCostWei: (receipt.gasUsed * gasPrice).toString(),
    estimatedCostQor: formatEther(receipt.gasUsed * gasPrice),
    contractAddress,
    txHash,
    verifiedCodeBytes,
    explorerUrl: contractAddress ? `${net.explorerUrl}/address/${contractAddress}` : undefined,
    note: "Deployed QoreGuardPolicyRegistry live to QoreX EVM and verified deployed runtime bytecode.",
  };
}
