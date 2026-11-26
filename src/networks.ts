// SPDX-License-Identifier: Apache-2.0
//
// QoreChain / QoreX verified network presets, precompile addresses, ABIs, and
// prefix-free domain separation constants.

import type { Address } from "viem";

export type QoreNetworkName = "testnet" | "mainnet" | "localnet";

export interface QoreNetworkConfig {
  readonly name: QoreNetworkName;
  readonly chainId: string;
  readonly evmChainId: number;
  readonly bech32Prefix: "qor";
  readonly baseDenom: "uqor";
  readonly displayDenom: "QOR";
  readonly decimals: 6;
  readonly signBytesVersion: "v1" | "v2";
  readonly pqcPrecompilesActive: boolean;
  readonly endpoints: {
    readonly rest: string;
    readonly rpc: string;
    readonly evmRpc: string;
    readonly evmWs?: string;
  };
  readonly explorerUrl: string;
}

/**
 * Verified public QoreChain network presets matching @qorechain/sdk and @qorechain/mcp.
 */
export const QORE_NETWORKS: Readonly<Record<QoreNetworkName, QoreNetworkConfig>> = {
  testnet: {
    name: "testnet",
    chainId: "qorechain-diana",
    evmChainId: 9800,
    bech32Prefix: "qor",
    baseDenom: "uqor",
    displayDenom: "QOR",
    decimals: 6,
    signBytesVersion: "v2",
    pqcPrecompilesActive: true,
    endpoints: {
      rest: "https://api-testnet.qore.host",
      rpc: "https://rpc-testnet.qore.host",
      evmRpc: "https://evm-testnet.qore.host",
      evmWs: "wss://evm-ws-testnet.qore.host",
    },
    explorerUrl: "https://explore.qore.network",
  },
  mainnet: {
    name: "mainnet",
    chainId: "qorechain-vladi",
    evmChainId: 9801,
    bech32Prefix: "qor",
    baseDenom: "uqor",
    displayDenom: "QOR",
    decimals: 6,
    signBytesVersion: "v2",
    pqcPrecompilesActive: false,
    endpoints: {
      rest: "https://api.qore.host",
      rpc: "https://rpc.qore.host",
      evmRpc: "https://evm.qore.host",
    },
    explorerUrl: "https://explore.qore.network",
  },
  localnet: {
    name: "localnet",
    chainId: "qorechain-devnet",
    evmChainId: 9800,
    bech32Prefix: "qor",
    baseDenom: "uqor",
    displayDenom: "QOR",
    decimals: 6,
    signBytesVersion: "v2",
    pqcPrecompilesActive: true,
    endpoints: {
      rest: "http://127.0.0.1:1317",
      rpc: "http://127.0.0.1:26657",
      evmRpc: "http://127.0.0.1:8545",
      evmWs: "ws://127.0.0.1:8546",
    },
    explorerUrl: "https://explore.qore.network",
  },
};

export function getQoreNetwork(name: QoreNetworkName = "testnet"): QoreNetworkConfig {
  return QORE_NETWORKS[name];
}

/**
 * Fixed QoreChain EVM Engine precompile addresses (aligned with @qorechain/evm).
 */
export const QORE_PRECOMPILES = {
  crossVmBridge: "0x0000000000000000000000000000000000000901" as Address,
  pqcVerify: "0x0000000000000000000000000000000000000A01" as Address,
  pqcKeyStatus: "0x0000000000000000000000000000000000000A02" as Address,
  aiRiskScore: "0x0000000000000000000000000000000000000B01" as Address,
  aiAnomalyCheck: "0x0000000000000000000000000000000000000B02" as Address,
  rlConsensusParams: "0x0000000000000000000000000000000000000C01" as Address,
} as const;

export const IQORE_PQC_ABI = [
  {
    type: "function",
    name: "pqcVerify",
    stateMutability: "view",
    inputs: [
      { name: "pubkey", type: "bytes" },
      { name: "signature", type: "bytes" },
      { name: "message", type: "bytes" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
  },
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "algorithmId", type: "uint8" },
      { name: "pubkey", type: "bytes" },
      { name: "possessionProven", type: "bool" },
    ],
  },
] as const;

export const IQORE_AI_ABI = [
  {
    type: "function",
    name: "aiRiskScore",
    stateMutability: "view",
    inputs: [{ name: "txData", type: "bytes" }],
    outputs: [
      { name: "score", type: "uint256" },
      { name: "level", type: "uint8" },
    ],
  },
  {
    type: "function",
    name: "aiAnomalyCheck",
    stateMutability: "view",
    inputs: [
      { name: "sender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [
      { name: "anomalyScore", type: "uint256" },
      { name: "flagged", type: "bool" },
    ],
  },
] as const;

export const IQORE_CONSENSUS_ABI = [
  {
    type: "function",
    name: "rlConsensusParams",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "blockTime", type: "uint256" },
      { name: "baseGasPrice", type: "uint256" },
      { name: "validatorSetSize", type: "uint256" },
      { name: "epoch", type: "uint256" },
    ],
  },
] as const;

/**
 * Unique, prefix-free QoreGuard domain separation strings (non-overlapping with
 * QoreChain's reserved list in qorechain-pqc/DESIGN.md).
 */
export const QOREGUARD_DOMAINS = {
  policyCommit: "qoreguard-policy-commit-v1|",
  auditBundle: "qoreguard-audit-bundle-v1|",
  qoreHybridV2: "qorechain-pqc-hybrid-v2",
} as const;
