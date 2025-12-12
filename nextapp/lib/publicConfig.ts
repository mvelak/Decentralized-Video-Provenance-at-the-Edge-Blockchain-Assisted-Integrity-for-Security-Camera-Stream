export type PublicConfig = {
  contractAddress: string;
  /** EIP-712 domain name (must match contract's EIP-712 domain name). */
  contractName: string;
  /** EIP-712 domain version (must match contract's EIP-712 domain version). */
  contractVersion: string;
  /** Optional: enforce chain id (e.g. 1, 11155111). */
  chainId?: number;
  /** If true, client will call /api/ipfs to upload. Otherwise uses mock CID. */
  ipfsUploadEnabled: boolean;
  /** If true, use relayer pattern (sign only, don't submit tx). If false, direct submission via MetaMask. */
  relayerEnabled: boolean;
  /** Relayer address for display purposes. */
  relayerAddress?: string;
};

function parseOptionalInt(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

export const PUBLIC_CONFIG: PublicConfig = {
  contractAddress: (process.env.NEXT_PUBLIC_CONTRACT_ADDRESS ?? "").trim(),
  contractName: (process.env.NEXT_PUBLIC_CONTRACT_NAME ?? "Veritas").trim(),
  contractVersion: (process.env.NEXT_PUBLIC_CONTRACT_VERSION ?? "1").trim(),
  chainId: parseOptionalInt(process.env.NEXT_PUBLIC_CHAIN_ID),
  ipfsUploadEnabled: (process.env.NEXT_PUBLIC_IPFS_UPLOAD ?? "").trim() === "true",
  relayerEnabled: (process.env.NEXT_PUBLIC_RELAYER_ENABLED ?? "true").trim() === "true",
  relayerAddress: (process.env.NEXT_PUBLIC_RELAYER_ADDRESS ?? "").trim(),
};

