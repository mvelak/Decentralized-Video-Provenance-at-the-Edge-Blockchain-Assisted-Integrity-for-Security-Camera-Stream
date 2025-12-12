export type PublicConfig = {
  contractAddress: string;
  /** EIP-712 domain name (must match contract constructor arg). */
  contractName: string;
  /** EIP-712 domain version (must match contract constructor arg). */
  contractVersion: string;
  /** Optional: enforce chain id (e.g. 1, 11155111). */
  chainId?: number;
  /** If true, client will call /api/ipfs to upload. Otherwise uses mock CID. */
  ipfsUploadEnabled: boolean;
};

function parseOptionalInt(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

export const PUBLIC_CONFIG: PublicConfig = {
  contractAddress: (process.env.NEXT_PUBLIC_CONTRACT_ADDRESS ?? "").trim(),
  contractName: (process.env.NEXT_PUBLIC_CONTRACT_NAME ?? "SecurityVideoRegistry").trim(),
  contractVersion: (process.env.NEXT_PUBLIC_CONTRACT_VERSION ?? "1").trim(),
  chainId: parseOptionalInt(process.env.NEXT_PUBLIC_CHAIN_ID),
  ipfsUploadEnabled: (process.env.NEXT_PUBLIC_IPFS_UPLOAD ?? "").trim() === "true",
};

