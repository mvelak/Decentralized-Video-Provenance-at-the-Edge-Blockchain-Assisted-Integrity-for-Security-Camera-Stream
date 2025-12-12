import { NextResponse } from 'next/server';
import { Contract, JsonRpcProvider, Wallet } from 'ethers';
import ABI from '@/abi.json';

export const runtime = 'nodejs';

type RelayerPayload = {
  contentHash: string;
  merkleRoot: string;
  originalTimestamp: number | bigint;
  sequence: number | bigint;
  cid: string;
  signature: string;
};

function getErrorMessage(err: unknown): string {
  if (typeof err === 'object' && err !== null) {
    const maybeReason = (err as { reason?: unknown }).reason;
    if (typeof maybeReason === 'string' && maybeReason.length > 0) return maybeReason;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

export async function POST(req: Request) {
  try {
    // 1. Validate environment variables
    const relayerKey = process.env.RELAYER_PRIVATE_KEY;
    const contractAddress = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS;
    const rpcUrl = process.env.NEXT_PUBLIC_RPC_URL || 'https://data-seed-prebsc-1-s1.binance.org:8545/';

    if (!relayerKey || !relayerKey.trim()) {
      return NextResponse.json(
        { error: 'Server missing RELAYER_PRIVATE_KEY. Set it to enable relayer submissions.' },
        { status: 501 }
      );
    }

    if (!contractAddress || !contractAddress.trim()) {
      return NextResponse.json(
        { error: 'Server missing NEXT_PUBLIC_CONTRACT_ADDRESS.' },
        { status: 500 }
      );
    }

    // 2. Parse and validate payload
    let payload: RelayerPayload;
    try {
      payload = (await req.json()) as RelayerPayload;
    } catch {
      return NextResponse.json({ error: 'Invalid JSON payload' }, { status: 400 });
    }

    const { contentHash, merkleRoot, originalTimestamp, sequence, cid, signature } = payload;

    if (!contentHash || !merkleRoot || !cid || !signature) {
      return NextResponse.json(
        { error: 'Missing required fields: contentHash, merkleRoot, cid, signature' },
        { status: 400 }
      );
    }

    // 3. Create relayer wallet and connect to provider
    const provider = new JsonRpcProvider(rpcUrl);
    const relayer = new Wallet(relayerKey.trim(), provider);

    // 4. Create contract instance with relayer as signer
    const contract = new Contract(contractAddress.trim(), ABI, relayer);

    // 5. Submit transaction to blockchain
    const tx = await contract.registerVideoSigned({
      contentHash,
      merkleRoot,
      originalTimestamp: BigInt(originalTimestamp),
      sequence: BigInt(sequence),
      cid,
      signature,
    });

    // 6. Return transaction hash (don't wait for confirmation)
    return NextResponse.json({
      success: true,
      txHash: tx.hash,
      relayer: await relayer.getAddress(),
    });
  } catch (error: unknown) {
    console.error('Relayer submission error:', error);
    return NextResponse.json(
      {
        error: 'Relayer submission failed',
        details: getErrorMessage(error),
      },
      { status: 500 }
    );
  }
}
