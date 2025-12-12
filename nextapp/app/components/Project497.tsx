'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { BrowserProvider, Contract, ethers } from 'ethers';
import ABI from '@/abi.json';
import { PUBLIC_CONFIG } from '@/lib/publicConfig';

type ChainId = number;

type ContractVideo = {
  uploader: string;
  sequence: bigint;
  relayer: string;
  createdAt: bigint;
  originalTimestamp: bigint;
  contentHash: string;
  merkleRoot: string;
  cid: string;
  cameraId: string;
};

function getErrorMessage(err: unknown): string {
  if (typeof err === 'object' && err !== null) {
    const maybeReason = (err as { reason?: unknown }).reason;
    if (typeof maybeReason === 'string' && maybeReason.length > 0) return maybeReason;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

function toSafeNumber(value: bigint): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return n;
}

function formatUnixSeconds(ts: bigint): string {
  const ms = toSafeNumber(ts) * 1000;
  if (!Number.isFinite(ms) || ms <= 0) return '—';
  return new Date(ms).toLocaleString();
}

function ipfsUrl(cid: string): string {
  const trimmed = cid.trim();
  if (!trimmed) return '';
  return `https://ipfs.io/ipfs/${trimmed}`;
}

function isBytes32(value: string): boolean {
  try {
    return ethers.isHexString(value, 32);
  } catch {
    return false;
  }
}

function normalizeVideo(v: unknown): ContractVideo {
  const obj = v as Record<string, unknown>;
  return {
    uploader: String(obj.uploader ?? ''),
    sequence: (obj.sequence as bigint) ?? BigInt(0),
    relayer: String(obj.relayer ?? ''),
    createdAt: (obj.createdAt as bigint) ?? BigInt(0),
    originalTimestamp: (obj.originalTimestamp as bigint) ?? BigInt(0),
    contentHash: String(obj.contentHash ?? ''),
    merkleRoot: String(obj.merkleRoot ?? ''),
    cid: String(obj.cid ?? ''),
    cameraId: String(obj.cameraId ?? ''),
  };
}

export default function Project497() {
  // --- State ---
  const [isRecording, setIsRecording] = useState(false);
  const [videoBlob, setVideoBlob] = useState<Blob | null>(null);
  const [walletAddress, setWalletAddress] = useState<string>('');
  const [connectedChainId, setConnectedChainId] = useState<ChainId | null>(null);
  const [status, setStatus] = useState<string>('Ready');
  const [logs, setLogs] = useState<string[]>([]);

  // Registration form fields
  const [cameraId, setCameraId] = useState<string>('cam-1');

  // Lookup + listing
  const [lookupHash, setLookupHash] = useState<string>('');
  const [lookupResult, setLookupResult] = useState<ContractVideo | null>(null);
  const [lookupError, setLookupError] = useState<string>('');
  const [lookupLoading, setLookupLoading] = useState<boolean>(false);

  const [listAddress, setListAddress] = useState<string>('');
  const [listOffset, setListOffset] = useState<number>(0);
  const [listLimit, setListLimit] = useState<number>(10);
  const [listTotal, setListTotal] = useState<number>(0);
  const [listResults, setListResults] = useState<ContractVideo[]>([]);
  const [listError, setListError] = useState<string>('');
  const [listLoading, setListLoading] = useState<boolean>(false);

  const addr = PUBLIC_CONFIG.contractAddress;
  const contractAddress = useMemo(() => {
    return ethers.isAddress(addr) ? ethers.getAddress(addr) : '';
  }, [addr]);

  // --- Refs ---
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const videoPreviewRef = useRef<HTMLVideoElement>(null);
  const chunksRef = useRef<Blob[]>([]);

  // --- Helpers ---
  const log = (msg: string) => setLogs((prev) => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);

  const requiredChainId = PUBLIC_CONFIG.chainId;
  const chainMismatch =
    requiredChainId !== undefined && connectedChainId !== null && connectedChainId !== requiredChainId;

  const getProvider = (): BrowserProvider => {
    const eth = window.ethereum;
    if (!eth) throw new Error('Please install MetaMask (or another injected wallet).');
    return new BrowserProvider(eth);
  };

  const getReadContract = async (): Promise<{ provider: BrowserProvider; contract: Contract; chainId: ChainId }> => {
    if (!contractAddress) throw new Error('Missing NEXT_PUBLIC_CONTRACT_ADDRESS (or invalid address).');
    const provider = getProvider();
    const network = await provider.getNetwork();
    const chainId = Number(network.chainId);
    const contract = new Contract(contractAddress, ABI, provider);
    return { provider, contract, chainId };
  };

  const getWriteContract = async (): Promise<{ provider: BrowserProvider; contract: Contract; chainId: ChainId; signerAddress: string }> => {
    if (!contractAddress) throw new Error('Missing NEXT_PUBLIC_CONTRACT_ADDRESS (or invalid address).');
    const provider = getProvider();
    const network = await provider.getNetwork();
    const chainId = Number(network.chainId);
    const signer = await provider.getSigner();
    const signerAddress = await signer.getAddress();
    const contract = new Contract(contractAddress, ABI, signer);
    return { provider, contract, chainId, signerAddress };
  };

  const switchToRequiredNetwork = async () => {
    if (!requiredChainId) return;
    if (!window.ethereum?.request) return;
    try {
      const hexChainId = '0x' + requiredChainId.toString(16);
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: hexChainId }],
      });
      log(`Requested network switch to ${requiredChainId}`);
    } catch (e: unknown) {
      log(`Network switch failed: ${getErrorMessage(e)}`);
    }
  };

  useEffect(() => {
    const eth = window.ethereum;
    if (!eth?.on) return;

    const handleAccountsChanged = (accounts: unknown) => {
      const arr = Array.isArray(accounts) ? (accounts as string[]) : [];
      const next = arr[0] ?? '';
      setWalletAddress(next);
      setListAddress((prev) => (prev.trim() ? prev : next));
      log(next ? 'Account changed' : 'Wallet disconnected');
    };

    const handleChainChanged = () => {
      (async () => {
        try {
          const provider = new BrowserProvider(eth);
          const network = await provider.getNetwork();
          setConnectedChainId(Number(network.chainId));
          log('Chain changed');
        } catch {
          // ignore
        }
      })();
    };

    eth.on('accountsChanged', handleAccountsChanged);
    eth.on('chainChanged', handleChainChanged);

    return () => {
      eth.removeListener?.('accountsChanged', handleAccountsChanged);
      eth.removeListener?.('chainChanged', handleChainChanged);
    };
  }, []);

  // --- 1. Wallet Connection ---
  const connectWallet = async () => {
    const eth = window.ethereum;
    if (!eth) {
      alert('Please install MetaMask');
      return;
    }
    try {
      const provider = new BrowserProvider(eth);
      const signer = await provider.getSigner();
      const address = await signer.getAddress();
      setWalletAddress(address);
      setListAddress((prev) => (prev.trim() ? prev : address));
      const network = await provider.getNetwork();
      setConnectedChainId(Number(network.chainId));
      log('Wallet connected');
    } catch (error) {
      console.error(error);
      log('Error connecting wallet');
    }
  };

  const clearWallet = () => {
    setWalletAddress('');
    setConnectedChainId(null);
    log('Cleared local wallet session');
  };

  // --- 2. Camera Logic ---
  const startCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      if (videoPreviewRef.current) {
        videoPreviewRef.current.srcObject = stream;
      }
      return stream;
    } catch {
      log('Camera access denied');
      return null;
    }
  };

  const startRecording = async () => {
    const stream = await startCamera();
    if (!stream) return;

    chunksRef.current = [];
    const recorder = new MediaRecorder(stream);

    recorder.ondataavailable = (e) => {
      if (e.data.size > 0) chunksRef.current.push(e.data);
    };

    recorder.onstop = () => {
      const blob = new Blob(chunksRef.current, { type: 'video/webm' });
      setVideoBlob(blob);
      log(`Recording finished. Size: ${(blob.size / 1024 / 1024).toFixed(2)} MB`);

      // Stop all tracks to turn off camera light
      stream.getTracks().forEach((track) => track.stop());
    };

    mediaRecorderRef.current = recorder;
    recorder.start();
    setIsRecording(true);
    setStatus('Recording...');
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
      setStatus('Review Video');
    }
  };

  // --- 3. IPFS Upload ---
  const uploadToIPFS = async (blob: Blob): Promise<string> => {
    setStatus('Uploading to IPFS...');
    if (PUBLIC_CONFIG.ipfsUploadEnabled) {
      const formData = new FormData();
      formData.append('file', blob, 'capture.webm');

      const res = await fetch('/api/ipfs', { method: 'POST', body: formData });
      const json = (await res.json()) as {
        cid?: string;
        error?: string;
        status?: number;
        details?: string;
      };

      if (!res.ok || !json.cid) {
        const messageParts = [
          json?.error ? `IPFS upload failed: ${json.error}` : 'IPFS upload failed',
          typeof json?.status === 'number' ? `pinata_status=${json.status}` : undefined,
          json?.details ? `details=${json.details}` : undefined,
        ].filter(Boolean);
        const message = messageParts.join(' | ');
        log(message);
        throw new Error(message);
      }

      log(`Uploaded to IPFS. CID: ${json.cid}`);
      return json.cid;
    }

    // MOCK DELAY & RETURN (demo mode)
    await new Promise((r) => setTimeout(r, 800));
    const mockCid = 'QmXyZ' + Math.random().toString(36).substring(7);
    log(`Mock IPFS upload. CID: ${mockCid}`);
    return mockCid;
  };

  // --- 4. Hashing Utility ---
  const hashContent = async (blob: Blob): Promise<string> => {
    const arrayBuffer = await blob.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = '0x' + hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    return hashHex; // bytes32 hex
  };

  // --- 5. Blockchain Interaction (New Contract) ---
  const registerOnChain = async () => {
    if (!videoBlob || !walletAddress) return;
    if (!contractAddress) {
      setStatus('Missing config');
      log('Missing NEXT_PUBLIC_CONTRACT_ADDRESS (or invalid address).');
      return;
    }
    if (chainMismatch) {
      setStatus('Wrong network');
      log(`Wrong network: connected ${connectedChainId}, required ${requiredChainId}`);
      return;
    }

    const cam = cameraId.trim();
    if (cam.length === 0 || cam.length > 32) {
      setStatus('Invalid cameraId');
      log('cameraId must be 1–32 chars.');
      return;
    }

    try {
      setStatus('Hashing & Signing (EIP-712)...');

      const { contract, chainId, signerAddress } = await getWriteContract();

      // A. Prepare Data
      const contentHash = await hashContent(videoBlob);
      const cid = await uploadToIPFS(videoBlob);
      const merkleRoot = ethers.keccak256(contentHash);
      const originalTimestamp = BigInt(Math.floor(Date.now() / 1000));

      if (!isBytes32(contentHash)) throw new Error('Computed contentHash is not bytes32.');
      if (!isBytes32(merkleRoot)) throw new Error('Computed merkleRoot is not bytes32.');

      const last = (await contract.lastSequence(signerAddress)) as bigint;
      const sequence = last + BigInt(1);

      log(`Hash generated: ${contentHash.slice(0, 10)}...`);
      log(`Sequence: ${sequence.toString()}`);

      // B. EIP-712 Typed Data Signature
      const domain = {
        name: PUBLIC_CONFIG.contractName,
        version: PUBLIC_CONFIG.contractVersion,
        chainId,
        verifyingContract: contractAddress,
      };

      const types = {
        Video: [
          { name: 'contentHash', type: 'bytes32' },
          { name: 'merkleRoot', type: 'bytes32' },
          { name: 'originalTimestamp', type: 'uint256' },
          { name: 'sequence', type: 'uint64' },
          { name: 'cameraId', type: 'string' },
          { name: 'cid', type: 'string' },
        ],
      };

      const value = {
        contentHash,
        merkleRoot,
        originalTimestamp,
        sequence,
        cameraId: cam,
        cid,
      };

      const signer = await (await getProvider()).getSigner();
      const signature = await signer.signTypedData(domain, types, value);
      log('EIP-712 signature created off-chain.');

      // C. Submit Transaction
      setStatus('Submitting to Blockchain...');
      const tx = await contract.registerVideoSigned({
        ...value,
        signature,
      });

      log(`Tx sent: ${(tx as { hash?: string }).hash ?? '(hash unavailable)'}`);
      await tx.wait();
      setStatus('Success! Video Registered.');
      log('Transaction confirmed on-chain.');

      // Convenience: auto-fill lookup with the new content hash
      setLookupHash(contentHash);
    } catch (error: unknown) {
      console.error(error);
      setStatus('Error');
      log(`Error: ${getErrorMessage(error)}`);
    }
  };

  const lookupOnChain = async () => {
    setLookupError('');
    setLookupResult(null);

    const h = lookupHash.trim();
    if (!isBytes32(h)) {
      setLookupError('Enter a valid bytes32 hash (0x + 64 hex chars).');
      return;
    }
    if (!contractAddress) {
      setLookupError('Missing NEXT_PUBLIC_CONTRACT_ADDRESS.');
      return;
    }

    setLookupLoading(true);
    try {
      const { contract } = await getReadContract();
      const v = await contract.getVideo(h);
      const normalized = normalizeVideo(v);
      setLookupResult(normalized);
      log(`Fetched video for hash ${h.slice(0, 10)}...`);
    } catch (e: unknown) {
      setLookupError(getErrorMessage(e));
      log(`Lookup failed: ${getErrorMessage(e)}`);
    } finally {
      setLookupLoading(false);
    }
  };

  const listForAddress = async (opts?: { offset?: number; limit?: number }) => {
    setListError('');

    const a = (listAddress || '').trim();
    if (!ethers.isAddress(a)) {
      setListError('Enter a valid wallet address.');
      return;
    }
    if (!contractAddress) {
      setListError('Missing NEXT_PUBLIC_CONTRACT_ADDRESS.');
      return;
    }

    const nextOffset = Math.max(0, opts?.offset ?? listOffset);
    const nextLimit = Math.max(1, Math.min(50, opts?.limit ?? listLimit));

    setListLoading(true);
    try {
      const { contract } = await getReadContract();
      const [page, total] = (await contract.getVideosByUploader(a, nextOffset, nextLimit)) as [unknown[], bigint];
      const videos = Array.isArray(page) ? page.map(normalizeVideo) : [];
      setListResults(videos);
      setListTotal(toSafeNumber(total));
      setListOffset(nextOffset);
      setListLimit(nextLimit);
      log(`Fetched ${videos.length} videos for ${a.slice(0, 6)}...`);
    } catch (e: unknown) {
      setListError(getErrorMessage(e));
      log(`List failed: ${getErrorMessage(e)}`);
    } finally {
      setListLoading(false);
    }
  };

  // --- UI Render ---
  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-200 p-8 font-mono">
      <div className="max-w-2xl mx-auto space-y-6">
        {/* Header */}
        <header className="flex justify-between items-center border-b border-neutral-800 pb-4">
          <h1 className="text-xl font-bold tracking-tighter text-emerald-500">
            497 PROJECT <span className="text-neutral-500 text-sm font-normal">{'// '}PROVENANCE</span>
          </h1>
          {!walletAddress ? (
            <button
              onClick={connectWallet}
              className="bg-neutral-800 hover:bg-neutral-700 px-4 py-2 text-xs rounded transition"
            >
              Connect Wallet
            </button>
          ) : (
            <div className="flex items-center gap-3">
              <span className="text-xs text-neutral-500 font-mono">
                {walletAddress.slice(0, 6)}...{walletAddress.slice(-4)}
                {connectedChainId !== null && <span className="ml-2 text-neutral-600">chain {connectedChainId}</span>}
              </span>
              <button
                onClick={clearWallet}
                className="text-xs text-neutral-400 hover:text-neutral-200 transition"
                title="Clear local session"
                type="button"
              >
                Disconnect
              </button>
            </div>
          )}
        </header>

        {chainMismatch && (
          <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
            Wrong network: connected chain <span className="font-mono">{connectedChainId}</span>, required{' '}
            <span className="font-mono">{requiredChainId}</span>.
            <div className="mt-2">
              <button
                type="button"
                onClick={switchToRequiredNetwork}
                className="rounded bg-red-500/20 px-3 py-1 text-xs text-red-100 hover:bg-red-500/30 transition"
              >
                Switch Network
              </button>
            </div>
          </div>
        )}

        {!contractAddress && (
          <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
            Missing config: set <span className="font-mono">NEXT_PUBLIC_CONTRACT_ADDRESS</span> to enable on-chain
            reads/writes.
          </div>
        )}

        {/* Register Config */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-950/40 p-4">
          <div className="text-xs text-neutral-500 mb-3">Registration settings (new contract)</div>
          <div className="grid grid-cols-1 gap-3">
            <label className="text-xs text-neutral-400">
              cameraId (1–32 chars)
              <input
                value={cameraId}
                onChange={(e) => setCameraId(e.target.value)}
                className="mt-1 w-full rounded bg-neutral-900 border border-neutral-800 px-3 py-2 text-xs text-neutral-100 outline-none focus:border-emerald-600"
                placeholder="cam-1"
              />
            </label>
            <div className="text-[11px] text-neutral-500">
              EIP-712 domain: <span className="text-neutral-300">{PUBLIC_CONFIG.contractName}</span>@
              <span className="text-neutral-300">{PUBLIC_CONFIG.contractVersion}</span>
            </div>
          </div>
        </div>

        {/* Video Stage */}
        <div className="relative aspect-video bg-black rounded-lg overflow-hidden border border-neutral-800 shadow-2xl">
          {(!videoBlob || isRecording) && (
            <video ref={videoPreviewRef} autoPlay muted className="w-full h-full object-cover" />
          )}
          {videoBlob && !isRecording && (
            <video src={URL.createObjectURL(videoBlob)} controls className="w-full h-full object-cover" />
          )}

          {/* Status Overlay */}
          <div className="absolute top-4 left-4">
            <div className="flex items-center gap-2 px-3 py-1 bg-black/50 backdrop-blur rounded-full text-xs border border-white/10">
              <div
                className={`w-2 h-2 rounded-full ${isRecording ? 'bg-red-500 animate-pulse' : 'bg-emerald-500'}`}
              />
              {status}
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="grid grid-cols-2 gap-4">
          {!isRecording && !videoBlob && (
            <button
              onClick={startRecording}
              className="col-span-2 bg-neutral-100 text-black py-3 rounded font-medium hover:bg-white transition"
            >
              Start Stream
            </button>
          )}

          {isRecording && (
            <button
              onClick={stopRecording}
              className="col-span-2 bg-red-500 text-white py-3 rounded font-medium hover:bg-red-600 transition"
            >
              Stop Recording
            </button>
          )}

          {videoBlob && !isRecording && (
            <>
              <button
                onClick={() => {
                  setVideoBlob(null);
                  setStatus('Ready');
                }}
                className="bg-neutral-800 py-3 rounded hover:bg-neutral-700 transition"
              >
                Retake
              </button>
              <button
                onClick={registerOnChain}
                disabled={!walletAddress || !contractAddress || chainMismatch}
                className="bg-emerald-600 text-white py-3 rounded hover:bg-emerald-500 transition disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Sign & Register
              </button>
            </>
          )}
        </div>

        {/* Lookup by hash */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-950/40 p-4 space-y-3">
          <div className="text-xs text-neutral-500">Get video from hash (on-chain lookup)</div>
          <div className="flex gap-2">
            <input
              value={lookupHash}
              onChange={(e) => setLookupHash(e.target.value)}
              className="flex-1 rounded bg-neutral-900 border border-neutral-800 px-3 py-2 text-xs text-neutral-100 outline-none focus:border-emerald-600"
              placeholder="0x… (bytes32 contentHash)"
            />
            <button
              type="button"
              onClick={lookupOnChain}
              disabled={!contractAddress || lookupLoading}
              className="rounded bg-neutral-800 px-3 py-2 text-xs hover:bg-neutral-700 transition disabled:opacity-50"
            >
              {lookupLoading ? 'Loading…' : 'Fetch'}
            </button>
          </div>
          {lookupError && <div className="text-xs text-red-300">{lookupError}</div>}
          {lookupResult && (
            <div className="rounded border border-neutral-800 bg-neutral-900/40 p-3 text-xs space-y-1">
              <div>
                <span className="text-neutral-500">uploader:</span> {lookupResult.uploader}
              </div>
              <div>
                <span className="text-neutral-500">cameraId:</span> {lookupResult.cameraId}
              </div>
              <div>
                <span className="text-neutral-500">sequence:</span> {lookupResult.sequence.toString()}
              </div>
              <div>
                <span className="text-neutral-500">createdAt:</span> {formatUnixSeconds(lookupResult.createdAt)}
              </div>
              <div>
                <span className="text-neutral-500">originalTimestamp:</span>{' '}
                {formatUnixSeconds(lookupResult.originalTimestamp)}
              </div>
              <div className="break-all">
                <span className="text-neutral-500">cid:</span> {lookupResult.cid}{' '}
                {lookupResult.cid && (
                  <a
                    className="ml-2 text-emerald-400 hover:text-emerald-300"
                    href={ipfsUrl(lookupResult.cid)}
                    target="_blank"
                    rel="noreferrer"
                  >
                    open
                  </a>
                )}
              </div>
            </div>
          )}
        </div>

        {/* List by uploader */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-950/40 p-4 space-y-3">
          <div className="text-xs text-neutral-500">Get all videos associated with wallet</div>

          <div className="grid grid-cols-1 gap-2">
            <input
              value={listAddress}
              onChange={(e) => setListAddress(e.target.value)}
              className="rounded bg-neutral-900 border border-neutral-800 px-3 py-2 text-xs text-neutral-100 outline-none focus:border-emerald-600"
              placeholder="0x… wallet address"
            />

            <div className="flex gap-2">
              <input
                value={String(listLimit)}
                onChange={(e) => setListLimit(Number(e.target.value || '10'))}
                className="w-24 rounded bg-neutral-900 border border-neutral-800 px-3 py-2 text-xs text-neutral-100 outline-none focus:border-emerald-600"
                placeholder="limit"
              />
              <button
                type="button"
                onClick={() => listForAddress({ offset: 0 })}
                disabled={!contractAddress || listLoading}
                className="rounded bg-neutral-800 px-3 py-2 text-xs hover:bg-neutral-700 transition disabled:opacity-50"
              >
                {listLoading ? 'Loading…' : 'Fetch'}
              </button>
              <div className="ml-auto text-xs text-neutral-500 self-center">
                total: <span className="text-neutral-200">{listTotal}</span>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={() => listForAddress({ offset: Math.max(0, listOffset - listLimit) })}
                disabled={listLoading || listOffset <= 0}
                className="rounded bg-neutral-800 px-3 py-1 text-xs hover:bg-neutral-700 transition disabled:opacity-50"
              >
                Prev
              </button>
              <div className="text-xs text-neutral-500">
                offset: <span className="text-neutral-200">{listOffset}</span>
              </div>
              <button
                type="button"
                onClick={() => listForAddress({ offset: listOffset + listLimit })}
                disabled={listLoading || listOffset + listLimit >= listTotal}
                className="rounded bg-neutral-800 px-3 py-1 text-xs hover:bg-neutral-700 transition disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>

          {listError && <div className="text-xs text-red-300">{listError}</div>}

          <div className="space-y-2">
            {listResults.map((v) => (
              <div key={v.contentHash} className="rounded border border-neutral-800 bg-neutral-900/40 p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-neutral-200">{v.cameraId || '—'}</div>
                  <div className="text-neutral-500">seq {v.sequence.toString()}</div>
                </div>
                <div className="mt-1 text-neutral-500">created {formatUnixSeconds(v.createdAt)}</div>
                <div className="mt-2 break-all">
                  <span className="text-neutral-500">hash:</span> {v.contentHash}
                  <button
                    type="button"
                    className="ml-2 text-emerald-400 hover:text-emerald-300"
                    onClick={() => {
                      setLookupHash(v.contentHash);
                      setLookupResult(v);
                      setLookupError('');
                    }}
                  >
                    use
                  </button>
                </div>
                <div className="mt-1 break-all">
                  <span className="text-neutral-500">cid:</span> {v.cid}{' '}
                  {v.cid && (
                    <a
                      className="ml-2 text-emerald-400 hover:text-emerald-300"
                      href={ipfsUrl(v.cid)}
                      target="_blank"
                      rel="noreferrer"
                    >
                      open
                    </a>
                  )}
                </div>
              </div>
            ))}

            {!listLoading && listResults.length === 0 && (
              <div className="text-xs text-neutral-600">No videos returned (or offset out of range).</div>
            )}
          </div>
        </div>

        {/* Terminal / Logs */}
        <div className="bg-neutral-900 rounded p-4 h-48 overflow-y-auto border border-neutral-800 text-xs font-mono">
          <div className="text-neutral-500 mb-2 border-b border-neutral-800 pb-1">System Logs</div>
          {logs.map((l, i) => (
            <div key={i} className="mb-1 text-emerald-400/80">
              {l}
            </div>
          ))}
          {logs.length === 0 && <span className="text-neutral-600">Waiting for input...</span>}
        </div>
      </div>
    </main>
  );
}
