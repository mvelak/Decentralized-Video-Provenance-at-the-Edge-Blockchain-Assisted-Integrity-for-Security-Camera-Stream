'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  };
}

export default function Page() {
  // --- State ---
  const [isRecording, setIsRecording] = useState(false);
  const [videoBlob, setVideoBlob] = useState<Blob | null>(null);
  const [walletAddress, setWalletAddress] = useState<string>('');
  const [connectedChainId, setConnectedChainId] = useState<ChainId | null>(null);
  const [status, setStatus] = useState<string>('Ready');
  const [logs, setLogs] = useState<string[]>([]);
  const [pushInProgress, setPushInProgress] = useState<boolean>(false);
  const [segmentSeconds, setSegmentSeconds] = useState<number>(30);
  const [qualityPreset, setQualityPreset] = useState<'high' | 'medium' | 'low' | 'potato'>('low');
  const [queueSize, setQueueSize] = useState<number>(0);
  const [lastRecordedUploader, setLastRecordedUploader] = useState<string>('');

  // Lookup + listing
  const [lookupHash, setLookupHash] = useState<string>('');
  const [lookupResult, setLookupResult] = useState<ContractVideo | null>(null);
  const [lookupError, setLookupError] = useState<string>('');
  const [lookupLoading, setLookupLoading] = useState<boolean>(false);

  const [listAddress, setListAddress] = useState<string>('');
  const [listOffset, setListOffset] = useState<number>(0);
  const [listLimit] = useState<number>(5); // Max 5 videos per page
  const [listTotal, setListTotal] = useState<number>(0);
  const [listResults, setListResults] = useState<ContractVideo[]>([]);
  const [listError, setListError] = useState<string>('');
  const [listLoading, setListLoading] = useState<boolean>(false);

  // Verification state
  const [verifyFile, setVerifyFile] = useState<File | null>(null);
  const [verifyLoading, setVerifyLoading] = useState<boolean>(false);
  const [verifyResult, setVerifyResult] = useState<{
    hash: string;
    found: boolean;
    video?: ContractVideo;
  } | null>(null);
  const [verifyError, setVerifyError] = useState<string>('');

  const addr = PUBLIC_CONFIG.contractAddress;
  const contractAddress = useMemo(() => {
    return ethers.isAddress(addr) ? ethers.getAddress(addr) : '';
  }, [addr]);

  // --- Refs ---
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const videoPreviewRef = useRef<HTMLVideoElement>(null);
  const pushJobIdRef = useRef<number>(0);
  const requestedNetworkSwitchRef = useRef<boolean>(false);
  const streamRef = useRef<MediaStream | null>(null);
  const segmentQueueRef = useRef<Array<{ blob: Blob; originalTimestamp: bigint }>>([]);

  // --- Helpers ---
  const log = useCallback(
    (msg: string) => setLogs((prev) => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]),
    []
  );

  const requiredChainId = PUBLIC_CONFIG.chainId;
  const chainMismatch =
    requiredChainId !== undefined && connectedChainId !== null && connectedChainId !== requiredChainId;

  const getRecorderMimeType = useCallback((): string | undefined => {
    const candidates = ['video/webm;codecs=vp9', 'video/webm;codecs=vp8', 'video/webm'];
    for (const c of candidates) {
      try {
        if (typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported(c)) return c;
      } catch {
        // ignore
      }
    }
    return undefined;
  }, []);

  const getCaptureSettings = useCallback(() => {
    switch (qualityPreset) {
      case 'high':
        return {
          constraints: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30, max: 30 } },
          videoBitsPerSecond: 2_500_000,
        };
      case 'medium':
        return {
          constraints: { width: { ideal: 854 }, height: { ideal: 480 }, frameRate: { ideal: 24, max: 24 } },
          videoBitsPerSecond: 1_000_000,
        };
      case 'low':
        return {
          constraints: { width: { ideal: 640 }, height: { ideal: 360 }, frameRate: { ideal: 15, max: 15 } },
          videoBitsPerSecond: 450_000,
        };
      case 'potato':
        return {
          constraints: { width: { ideal: 320 }, height: { ideal: 240 }, frameRate: { ideal: 10, max: 12 } },
          videoBitsPerSecond: 180_000,
        };
    }
  }, [qualityPreset]);

  const getProvider = useCallback((): BrowserProvider => {
    const eth = window.ethereum;
    if (!eth) throw new Error('Please install MetaMask (or another injected wallet).');
    return new BrowserProvider(eth);
  }, []);

  const getReadContract = useCallback(async (): Promise<{ provider: BrowserProvider; contract: Contract; chainId: ChainId }> => {
    if (!contractAddress) throw new Error('Missing NEXT_PUBLIC_CONTRACT_ADDRESS (or invalid address).');
    const provider = getProvider();
    const network = await provider.getNetwork();
    const chainId = Number(network.chainId);
    const contract = new Contract(contractAddress, ABI, provider);
    return { provider, contract, chainId };
  }, [contractAddress, getProvider]);

  const getWriteContract = useCallback(async (): Promise<{
    provider: BrowserProvider;
    contract: Contract;
    chainId: ChainId;
    signer: Awaited<ReturnType<BrowserProvider['getSigner']>>;
    signerAddress: string;
  }> => {
    if (!contractAddress) throw new Error('Missing NEXT_PUBLIC_CONTRACT_ADDRESS (or invalid address).');
    const provider = getProvider();
    const network = await provider.getNetwork();
    const chainId = Number(network.chainId);
    const signer =
      walletAddress && ethers.isAddress(walletAddress) ? await provider.getSigner(walletAddress) : await provider.getSigner();
    const signerAddress = await signer.getAddress();
    const contract = new Contract(contractAddress, ABI, signer);
    return { provider, contract, chainId, signer, signerAddress };
  }, [contractAddress, getProvider, walletAddress]);

  const switchToRequiredNetwork = useCallback(async () => {
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
  }, [log, requiredChainId]);

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
  }, [log]);

  // --- 1. Wallet Connection ---
  const connectWallet = async () => {
    const eth = window.ethereum;
    if (!eth) {
      alert('Please install MetaMask');
      return;
    }
    try {
      // Ensure the wallet authorizes accounts for this site.
      await eth.request?.({ method: 'eth_requestAccounts' });
      const provider = new BrowserProvider(eth);
      const accounts = await provider.listAccounts();
      const first = accounts[0]?.address ?? '';
      const signer = first && ethers.isAddress(first) ? await provider.getSigner(first) : await provider.getSigner();
      const address = await signer.getAddress();
      setWalletAddress(ethers.getAddress(address));
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
      const { constraints } = getCaptureSettings();
      const stream = await navigator.mediaDevices.getUserMedia({ video: constraints, audio: false });
      if (videoPreviewRef.current) {
        videoPreviewRef.current.srcObject = stream;
      }
      streamRef.current = stream;
      return stream;
    } catch {
      log('Camera access denied');
      return null;
    }
  };

  const enqueueSegment = useCallback((blob: Blob, originalTimestamp: bigint) => {
    segmentQueueRef.current.push({ blob, originalTimestamp });
    setQueueSize(segmentQueueRef.current.length);
  }, []);

  const startRecording = async () => {
    const stream = await startCamera();
    if (!stream) return;

    // reset queue for the new session
    segmentQueueRef.current = [];
    setQueueSize(0);
    requestedNetworkSwitchRef.current = false;

    const mimeType = getRecorderMimeType();
    const { videoBitsPerSecond } = getCaptureSettings();
    const recorder = new MediaRecorder(stream, {
      ...(mimeType ? { mimeType } : {}),
      videoBitsPerSecond,
    });

    recorder.ondataavailable = (e) => {
      if (e.data.size <= 0) return;
      const blob = e.data;
      setVideoBlob(blob); // keep last segment for preview/retry
      enqueueSegment(blob, BigInt(Math.floor(Date.now() / 1000)));
      log(`Segment ready: ${(blob.size / 1024 / 1024).toFixed(2)} MB (queued=${segmentQueueRef.current.length})`);
    };

    recorder.onstop = () => {
      // Stop all tracks to turn off camera light
      streamRef.current?.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
      setStatus('Stopped');
      log('Recording stopped.');
    };

    mediaRecorderRef.current = recorder;
    const timesliceMs = Math.max(5_000, Math.min(300_000, Math.floor(segmentSeconds * 1000)));
    recorder.start(timesliceMs);
    setIsRecording(true);
    setStatus(`Recording & uploading every ~${Math.round(timesliceMs / 1000)}s…`);
    log(
      `Recorder started (timeslice=${timesliceMs}ms, bitrate=${videoBitsPerSecond}, mime=${mimeType ?? 'default'})`
    );
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      try {
        mediaRecorderRef.current.requestData(); // flush final segment
      } catch {
        // ignore
      }
      mediaRecorderRef.current.stop();
      setIsRecording(false);
      setStatus('Stopping…');
    }
  };

  // --- 3. IPFS Upload ---
  const uploadToIPFS = useCallback(async (blob: Blob): Promise<string> => {
    setStatus('Uploading to IPFS...');
    if (PUBLIC_CONFIG.ipfsUploadEnabled) {
      const formData = new FormData();
      formData.append('file', blob, `capture-${Date.now()}.webm`);

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
  }, [log]);

  // --- 4. Hashing Utility ---
  const hashContent = useCallback(async (blob: Blob): Promise<string> => {
    const arrayBuffer = await blob.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = '0x' + hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    return hashHex; // bytes32 hex
  }, []);

  // --- 4.5. List videos by address ---
  const listForAddress = useCallback(async (opts?: { offset?: number; limit?: number; address?: string }) => {
    setListError('');

    const a = (opts?.address || listAddress || '').trim();
    if (!ethers.isAddress(a)) {
      setListError('Enter a valid wallet address.');
      return;
    }
    if (!contractAddress) {
      setListError('Missing NEXT_PUBLIC_CONTRACT_ADDRESS.');
      return;
    }

    const uploader = ethers.getAddress(a);
    const nextLimit = Math.max(1, Math.min(50, opts?.limit ?? listLimit));

    setListLoading(true);
    try {
      const { provider, contract, chainId } = await getReadContract();

      const code = await provider.getCode(contractAddress);
      if (!code || code === '0x') {
        throw new Error(`No contract deployed at ${contractAddress} on chain ${chainId}. Check network/contract address.`);
      }

      // The requested offset is the "page offset" from the user's perspective (0, 5, 10, etc.)
      const requestedOffset = opts?.offset ?? listOffset;
      
      // First call to get total count (fetch with offset=0, limit=0 to just get total)
      const totalRes = (await contract.getVideosByUploader(
        uploader,
        BigInt(0),
        BigInt(0)
      )) as unknown as { 0: unknown; 1: unknown; page?: unknown; total?: unknown };
      
      const totalRaw = (totalRes.total ?? totalRes[1]) as unknown;
      const total =
        typeof totalRaw === 'bigint'
          ? totalRaw
          : typeof (totalRaw as { toString?: unknown })?.toString === 'function'
            ? BigInt(String((totalRaw as { toString: () => string }).toString()))
            : BigInt(0);
      
      const totalNum = toSafeNumber(total);
      
      if (totalNum === 0) {
        setListResults([]);
        setListTotal(0);
        setListOffset(0);
        log(`No videos found for ${uploader.slice(0, 6)}...`);
        return;
      }

      // Calculate how many videos to actually fetch
      const remainingVideos = Math.max(0, totalNum - requestedOffset);
      const videosToFetch = Math.min(nextLimit, remainingVideos);
      
      // Calculate actual offset from the end for newest-first display
      // To show newest first, we need to fetch from the end
      // Example: total=6, requestedOffset=0, limit=5
      //   We want indices [5,4,3,2,1] reversed = videos [6,5,4,3,2]
      //   actualOffset = 6 - 5 = 1, limit=5 -> indices [1,2,3,4,5] -> reverse to [5,4,3,2,1]
      // Example: total=6, requestedOffset=5, limit=5
      //   We want index [0] = video [1]
      //   remainingVideos = 6-5 = 1, videosToFetch = min(5,1) = 1
      //   actualOffset = 6 - 5 - 1 = 0, limit=1 -> index [0] -> reverse to [0]
      const actualOffset = totalNum - requestedOffset - videosToFetch;

      const res = (await contract.getVideosByUploader(
        uploader,
        BigInt(actualOffset),
        BigInt(videosToFetch)
      )) as unknown as { 0: unknown; 1: unknown; page?: unknown; total?: unknown };

      const page = (res.page ?? res[0]) as unknown;
      const videos = Array.isArray(page) ? page.map(normalizeVideo) : [];

      // Reverse so newest appears first
      const reversedVideos = [...videos].reverse();

      setListResults(reversedVideos);
      setListTotal(totalNum);
      setListOffset(requestedOffset);
      log(`Fetched ${reversedVideos.length} videos for ${uploader.slice(0, 6)}... (offset=${actualOffset}, showing ${requestedOffset+1}-${requestedOffset+reversedVideos.length} of ${totalNum})`);
    } catch (e: unknown) {
      setListError(getErrorMessage(e));
      log(`List failed: ${getErrorMessage(e)}`);
    } finally {
      setListLoading(false);
    }
  }, [contractAddress, getReadContract, listAddress, listLimit, listOffset, log]);

  // --- 5. Blockchain Interaction (New Contract) ---
  const registerOnChain = useCallback(async (blob: Blob, originalTimestamp: bigint) => {
    if (!contractAddress) {
      setStatus('Missing config');
      log('Missing NEXT_PUBLIC_CONTRACT_ADDRESS (or invalid address).');
      return;
    }
    if (!walletAddress) {
      setStatus('Connect wallet');
      log('Connect wallet to sign and register.');
      return;
    }
    if (chainMismatch) {
      setStatus('Wrong network');
      log(`Wrong network: connected ${connectedChainId}, required ${requiredChainId}`);
      return;
    }

    // Declare variables at function scope for error handling
    let contentHash = '';
    let cid = '';
    
    try {
      // Prevent double-submit / stale async updates
      setPushInProgress(true);
      const myJobId = ++pushJobIdRef.current;

      setStatus('Preparing data...');

      const { provider, contract, chainId, signer, signerAddress } = await getWriteContract();

      // Sanity check: ensure there is contract code at this address on this chain.
      const code = await provider.getCode(contractAddress);
      if (!code || code === '0x') {
        throw new Error(`No contract deployed at ${contractAddress} on chain ${chainId}. Check network/contract address.`);
      }

      // A. Prepare Data - hash and get sequence in parallel
      setStatus('Hashing content...');
      const [hashResult, lastSeq] = await Promise.all([
        hashContent(blob),
        contract.lastSequence(signerAddress) as Promise<bigint>
      ]);
      
      contentHash = hashResult;
      const merkleRoot = ethers.keccak256(contentHash);
      const sequence = lastSeq + BigInt(1);

      if (!isBytes32(contentHash)) throw new Error('Computed contentHash is not bytes32.');
      if (!isBytes32(merkleRoot)) throw new Error('Computed merkleRoot is not bytes32.');

      log(`Hash generated: ${contentHash.slice(0, 10)}...`);
      log(`Sequence: ${sequence.toString()}`);

      // B. Upload to IPFS (this is the slow part)
      cid = await uploadToIPFS(blob);

      // C. EIP-712 Typed Data Signature
      setStatus('Awaiting signature...');
      log('Please sign in MetaMask to register this video.');
      
      const domain = {
        // Must match the contract's EIP-712 domain (see contract constructor).
        name: 'Veritas',
        version: '1',
        chainId,
        verifyingContract: contractAddress,
      };

      const types = {
        Video: [
          { name: 'contentHash', type: 'bytes32' },
          { name: 'merkleRoot', type: 'bytes32' },
          { name: 'originalTimestamp', type: 'uint256' },
          { name: 'sequence', type: 'uint64' },
          { name: 'cid', type: 'string' },
        ],
      };

      const value = {
        contentHash,
        merkleRoot,
        originalTimestamp,
        sequence,
        cid,
      };

      // Request signature from user
      let signature: string;
      try {
        signature = await signer.signTypedData(domain, types, value);
        log('✓ Signature received.');
      } catch (signError: unknown) {
        // Handle signature rejection gracefully
        const errorMsg = getErrorMessage(signError);
        const errorCode = (signError as { code?: number | string }).code;
        
        // Check for various rejection patterns
        const isRejection = 
          errorMsg.toLowerCase().includes('user rejected') ||
          errorMsg.toLowerCase().includes('user denied') ||
          errorMsg.toLowerCase().includes('user cancelled') ||
          errorMsg.toLowerCase().includes('user disapproved') ||
          errorMsg.toLowerCase().includes('rejected') ||
          errorCode === 4001 || // MetaMask rejection
          errorCode === 'ACTION_REJECTED'; // Ethers.js rejection

        if (isRejection) {
          setStatus('Signature cancelled');
          log('⚠️ Signature request was cancelled.');
          log(`Video uploaded to IPFS: ${cid}`);
          log(`View at: https://ipfs.io/ipfs/${cid}`);
          log('💡 The video is NOT registered on-chain.');
          log('You can retry by clicking "Retry last segment" or record again.');
          return; // Exit gracefully without throwing
        }
        
        // Handle other signature errors (connection issues, etc.)
        setStatus('Signature failed');
        log(`❌ Signature error: ${errorMsg}`);
        log(`Video uploaded to IPFS: ${cid}`);
        log(`View at: https://ipfs.io/ipfs/${cid}`);
        return; // Exit gracefully
      }

      // D. Submit via Relayer or Direct
      setStatus('Submitting to blockchain...');
      
      let txHash: string;
      let receipt: unknown;

      if (PUBLIC_CONFIG.relayerEnabled) {
        // Relayer pattern: POST to API, relayer submits transaction
        log('Sending to relayer...');
        const relayerRes = await fetch('/api/relayer', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contentHash,
            merkleRoot,
            originalTimestamp: originalTimestamp.toString(),
            sequence: sequence.toString(),
            cid,
            signature,
          }),
        });

        const relayerData = await relayerRes.json();
        if (!relayerRes.ok) {
          throw new Error(relayerData.error || 'Relayer submission failed');
        }

        txHash = relayerData.txHash;
        log(`✓ Transaction submitted: ${txHash.slice(0, 10)}...`);
        log(`Relayer: ${relayerData.relayer ? relayerData.relayer.slice(0, 6) + '...' : 'unknown'}`);

        // Wait for transaction confirmation using provider
        setStatus('Waiting for confirmation...');
        log('Waiting for blockchain confirmation...');
        receipt = await provider.waitForTransaction(txHash);
      } else {
        // Direct submission: User's wallet submits transaction
        log('Submitting transaction...');
        const tx = await contract.registerVideoSigned({
          ...value,
          signature,
        });
        txHash = (tx as { hash?: string }).hash ?? '(hash unavailable)';
        log(`✓ Transaction submitted: ${txHash.slice(0, 10)}...`);
        
        setStatus('Waiting for confirmation...');
        log('Waiting for blockchain confirmation...');
        receipt = await tx.wait();
      }

      if (pushJobIdRef.current !== myJobId) return; // stale job; ignore UI updates

      // Verify state moved for this uploader (helps debug “confirmed but no data” cases).
      try {
        const nextLast = (await contract.lastSequence(signerAddress)) as bigint;
        log(`Post-tx lastSequence(${signerAddress.slice(0, 6)}...)= ${nextLast.toString()}`);
      } catch (e: unknown) {
        log(`Post-tx lastSequence check failed: ${getErrorMessage(e)}`);
      }

      // Parse VideoRegistered event (proves what uploader the contract stored under).
      try {
        const logs = Array.isArray((receipt as { logs?: unknown }).logs) ? ((receipt as { logs: unknown[] }).logs as unknown[]) : [];
        for (const l of logs) {
          const logObj = l as { address?: unknown; topics?: unknown; data?: unknown };
          if (String(logObj.address ?? '').toLowerCase() !== contractAddress.toLowerCase()) continue;
          try {
            type ParsedLog = { name?: string; args?: { uploader?: unknown; sequence?: unknown; contentHash?: unknown } };
            const parsed = (contract as unknown as { interface: { parseLog: (x: unknown) => ParsedLog } }).interface.parseLog(l);
            if (parsed?.name === 'VideoRegistered') {
              const uploaderFromEvent = String(parsed?.args?.uploader ?? '');
              const seqFromEvent = parsed?.args?.sequence;
              const hashFromEvent = String(parsed?.args?.contentHash ?? '');
              if (ethers.isAddress(uploaderFromEvent)) {
                const normalized = ethers.getAddress(uploaderFromEvent);
                setLastRecordedUploader(normalized);
                // If user is currently listing by the connected wallet and getting 0, this helps.
                setListAddress((prev) => (prev.trim() ? prev : normalized));
              }
              log(
                `Event VideoRegistered uploader=${uploaderFromEvent.slice(0, 6)}... seq=${String(seqFromEvent)} hash=${hashFromEvent.slice(
                  0,
                  10
                )}...`
              );
              break;
            }
          } catch {
            // ignore non-matching logs
          }
        }
      } catch (e: unknown) {
        log(`Event parse failed: ${getErrorMessage(e)}`);
      }

      // Immediate read-backs: getVideo + getVideosByUploader (helps isolate buggy list vs missing writes).
      try {
        const stored = await contract.getVideo(contentHash);
        const nv = normalizeVideo(stored);
        if (ethers.isAddress(nv.uploader)) {
          const normalized = ethers.getAddress(nv.uploader);
          setLastRecordedUploader(normalized);
          setListAddress((prev) => (prev.trim() ? prev : normalized));
        }
        log(`Read-back getVideo uploader=${nv.uploader.slice(0, 6)}... seq=${nv.sequence.toString()} cid=${nv.cid ? 'yes' : 'no'}`);

        const uploaderKey = nv.uploader && ethers.isAddress(nv.uploader) ? ethers.getAddress(nv.uploader) : signerAddress;
        const res2 = (await contract.getVideosByUploader(uploaderKey, BigInt(0), BigInt(5))) as unknown as {
          0: unknown;
          1: unknown;
          page?: unknown;
          total?: unknown;
        };
        const page2 = (res2.page ?? res2[0]) as unknown;
        const total2Raw = (res2.total ?? res2[1]) as unknown;
        const total2 =
          typeof total2Raw === 'bigint'
            ? total2Raw
            : typeof (total2Raw as { toString?: unknown })?.toString === 'function'
              ? BigInt(String((total2Raw as { toString: () => string }).toString()))
              : BigInt(0);
        log(`Read-back getVideosByUploader(${uploaderKey.slice(0, 6)}...) pageLen=${Array.isArray(page2) ? page2.length : -1} total=${total2.toString()}`);
      } catch (e: unknown) {
        log(`Read-back checks failed: ${getErrorMessage(e)}`);
      }

      setStatus('✓ Video registered successfully');
      log('✓ Transaction confirmed on-chain.');
      log(`View on IPFS: https://ipfs.io/ipfs/${cid}`);

      // Convenience: auto-fill lookup with the new content hash
      setLookupHash(contentHash);

      // Refresh video list if we're currently viewing videos for this uploader or connected wallet
      try {
        const uploaderToCheck = signerAddress && ethers.isAddress(signerAddress) ? ethers.getAddress(signerAddress) : null;
        const currentListAddr = listAddress && ethers.isAddress(listAddress) ? ethers.getAddress(listAddress) : null;
        const connectedWalletAddr = walletAddress && ethers.isAddress(walletAddress) ? ethers.getAddress(walletAddress) : null;
        
        // Refresh if viewing the uploader's videos or if the uploader is the connected wallet
        const shouldRefresh = uploaderToCheck && (
          (currentListAddr && uploaderToCheck.toLowerCase() === currentListAddr.toLowerCase()) ||
          (connectedWalletAddr && uploaderToCheck.toLowerCase() === connectedWalletAddr.toLowerCase())
        );
        
        if (shouldRefresh) {
          // Refresh the list for the uploader
          await listForAddress({ offset: 0, limit: listLimit, address: uploaderToCheck });
          log('Video list refreshed.');
        }
      } catch (refreshError) {
        // Don't fail the whole registration if refresh fails
        log(`List refresh failed: ${getErrorMessage(refreshError)}`);
      }
    } catch (error: unknown) {
      console.error(error);
      const errorMsg = getErrorMessage(error);
      
      // Provide context-aware error messages
      if (errorMsg.includes('IPFS')) {
        setStatus('IPFS upload failed');
        log(`❌ Error uploading to IPFS: ${errorMsg}`);
        log('Video was not uploaded or registered. Please try again.');
      } else if (errorMsg.includes('Relayer') || errorMsg.includes('relayer')) {
        setStatus('Relayer submission failed');
        log(`❌ Relayer error: ${errorMsg}`);
        log(`Video uploaded to IPFS (${cid || 'unknown'}), but not registered on-chain.`);
        log('The relayer may be down or out of gas. Contact administrator.');
      } else if (errorMsg.includes('insufficient funds') || errorMsg.includes('gas')) {
        setStatus('Insufficient gas');
        log(`❌ Gas error: ${errorMsg}`);
        log(PUBLIC_CONFIG.relayerEnabled 
          ? 'The relayer wallet needs more BNB for gas.'
          : 'Your wallet needs more BNB for gas fees.');
      } else {
        setStatus('Error');
        log(`❌ Error: ${errorMsg}`);
        log('An unexpected error occurred. Check console for details.');
      }
    } finally {
      setPushInProgress(false);
    }
  }, [
    chainMismatch,
    connectedChainId,
    contractAddress,
    getProvider,
    getWriteContract,
    hashContent,
    listAddress,
    listForAddress,
    listLimit,
    log,
    requiredChainId,
    uploadToIPFS,
    walletAddress,
  ]);

  const pushNextFromQueue = useCallback(async () => {
    const next = segmentQueueRef.current.shift();
    setQueueSize(segmentQueueRef.current.length);
    if (!next) return;
    await registerOnChain(next.blob, next.originalTimestamp);
  }, [registerOnChain]);

  // --- 6. Auto-push flow: continuously drain queued segments ---
  useEffect(() => {
    if (!contractAddress) return;
    if (pushInProgress) return;
    if (segmentQueueRef.current.length === 0) return;

    // If wallet isn't connected yet, pause queue processing.
    if (!walletAddress) {
      setStatus('Connect wallet to auto-upload');
      return;
    }

    // If wrong network, request switch once; keep queue pending.
    if (chainMismatch) {
      if (!requestedNetworkSwitchRef.current) {
        requestedNetworkSwitchRef.current = true;
        void switchToRequiredNetwork();
      }
      setStatus('Switch network to auto-upload');
      return;
    }

    requestedNetworkSwitchRef.current = false;
    void pushNextFromQueue();
  }, [chainMismatch, contractAddress, pushInProgress, pushNextFromQueue, queueSize, switchToRequiredNetwork, walletAddress]);

  // --- 7. Auto-fetch videos when wallet changes ---
  useEffect(() => {
    if (!walletAddress) {
      setListAddress('');
      setListResults([]);
      setListTotal(0);
      setListOffset(0);
      return;
    }
    
    setListAddress(walletAddress);
    
    // Auto-fetch videos for the connected wallet
    if (contractAddress && ethers.isAddress(walletAddress)) {
      void listForAddress({ offset: 0, limit: 5, address: walletAddress });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [walletAddress, contractAddress]);

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

  const verifyVideoFile = async () => {
    setVerifyError('');
    setVerifyResult(null);

    if (!verifyFile) {
      setVerifyError('Please select a video file.');
      return;
    }
    if (!contractAddress) {
      setVerifyError('Missing NEXT_PUBLIC_CONTRACT_ADDRESS.');
      return;
    }

    setVerifyLoading(true);
    try {
      log(`Hashing uploaded file: ${verifyFile.name} (${(verifyFile.size / 1024 / 1024).toFixed(2)} MB)`);
      
      // Hash the file
      const hash = await hashContent(verifyFile);
      log(`Computed hash: ${hash}`);

      // Look it up on-chain
      const { contract } = await getReadContract();
      
      try {
        const v = await contract.getVideo(hash);
        const normalized = normalizeVideo(v);

        // Check if video exists (uploader won't be zero address if it exists)
        const exists = normalized.uploader !== ethers.ZeroAddress;

        if (exists) {
          setVerifyResult({ hash, found: true, video: normalized });
          log(`Video found on-chain. Uploader: ${normalized.uploader.slice(0, 6)}...`);
        } else {
          setVerifyResult({ hash, found: false });
          log(`Video not found on-chain. Hash: ${hash}`);
        }
      } catch (contractError: unknown) {
        // Contract throws VideoNotFound() when video doesn't exist
        const errorMsg = getErrorMessage(contractError);
        if (errorMsg.includes('VideoNotFound') || errorMsg.includes('revert')) {
          setVerifyResult({ hash, found: false });
          log(`Video not found on-chain. Hash: ${hash}`);
        } else {
          throw contractError; // Re-throw unexpected errors
        }
      }
    } catch (e: unknown) {
      setVerifyError(getErrorMessage(e));
      log(`Verification failed: ${getErrorMessage(e)}`);
    } finally {
      setVerifyLoading(false);
    }
  };


  // --- UI Render ---
  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-200 p-8 font-mono">
      <div className="max-w-2xl mx-auto space-y-6">
        {/* Header */}
        <header className="flex justify-between items-center border-b border-neutral-800 pb-4">
          <h1 className="text-xl font-bold tracking-tighter text-emerald-500">
            Veritas <span className="text-neutral-500 text-sm font-normal">{'// '}DEMO</span>
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
              <div className="text-xs text-neutral-500 font-mono text-right">
                <div>
                  {PUBLIC_CONFIG.relayerEnabled ? 'Camera' : 'Wallet'}: {walletAddress.slice(0, 6)}...{walletAddress.slice(-4)}
                </div>
                {connectedChainId !== null && <div className="text-neutral-600">chain {connectedChainId}</div>}
                {PUBLIC_CONFIG.relayerEnabled && (
                  <div className="text-[10px] text-neutral-600 mt-0.5">
                    (sign only, relayer pays gas)
                  </div>
                )}
              </div>
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
            <div className="grid grid-cols-2 gap-3">
              <label className="text-xs text-neutral-400">
                segment length
                <select
                  value={String(segmentSeconds)}
                  onChange={(e) => setSegmentSeconds(Number(e.target.value))}
                  className="mt-1 w-full rounded bg-neutral-900 border border-neutral-800 px-3 py-2 pr-8 text-xs text-neutral-100 outline-none focus:border-emerald-600 appearance-none bg-[url('data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20fill%3D%22none%22%20viewBox%3D%220%200%2020%2020%22%3E%3Cpath%20stroke%3D%22%23a3a3a3%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%20stroke-width%3D%221.5%22%20d%3D%22M6%208l4%204%204-4%22%2F%3E%3C%2Fsvg%3E')] bg-[length:1rem] bg-[right_0.5rem_center] bg-no-repeat"
                  disabled={isRecording}
                >
                  <option value="15">15s</option>
                  <option value="30">30s</option>
                  <option value="60">60s</option>
                </select>
                <div className="mt-1 text-[11px] text-neutral-600">Applies on next start (disabled while recording).</div>
              </label>
              <label className="text-xs text-neutral-400">
                quality / compression
                <select
                  value={qualityPreset}
                  onChange={(e) => setQualityPreset(e.target.value as 'high' | 'medium' | 'low' | 'potato')}
                  className="mt-1 w-full rounded bg-neutral-900 border border-neutral-800 px-3 py-2 pr-8 text-xs text-neutral-100 outline-none focus:border-emerald-600 appearance-none bg-[url('data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20fill%3D%22none%22%20viewBox%3D%220%200%2020%2020%22%3E%3Cpath%20stroke%3D%22%23a3a3a3%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%20stroke-width%3D%221.5%22%20d%3D%22M6%208l4%204%204-4%22%2F%3E%3C%2Fsvg%3E')] bg-[length:1rem] bg-[right_0.5rem_center] bg-no-repeat"
                  disabled={isRecording}
                >
                  <option value="high">high (720p, ~2.5Mbps)</option>
                  <option value="medium">medium (480p, ~1Mbps)</option>
                  <option value="low">low (360p, ~450kbps)</option>
                  <option value="potato">potato (240p, ~180kbps)</option>
                </select>
                <div className="mt-1 text-[11px] text-neutral-600">Lower = smaller uploads + faster IPFS.</div>
              </label>
            </div>
            <div className="text-[11px] text-neutral-500">
              EIP-712 domain: <span className="text-neutral-300">{PUBLIC_CONFIG.contractName}</span>@
              <span className="text-neutral-300">{PUBLIC_CONFIG.contractVersion}</span>
              {PUBLIC_CONFIG.relayerEnabled && PUBLIC_CONFIG.relayerAddress && (
                <div className="mt-1">
                  Relayer: <span className="text-neutral-300 font-mono">{PUBLIC_CONFIG.relayerAddress.slice(0, 6)}...{PUBLIC_CONFIG.relayerAddress.slice(-4)}</span>
                </div>
              )}
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
            <>
              <button
                onClick={() => {
                  try {
                    mediaRecorderRef.current?.requestData();
                    log('Requested segment flush (upload ASAP).');
                  } catch {
                    // ignore
                  }
                }}
                className="bg-neutral-800 text-white py-3 rounded font-medium hover:bg-neutral-700 transition"
                type="button"
              >
                Upload Now
              </button>
              <button
                onClick={stopRecording}
                className="bg-red-500 text-white py-3 rounded font-medium hover:bg-red-600 transition"
                type="button"
              >
                Stop
              </button>
            </>
          )}

          {videoBlob && !isRecording && (
            <>
              <button
                onClick={() => {
                  setVideoBlob(null);
                  pushJobIdRef.current += 1; // invalidate any in-flight async job
                  segmentQueueRef.current = [];
                  setQueueSize(0);
                  setStatus('Ready');
                }}
                className="bg-neutral-800 py-3 rounded hover:bg-neutral-700 transition"
              >
                Clear
              </button>
              <button
                onClick={() => {
                  if (!videoBlob) return;
                  enqueueSegment(videoBlob, BigInt(Math.floor(Date.now() / 1000)));
                }}
                disabled={!contractAddress || chainMismatch}
                className="bg-emerald-600 text-white py-3 rounded hover:bg-emerald-500 transition disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Retry last segment
              </button>
            </>
          )}
        </div>

        <div className="rounded-lg border border-neutral-800 bg-neutral-950/40 p-4 text-xs">
          <div className="flex items-center justify-between">
            <div className="text-neutral-500">upload queue</div>
            <div className="text-neutral-400">
              queued: <span className="text-neutral-200">{queueSize}</span>
              {pushInProgress && <span className="ml-2 text-emerald-400">uploading…</span>}
            </div>
          </div>
          <div className="mt-2 text-[11px] text-neutral-600">
            The recorder emits a new segment about every {segmentSeconds}s while streaming.
          </div>
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
                <span className="text-neutral-500">uploader (camera):</span> {lookupResult.uploader}
              </div>
              <div>
                <span className="text-neutral-500">relayer (gas payer):</span> {lookupResult.relayer}
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

        {/* Verify Video File */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-950/40 p-4 space-y-3">
          <div className="text-xs text-neutral-500">Verify video integrity</div>
          
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <label className="flex-1">
                <input
                  type="file"
                  accept="video/*"
                  onChange={(e) => {
                    const file = e.target.files?.[0] || null;
                    setVerifyFile(file);
                    setVerifyResult(null);
                    setVerifyError('');
                  }}
                  className="block w-full text-xs text-neutral-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-xs file:bg-neutral-800 file:text-neutral-200 hover:file:bg-neutral-700 file:cursor-pointer cursor-pointer"
                />
              </label>
              <button
                type="button"
                onClick={verifyVideoFile}
                disabled={!contractAddress || !verifyFile || verifyLoading}
                className="rounded bg-neutral-800 px-4 py-2 text-xs hover:bg-neutral-700 transition disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
              >
                {verifyLoading ? 'Verifying…' : 'Verify'}
              </button>
            </div>

            {verifyFile && (
              <div className="text-xs text-neutral-500">
                Selected: <span className="text-neutral-300">{verifyFile.name}</span> ({(verifyFile.size / 1024 / 1024).toFixed(2)} MB)
              </div>
            )}

            {verifyError && <div className="text-xs text-red-300">{verifyError}</div>}

            {verifyResult && (
              <div className="rounded border border-neutral-800 bg-neutral-900/40 p-3 text-xs space-y-1">
                <div>
                  <span className="text-neutral-500">status:</span>{' '}
                  <span className={verifyResult.found ? 'text-emerald-400' : 'text-red-400'}>
                    {verifyResult.found ? 'registered' : 'not registered'}
                  </span>
                </div>
                <div className="break-all">
                  <span className="text-neutral-500">contentHash:</span>{' '}
                  <span className="text-neutral-200">{verifyResult.hash}</span>
                </div>
                <div>
                  <span className="text-neutral-500">registrant:</span>{' '}
                  <span className="text-neutral-200">{verifyResult.found && verifyResult.video ? verifyResult.video.uploader : '—'}</span>
                </div>
                <div>
                  <span className="text-neutral-500">sequence:</span>{' '}
                  <span className="text-neutral-200">{verifyResult.found && verifyResult.video ? verifyResult.video.sequence.toString() : '—'}</span>
                </div>
                <div>
                  <span className="text-neutral-500">timestamp:</span>{' '}
                  <span className="text-neutral-200">{verifyResult.found && verifyResult.video ? formatUnixSeconds(verifyResult.video.createdAt) : '—'}</span>
                </div>
                <div>
                  <span className="text-neutral-500">relayer:</span>{' '}
                  <span className="text-neutral-200">
                    {verifyResult.found && verifyResult.video 
                      ? `${verifyResult.video.relayer.slice(0, 6)}...${verifyResult.video.relayer.slice(-4)}` 
                      : '—'}
                  </span>
                </div>
                <div className="break-all">
                  <span className="text-neutral-500">cid:</span>{' '}
                  <span className="text-neutral-200">{verifyResult.found && verifyResult.video ? verifyResult.video.cid : '—'}</span>
                  {verifyResult.found && verifyResult.video?.cid && (
                    <a
                      className="ml-2 text-emerald-400 hover:text-emerald-300"
                      href={ipfsUrl(verifyResult.video.cid)}
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
        </div>

        {/* List by uploader */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-950/40 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-xs text-neutral-500">Your Videos</div>
            {walletAddress && (
              <div className="text-xs text-neutral-500">
                total: <span className="text-neutral-200">{listTotal}</span>
              </div>
            )}
          </div>

          {!walletAddress ? (
            <div className="text-center py-8 text-neutral-500 text-sm">
              Connect your wallet to view your videos
            </div>
          ) : (
            <>
              {listError && <div className="text-xs text-red-300">{listError}</div>}

              <div className="space-y-2">
                {listLoading ? (
                  // Loading skeleton
                  <>
                    {[...Array(3)].map((_, i) => (
                      <div key={i} className="rounded border border-neutral-800 bg-neutral-900/40 p-3 animate-pulse">
                        <div className="flex items-center justify-between gap-2">
                          <div className="h-4 bg-neutral-800 rounded w-32"></div>
                          <div className="h-4 bg-neutral-800 rounded w-12"></div>
                        </div>
                        <div className="mt-2 h-3 bg-neutral-800 rounded w-full"></div>
                        <div className="mt-2 h-3 bg-neutral-800 rounded w-3/4"></div>
                      </div>
                    ))}
                  </>
                ) : (
                  <>
                    {listResults.map((v) => (
                      <div key={v.contentHash} className="rounded border border-neutral-800 bg-neutral-900/40 p-3 text-xs">
                        <div className="flex items-center justify-between gap-2">
                          <div className="text-neutral-200">
                            uploader: {v.uploader.slice(0, 6)}...{v.uploader.slice(-4)}
                          </div>
                          <div className="text-neutral-500">seq {v.sequence.toString()}</div>
                        </div>
                        <div className="mt-1 text-neutral-500">
                          created {formatUnixSeconds(v.createdAt)} | relayer: {v.relayer.slice(0, 6)}...{v.relayer.slice(-4)}
                        </div>
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

                    {listResults.length === 0 && (
                      <div className="text-xs text-neutral-600 text-center py-4">
                        No videos found for this wallet
                      </div>
                    )}
                  </>
                )}
              </div>

              {walletAddress && !listLoading && listTotal > listLimit && (
                <div className="flex items-center justify-between pt-2">
                  <button
                    type="button"
                    onClick={() => listForAddress({ offset: Math.max(0, listOffset - listLimit) })}
                    disabled={listOffset <= 0}
                    className="rounded bg-neutral-800 px-3 py-1 text-xs hover:bg-neutral-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Prev
                  </button>
                  <div className="text-xs text-neutral-500">
                    showing {listOffset + 1}-{Math.min(listOffset + listLimit, listTotal)} of {listTotal}
                  </div>
                  <button
                    type="button"
                    onClick={() => listForAddress({ offset: listOffset + listLimit })}
                    disabled={listOffset + listLimit >= listTotal}
                    className="rounded bg-neutral-800 px-3 py-1 text-xs hover:bg-neutral-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}
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
