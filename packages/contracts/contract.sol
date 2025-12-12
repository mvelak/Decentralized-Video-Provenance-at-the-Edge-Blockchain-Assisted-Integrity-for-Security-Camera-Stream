// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Veritas Smart Contract
/// @author Marco Vela-Koentarjo
/// @notice A permissionless, immutable registry for security footage.
contract Veritas {
    // -------------------------------------------------------------------------
    // Custom Errors
    // -------------------------------------------------------------------------
    error VideoAlreadyRegistered();
    error VideoNotFound();
    error TimestampInFuture();
    error SignatureExpired();
    error InvalidSignature();
    error InvalidSequence(uint64 expectedGreaterThan, uint64 actual);
    error InvalidInput(string reason);

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event VideoRegistered(
        bytes32 indexed contentHash,
        string cid,
        address indexed uploader,
        uint64 sequence,
        uint256 originalTimestamp
    );

    // -------------------------------------------------------------------------
    // State Variables & Structs
    // -------------------------------------------------------------------------

    struct RegisterInput {
        bytes32 contentHash;
        bytes32 merkleRoot;
        uint256 originalTimestamp;
        uint64 sequence;
        string cid;
        bytes signature;
    }

    struct Video {
        address uploader;        // Slot 0
        uint64 sequence;
        
        address relayer;         // Slot 1 (The address that paid the gas)
        uint48 createdAt;
        uint48 originalTimestamp;

        bytes32 contentHash;     // Slot 2
        bytes32 merkleRoot;      // Slot 3

        string cid;              // Slot 4
    }

    // Storage
    mapping(bytes32 => Video) private videos;
    mapping(address => bytes32[]) private userVideoHistory;
    mapping(address => uint64) public lastSequence;

    // EIP-712 Constants
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;
    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;

    bytes32 public constant VIDEO_TYPEHASH = keccak256(
        "Video(bytes32 contentHash,bytes32 merkleRoot,uint256 originalTimestamp,uint64 sequence,string cid)"
    );

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor() {
        _HASHED_NAME = keccak256("Veritas");
        _HASHED_VERSION = keccak256("1");
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
    }

    // -------------------------------------------------------------------------
    // Core Logic
    // -------------------------------------------------------------------------

    /// @notice Registers a video. Anyone can call this if they have a valid signature.
    function registerVideoSigned(RegisterInput calldata input) external {
        // 1. Validation
        if (bytes(input.cid).length == 0 || bytes(input.cid).length > 64) revert InvalidInput("Bad CID length");

        if (videos[input.contentHash].uploader != address(0)) revert VideoAlreadyRegistered();
        if (input.originalTimestamp > block.timestamp + 300) revert TimestampInFuture();
        if (input.originalTimestamp < block.timestamp - 7 days) revert SignatureExpired();

        address signer;

        // 2. Scoped Block for Signature Recovery
        {
            bytes32 structHash = keccak256(
                abi.encode(
                    VIDEO_TYPEHASH,
                    input.contentHash,
                    input.merkleRoot,
                    input.originalTimestamp,
                    input.sequence,
                    keccak256(bytes(input.cid))
                )
            );

            bytes32 domainSeparator = _domainSeparatorV4();
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

            signer = _recoverSigner(digest, input.signature);
        }

        if (signer == address(0)) revert InvalidSignature();

        // 3. Verify Sequence
        if (input.sequence <= lastSequence[signer]) revert InvalidSequence(lastSequence[signer], input.sequence);
        lastSequence[signer] = input.sequence;

        // 4. Store Video
        // Note: msg.sender is the "Relayer" (the account paying gas)
        videos[input.contentHash].uploader = signer;
        videos[input.contentHash].sequence = input.sequence;
        videos[input.contentHash].relayer = msg.sender; 
        videos[input.contentHash].createdAt = uint48(block.timestamp);
        videos[input.contentHash].originalTimestamp = uint48(input.originalTimestamp);
        videos[input.contentHash].contentHash = input.contentHash;
        videos[input.contentHash].merkleRoot = input.merkleRoot;
        videos[input.contentHash].cid = input.cid;
        
        userVideoHistory[signer].push(input.contentHash);

        emit VideoRegistered(
            input.contentHash, 
            input.cid, 
            signer, 
            input.sequence, 
            input.originalTimestamp
        );
    }

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------

    function getVideo(bytes32 contentHash) external view returns (Video memory) {
        if (videos[contentHash].uploader == address(0)) revert VideoNotFound();
        return videos[contentHash];
    }

    function getVideosByUploader(
        address uploader, 
        uint256 offset, 
        uint256 limit
    ) external view returns (Video[] memory page, uint256 total) {
        bytes32[] storage userHashes = userVideoHistory[uploader];
        total = userHashes.length;

        if (offset >= total) {
            return (new Video[](0), total);
        }

        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }

        uint256 resultLen = end - offset;
        page = new Video[](resultLen);

        for (uint256 i = 0; i < resultLen; ) {
            bytes32 hash = userHashes[offset + i];
            page[i] = videos[hash];
            unchecked { ++i; }
        }

        return (page, total);
    }

    // -------------------------------------------------------------------------
    // Internal & EIP-712 Helpers
    // -------------------------------------------------------------------------
    
    function _domainSeparatorV4() internal view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator();
        }
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                _HASHED_NAME,
                _HASHED_VERSION,
                block.chainid,
                address(this)
            )
        );
    }

    function _recoverSigner(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        return ecrecover(digest, v, r, s);
    }
}