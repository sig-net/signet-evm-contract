/**
 * Common signing utilities for tests
 *
 * This module provides reusable functions for:
 * - Creating unique sign arguments with identifiable payloads
 * - Computing request IDs (simple and bidirectional)
 * - Acting as a mock MPC signer: deriving child keys with the SigNet epsilon
 *   KDF and producing contract-format signatures
 *
 * Key derivation is golden-anchored to signet.js: every child key derived
 * from the local root private key is cross-checked against
 * `utils.cryptography.deriveChildPublicKey` so the mock MPC in these tests
 * matches the real network byte-for-byte.
 */
import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  hexToBytes,
  keccak256,
  numberToHex,
  parseAbi,
  serializeTransaction,
  stringToHex,
  toHex,
  type Hex,
  type TransactionSerializableEIP1559,
} from 'viem';
import { publicKeyToAddress } from 'viem/accounts';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { utils as signetUtils, constants as signetConstants } from 'signet.js';

// ---------------------------------------------------------------------------
// Types mirroring the contract structs
// ---------------------------------------------------------------------------

export interface SignArgs {
  payload: Hex; // bytes32
  path: string;
  keyVersion: number;
  algo: string;
  dest: string;
  params: string;
}

export interface BidirectionalArgs {
  serializedTransaction: Hex;
  caip2Id: string;
  keyVersion: number;
  path: string;
  algo: string;
  dest: string;
  params: string;
  outputDeserializationSchema: Hex;
  respondSerializationSchema: Hex;
}

export interface SignatureStruct {
  bigR: { x: bigint; y: bigint };
  s: bigint;
  recoveryId: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Test-only MPC root private key (deterministic, never use in production). */
export const TEST_ROOT_PRIVATE_KEY: Hex = keccak256(
  stringToHex('signet-evm-contract test root')
);

/** v2 derivation requires keyVersion >= 1. */
export const KEY_VERSION = 1;

/** KDF chain id for EVM source chains — golden value from signet.js. */
export const ETHEREUM_KDF_CHAIN_ID = signetConstants.KDF_CHAIN_IDS.ETHEREUM;

/**
 * Derivation path for bidirectional response-verification keys, the EVM
 * counterpart of the MPC node's "solana response key" / "canton response key".
 */
export const RESPONSE_KEY_PATH = 'ethereum response key';

/** Magic prefix marking a failed destination-chain transaction. */
export const ERROR_PREFIX = '0xdeadbeef';

/** ABI-encoded boolean `true` (one 32-byte slot). */
export const ABI_BOOL_TRUE: Hex = `0x${'1'.padStart(64, '0')}`;

const EPSILON_DERIVATION_PREFIX = 'sig.network v2.0.0 epsilon derivation';

/** secp256k1 group order n (protocol constant). */
const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// Unique payload prefixes for easy identification in logs
const PAYLOAD_PREFIXES = {
  PROXY_TEST: 0x10,
  WALLET_TEST: 0x20,
  CONFIG_TEST: 0x30,
  CONCURRENT_TEST: 0x40,
  BIDIRECTIONAL_TEST: 0x50,
} as const;

// ---------------------------------------------------------------------------
// Root key helpers
// ---------------------------------------------------------------------------

/** Uncompressed SEC1 root public key ("04" + x + y, no 0x prefix). */
export function rootPublicKey(): `04${string}` {
  const pub = secp256k1.getPublicKey(hexToBytes(TEST_ROOT_PRIVATE_KEY), false);
  return toHex(pub).slice(2) as `04${string}`;
}

// ---------------------------------------------------------------------------
// Epsilon key derivation (mock MPC side)
// ---------------------------------------------------------------------------

/**
 * Derive the epsilon scalar for a requester + path, mirroring the MPC node's
 * `derive_epsilon_eth` (kdf.rs) for keyVersion >= 1:
 * keccak256("sig.network v2.0.0 epsilon derivation:eip155:1:<0x addr>:<path>")
 */
function deriveEpsilon(predecessor: string, path: string): bigint {
  const derivationPath = `${EPSILON_DERIVATION_PREFIX}:${ETHEREUM_KDF_CHAIN_ID}:${predecessor.toLowerCase()}:${path}`;
  return BigInt(keccak256(stringToHex(derivationPath)));
}

/**
 * Derive the child private key: childPriv = (rootPriv + epsilon) mod n.
 * The derived public key is cross-checked against signet.js
 * `deriveChildPublicKey` (the golden reference) on every call.
 */
export function deriveChildPrivateKey(predecessor: string, path: string): Hex {
  const epsilon = deriveEpsilon(predecessor, path);
  const childPriv = (BigInt(TEST_ROOT_PRIVATE_KEY) + epsilon) % SECP256K1_N;
  const childPrivHex = numberToHex(childPriv, { size: 32 });

  const expectedPub = signetUtils.cryptography.deriveChildPublicKey(
    rootPublicKey(),
    predecessor.toLowerCase(),
    path,
    ETHEREUM_KDF_CHAIN_ID,
    KEY_VERSION
  );
  const actualPub = toHex(
    secp256k1.getPublicKey(hexToBytes(childPrivHex), false)
  ).slice(2);
  if (actualPub !== expectedPub) {
    throw new Error(
      'Child key derivation diverged from the signet.js golden reference'
    );
  }

  return childPrivHex;
}

/** Ethereum address of the derived child key (golden: via signet.js pubkey). */
export function deriveChildAddress(predecessor: string, path: string): Hex {
  const childPub = signetUtils.cryptography.deriveChildPublicKey(
    rootPublicKey(),
    predecessor.toLowerCase(),
    path,
    ETHEREUM_KDF_CHAIN_ID,
    KEY_VERSION
  );
  return publicKeyToAddress(`0x${childPub}`);
}

// ---------------------------------------------------------------------------
// Sign argument factories
// ---------------------------------------------------------------------------

/**
 * Creates unique sign arguments with identifiable payloads
 */
export function createSignArgs(
  testType: keyof typeof PAYLOAD_PREFIXES,
  pathSuffix: string = '',
  offset: number = 0
): SignArgs {
  const prefix = PAYLOAD_PREFIXES[testType];
  const payloadBytes = Uint8Array.from({ length: 32 }, (_, i) => {
    if (i === 0) return prefix; // First byte identifies test type
    if (i === 1) return offset; // Second byte for test iteration/offset
    return (i + offset) % 256; // Remaining bytes with pattern
  });

  return {
    payload: toHex(payloadBytes),
    keyVersion: KEY_VERSION,
    path: pathSuffix
      ? `test-${testType.toLowerCase()}-path-${pathSuffix}`
      : `test-${testType.toLowerCase()}-path`,
    algo: 'secp256k1',
    dest: 'ethereum',
    params: '{}',
  };
}

/** JSON ABI schema for a single bool return value (utf8-encoded bytes). */
const BOOL_SCHEMA: Hex = stringToHex('[{"name":"","type":"bool"}]');

/**
 * Creates bidirectional sign arguments around a serialized unsigned EIP-1559
 * destination-chain transaction.
 */
export function createBidirectionalArgs(
  serializedTransaction: Hex,
  destinationChainId: number,
  pathSuffix: string = ''
): BidirectionalArgs {
  return {
    serializedTransaction,
    caip2Id: `eip155:${destinationChainId}`,
    keyVersion: KEY_VERSION,
    path: pathSuffix
      ? `test-bidirectional-path-${pathSuffix}`
      : 'test-bidirectional-path',
    algo: 'secp256k1',
    dest: 'ethereum',
    params: '{}',
    outputDeserializationSchema: BOOL_SCHEMA,
    respondSerializationSchema: BOOL_SCHEMA,
  };
}

/**
 * Builds a canonical unsigned EIP-1559 ERC-20 `transfer(to, amount)`
 * destination-chain transaction for bidirectional tests.
 */
export function buildDestinationTransaction(
  destinationChainId: number
): TransactionSerializableEIP1559 {
  const erc20Abi = parseAbi([
    'function transfer(address to, uint256 amount) returns (bool)',
  ]);
  return {
    type: 'eip1559',
    chainId: destinationChainId,
    nonce: 0,
    to: '0xB4F1737Af37711e9A5890D9510c9bB60e170CB0D',
    value: 0n,
    data: encodeFunctionData({
      abi: erc20Abi,
      functionName: 'transfer',
      args: [
        '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
        1_000_000_000_000_000n,
      ],
    }),
    gas: 100_000n,
    maxFeePerGas: 20_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  };
}

// ---------------------------------------------------------------------------
// Request IDs
// ---------------------------------------------------------------------------

/**
 * Request ID for the simple `sign` flow. Must match the MPC node
 * (`SignatureRequestedEncoding` in indexer_eth/abi.rs) and signet.js
 * (`getRequestIdRespond`) byte-for-byte:
 * keccak256(abi.encode(sender, payload, path, keyVersion, chainId, algo, dest, params))
 */
export function generateSignRequestId(
  sender: Hex,
  args: SignArgs,
  chainId: bigint
): Hex {
  const encoded = encodeAbiParameters(
    [
      { type: 'address' },
      { type: 'bytes' },
      { type: 'string' },
      { type: 'uint32' },
      { type: 'uint256' },
      { type: 'string' },
      { type: 'string' },
      { type: 'string' },
    ],
    [
      sender,
      args.payload,
      args.path,
      args.keyVersion,
      chainId,
      args.algo,
      args.dest,
      args.params,
    ]
  );
  return keccak256(encoded);
}

/**
 * Request ID for the `signBidirectional` flow, mirroring the Solana program's
 * packed scheme (indexer_sol.rs `generate_request_id`) with the EVM address
 * as the sender:
 * keccak256(abi.encodePacked(sender, serializedTransaction, caip2Id, keyVersion, path, algo, dest, params))
 */
export function generateBidirectionalRequestId(
  sender: Hex,
  args: BidirectionalArgs
): Hex {
  const encoded = encodePacked(
    [
      'address',
      'bytes',
      'string',
      'uint32',
      'string',
      'string',
      'string',
      'string',
    ],
    [
      sender,
      args.serializedTransaction,
      args.caip2Id,
      args.keyVersion,
      args.path,
      args.algo,
      args.dest,
      args.params,
    ]
  );
  return keccak256(encoded);
}

// ---------------------------------------------------------------------------
// Mock MPC signing
// ---------------------------------------------------------------------------

/**
 * Sign a 32-byte digest with the child key derived for (predecessor, path),
 * returning the contract's Signature struct (full R point + s + recoveryId).
 */
export function mpcSignDigest(
  predecessor: string,
  path: string,
  digest: Hex
): SignatureStruct {
  const childPriv = deriveChildPrivateKey(predecessor, path);
  const sigBytes = secp256k1.sign(hexToBytes(digest), hexToBytes(childPriv), {
    prehash: false,
    format: 'recovered',
  });
  const sig = secp256k1.Signature.fromBytes(sigBytes, 'recovered');
  const recovery = sig.recovery ?? 0;
  if (recovery !== 0 && recovery !== 1) {
    throw new Error(`Unexpected recovery id: ${recovery}`);
  }

  // Reconstruct the full R point from r + y parity (recovery id).
  const prefix = recovery === 1 ? '03' : '02';
  const rHex = sig.r.toString(16).padStart(64, '0');
  const bigR = secp256k1.Point.fromHex(`${prefix}${rHex}`);
  const affine = bigR.toAffine();

  return {
    bigR: { x: affine.x, y: affine.y },
    s: sig.s,
    recoveryId: recovery,
  };
}

/** Convert the contract Signature struct to viem's r/s/yParity form. */
export function signatureStructToRsv(signature: SignatureStruct): {
  r: Hex;
  s: Hex;
  yParity: number;
} {
  return {
    r: numberToHex(signature.bigR.x, { size: 32 }),
    s: numberToHex(signature.s, { size: 32 }),
    yParity: signature.recoveryId,
  };
}

/**
 * Response hash for the bidirectional outcome:
 * keccak256(requestId || serializedOutput). Matches the MPC node
 * (respond_bidirectional.rs), the Solana consumer docs, and Canton's
 * computeResponseHash.
 */
export function computeResponseHash(
  requestId: Hex,
  serializedOutput: Hex
): Hex {
  return keccak256(concatHex([requestId, serializedOutput]));
}

/** Check whether a serialized output carries the 0xdeadbeef failure prefix. */
export function hasErrorPrefix(serializedOutput: Hex): boolean {
  return serializedOutput.toLowerCase().startsWith(ERROR_PREFIX);
}
