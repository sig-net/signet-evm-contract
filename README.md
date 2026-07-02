# SigNet EVM program

This repository contains the Solidity contract that is deployed on EVM blockchains. It allows requesting signatures from the SigNet MPC network, supporting both simple signing (`sign`) and bidirectional cross-chain transactions (`signBidirectional`), following the same pattern as the [SigNet Solana program](https://github.com/sig-net/signet-solana-program) and the Canton Signer templates.

## Overview

The contract is an event bus plus a deposit sink: it performs no signature verification itself. MPC responses are delivered as events, and consumers MUST verify them against the expected derived MPC key (see [Response verification](#response-verification)).

### Functions

| Function               | Description                                                     |
| ---------------------- | --------------------------------------------------------------- |
| `sign`                 | Request a signature on a 32-byte payload                        |
| `signBidirectional`    | Cross-chain transaction with verified execution result callback |
| `respond`              | MPC delivers signatures (batched); emits `SignatureResponded`   |
| `respondBidirectional` | MPC delivers the destination-chain execution result             |
| `respondError`         | MPC reports signing errors (debugging only)                     |
| `getSignatureDeposit`  | Query the current deposit amount (view)                         |
| `setSignatureDeposit`  | Update the deposit (admin only)                                 |
| `withdraw`             | Withdraw accumulated deposits (admin only)                      |

## Bidirectional flow

```text
User                    EVM (source)            MPC Network        Destination chain
  |                        |                         |                    |
  | signBidirectional()    |                         |                    |
  +----------------------->|                         |                    |
  |                        |  SignBidirectional      |                    |
  |                        +------------------------>|                    |
  |                        |<---- respond() ---------+                    |
  | Poll SignatureResponded|                         |                    |
  |<-----------------------+                         |                    |
  | Broadcast signed tx ---+-------------------------+------------------->|
  |                        |                         |<-- observation ----+
  |                        |<- respondBidirectional()|                    |
  | Poll RespondBidirectional                        |                    |
  |<-----------------------+                         |                    |
```

1. The user calls `signBidirectional` with the serialized unsigned destination-chain transaction (plus the two serialization schemas). The MPC signs the transaction hash and answers through `respond` (`SignatureResponded` event).
2. The user reconstructs the signed transaction and broadcasts it to the destination chain — **the MPC does not broadcast**.
3. The MPC observes the destination chain for confirmation, extracts the execution output (parsed per `outputDeserializationSchema`), serializes it per `respondSerializationSchema`, signs it, and calls `respondBidirectional` (`RespondBidirectional` event).

## Request IDs

Request IDs are computed off-chain, never by the contract:

```text
// sign (matches the MPC node and signet.js getRequestIdRespond):
requestId = keccak256(abi.encode(
    sender, payload, path, keyVersion, block.chainid, algo, dest, params))

// signBidirectional (packed, mirroring the Solana program):
requestId = keccak256(abi.encodePacked(
    sender, serializedTransaction, caip2Id, keyVersion, path, algo, dest, params))
```

## Response verification

The bidirectional execution-result signature is made over `keccak256(abi.encodePacked(requestId, serializedOutput))` using a **different derivation path** than the transaction signature:

| Signature             | KDF predecessor | Derivation path                   |
| --------------------- | --------------- | --------------------------------- |
| Transaction signature | requester       | The request's `path` parameter    |
| Response signature    | requester       | `"ethereum response key"` (fixed) |

Child keys follow the SigNet epsilon KDF (see signet.js `deriveChildPublicKey`): `epsilon = keccak256("sig.network v2.0.0 epsilon derivation:eip155:1:<0x sender>:<path>")`, `childPubKey = rootPubKey + epsilon * G`.

Failed destination-chain transactions are reported with the magic prefix `0xdeadbeef` at the start of `serializedOutput`.

## Prerequisites

- Node.js v22+
- pnpm v10+

## Installation

```bash
pnpm install
```

## Build

```bash
pnpm build
```

## Testing

```bash
pnpm test
```

The test suite runs against the in-process Hardhat network with a mock MPC signer (`test-utils/signingUtils.ts`) whose key derivation is golden-anchored to signet.js — every derived child key is cross-checked against `utils.cryptography.deriveChildPublicKey`, so the tests verify the exact signatures the real network would produce.

`pnpm check` runs format check + typecheck + tests.

## Deployment

```bash
# Local
pnpm hardhat ignition deploy ignition/modules/ChainSignatures.ts

# Sepolia (set SEPOLIA_RPC_URL and SEPOLIA_PRIVATE_KEY in .env)
pnpm hardhat ignition deploy ignition/modules/ChainSignatures.ts --network sepolia
```

Production deployments should pass the MPC network's admin address and the required deposit via module parameters (`admin`, `signatureDeposit`).

## Project layout

```text
contracts/ChainSignatures.sol   The signing contract (event bus + deposit sink)
contracts/ProxyTestCaller.sol   Consumer-contract example (Solana proxy-test-cpi analog)
test/                           node:test + viem specs, one per flow
test-utils/                     Mock MPC signer + request-id helpers (signet.js golden-checked)
ignition/modules/               Hardhat Ignition deployment module
```
