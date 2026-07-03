# Examples

Example consumer contracts built on the SigNet ChainSignatures contract, mirroring the [solana-contract-examples](https://github.com/sig-net/solana-contract-examples) vault program for the EVM → EVM case.

## Erc20Vault — cross-chain ERC-20 custody (EVM ↔ EVM)

`Erc20Vault.sol` custodies ERC-20 tokens that live on a **destination** EVM chain while all accounting happens on the **source** chain where this contract is deployed. The MPC network holds the keys: users deposit into MPC-derived addresses, and the vault directs transfers by requesting signatures through `ChainSignatures.signBidirectional`.

### Key model

Every MPC child key uses **this contract's address as the KDF predecessor** (the vault is the `sender` of every `signBidirectional` call):

| Key                      | Derivation path           | Purpose                                                 |
| ------------------------ | ------------------------- | ------------------------------------------------------- |
| Per-user deposit address | `"0x<user address hex>"`  | Where the user funds their deposit                      |
| Vault address            | `"root"`                  | Custodies all deposited ERC-20 on the destination chain |
| Response verifier        | `"ethereum response key"` | Signs the MPC's execution-outcome reports               |

`vaultEvmAddress` and `responseSigner` are derived off-chain (signet.js `deriveChildPublicKey`) and pinned once via `initialize` — the predecessor is the contract address, which only exists after deployment. This mirrors the Canton vault (which stores `evmVaultAddress` + `mpcResponseVerifyKey` at creation). The Solana example derives addresses on-chain through a `secp256k1_recover` EC-multiplication trick; the EVM `ecrecover` precompile returns only addresses (not curve points), so on-chain derivation would require a full EC library.

### Deposit

```text
User funds deposit address (destination chain)
  └─ depositErc20(erc20, amount, txParams)          [source chain]
       ├─ builds transfer(vaultEvmAddress, amount) RLP on-chain (EVMTransactionLib)
       ├─ records PendingDeposit[requestId]          (single-use)
       └─ ChainSignatures.signBidirectional{value}   (path = user address)
  MPC signs → user broadcasts to destination chain → MPC observes outcome
  └─ claimErc20(requestId, output, signature)        [source chain]
       ├─ verifies signature over keccak256(requestId ‖ output) against responseSigner
       ├─ rejects 0xdeadbeef-prefixed / false outputs
       └─ credits userBalances[user][erc20]
```

The transfer recipient is **always** the vault address — it is built on-chain and cannot be caller-supplied.

### Withdrawal

```text
withdrawErc20(erc20, amount, recipient, txParams)    [source chain]
  ├─ optimistically debits userBalances
  ├─ builds transfer(recipient, amount) from the vault key (path = "root")
  └─ records PendingWithdrawal[requestId] + signBidirectional
MPC signs → broadcast → MPC observes outcome
completeWithdrawErc20(requestId, output, signature)
  ├─ verifies the outcome signature
  └─ refunds the debit when the destination tx failed (0xdeadbeef or false)
```

### On-chain transaction building

`EVMTransactionLib` (from the [signet.sol](https://github.com/sig-net/signet.sol) package, where it is validated against viem byte-for-byte) RLP-encodes the unsigned EIP-1559 destination transaction on-chain — the Solidity analog of what `signet-rs` does inside the Solana example program. The example test re-verifies this: the emitted `serializedTransaction` must equal viem's `serializeTransaction` output exactly.

### Request IDs

Computed on-chain by the vault (and cross-checked in the tests against the ecosystem formula):

```text
requestId = keccak256(abi.encodePacked(
    address(this), rlpTx, caip2Id, keyVersion, path, algo, dest, params))
```

### Running the example tests

```bash
pnpm test   # includes test/examples/erc20-vault.test.ts + erc20-vault.e2e.test.ts
```

Two layers of coverage:

- `erc20-vault.test.ts` exercises the full lifecycle with the in-process mock MPC (`test-utils/signingUtils.ts`): deposit → sign → (simulated) broadcast → outcome → claim, withdrawal with success and refund paths, plus signature-forgery and replay rejections.
- `erc20-vault.e2e.test.ts` emulates the real deployment with **two independent in-process Hardhat chains** — the source chain hosting ChainSignatures + the vault, and a destination chain (chainId 11155111) hosting a `TestERC20`. The MPC-signed transactions are broadcast and executed for real: tokens actually move between the derived deposit address, the vault address, and recipients; the outcome is extracted by re-simulating the call at the parent block (exactly how the MPC node builds `serializedOutput`); and the refund path is triggered by a transfer that genuinely returns `false` on-chain.
