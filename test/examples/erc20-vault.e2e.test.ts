/**
 * EVM <-> EVM e2e against two in-process chains.
 *
 * Unlike the unit tests (which simulate the destination outcome), this suite
 * emulates the full deployment locally with two independent Hardhat networks:
 *
 *   - source chain (`hardhatMainnet`, chainId 31337): ChainSignatures + Erc20Vault
 *   - destination chain (`hardhatDestination`, chainId 11155111): TestERC20
 *
 * The MPC-signed transactions produced by the vault are actually broadcast to
 * the destination chain and executed; real token balances move; the outcome
 * is extracted the way the MPC node does it (re-simulating the call at the
 * parent block to read the return data) and reported back to the source
 * chain. The mock MPC signer (test-utils) is golden-checked against signet.js
 * on every derivation, so these are the exact signatures the network would
 * produce.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { network } from 'hardhat';
import {
  keccak256,
  parseEther,
  parseEventLogs,
  parseGwei,
  parseTransaction,
  serializeTransaction,
  type Hex,
} from 'viem';
import {
  deriveChildAddress,
  mpcSignDigest,
  signatureStructToRsv,
  computeResponseHash,
  ABI_BOOL_TRUE,
  RESPONSE_KEY_PATH,
} from '../../test-utils/signingUtils.js';

const SIGNATURE_DEPOSIT = parseGwei('50000');
const DESTINATION_CHAIN_ID = 11155111;
const ROOT_PATH = 'root';
const DEPOSIT_AMOUNT = 1_000_000_000_000_000n; // 0.001 token
const WITHDRAW_AMOUNT = 600_000_000_000_000n;
const REFUND_AMOUNT = 400_000_000_000_000n;
const GAS_LIMIT = 100_000n;
const MAX_FEE_PER_GAS = 20_000_000_000n;
const MAX_PRIORITY_FEE_PER_GAS = 1_000_000_000n;
const ABI_BOOL_FALSE: Hex = `0x${'0'.repeat(64)}`;

void describe('ERC20 Vault example e2e (two local chains)', async () => {
  // ── Source chain: ChainSignatures + Erc20Vault ─────────────────────────────
  const source = await network.getOrCreate();
  const sourcePublic = await source.viem.getPublicClient();
  const [admin, requester, responder] = await source.viem.getWalletClients();

  const chainSignatures = await source.viem.deployContract('ChainSignatures', [
    admin.account.address,
    SIGNATURE_DEPOSIT,
  ]);
  const vault = await source.viem.deployContract('Erc20Vault', [
    chainSignatures.address,
    admin.account.address,
  ]);

  const vaultEvmAddress = deriveChildAddress(vault.address, ROOT_PATH);
  const responseSigner = deriveChildAddress(vault.address, RESPONSE_KEY_PATH);
  await vault.write.initialize([vaultEvmAddress, responseSigner]);

  const userPath = requester.account.address.toLowerCase();
  const depositAddress = deriveChildAddress(vault.address, userPath);

  // ── Destination chain: an independent simulated network + TestERC20 ────────
  const destination = await network.create('hardhatDestination');
  const destPublic = await destination.viem.getPublicClient();
  const [faucet] = await destination.viem.getWalletClients();
  const token = await destination.viem.deployContract('TestERC20', []);

  /** Destination-chain EIP-1559 params for `from`, with its live nonce. */
  async function destTxParams(from: Hex) {
    return {
      chainId: BigInt(DESTINATION_CHAIN_ID),
      nonce: BigInt(await destPublic.getTransactionCount({ address: from })),
      value: 0n,
      gasLimit: GAS_LIMIT,
      maxFeePerGas: MAX_FEE_PER_GAS,
      maxPriorityFeePerGas: MAX_PRIORITY_FEE_PER_GAS,
    };
  }

  /** Fund an MPC-derived address with gas ETH on the destination chain. */
  async function fundGas(address: Hex) {
    const hash = await faucet.sendTransaction({
      to: address,
      value: parseEther('0.01'),
    });
    await destPublic.waitForTransactionReceipt({ hash });
  }

  async function tokenBalance(address: Hex): Promise<bigint> {
    return token.read.balanceOf([address]);
  }

  /**
   * Play user + MPC for one request: sign the emitted destination tx with the
   * derived child key, broadcast it to the destination chain, and extract the
   * real return data by re-simulating the call at the parent block (what the
   * MPC node does to build `serializedOutput`).
   */
  async function signBroadcastAndObserve(
    sourceTxHash: Hex,
    signerPath: string,
    expectedFrom: Hex
  ): Promise<{ requestId: Hex; serializedOutput: Hex }> {
    const receipt = await sourcePublic.waitForTransactionReceipt({
      hash: sourceTxHash,
    });
    const [signEvent] = parseEventLogs({
      abi: chainSignatures.abi,
      logs: receipt.logs,
      eventName: 'SignBidirectional',
    });
    const [vaultEvent] = parseEventLogs({
      abi: vault.abi,
      logs: receipt.logs,
      eventName:
        signerPath === ROOT_PATH ? 'WithdrawalInitiated' : 'DepositInitiated',
    });
    const requestId = vaultEvent.args.requestId;
    const serializedTx = signEvent.args.serializedTransaction;

    // MPC leg 1: sign the destination transaction hash with the child key.
    const txSignature = mpcSignDigest(
      vault.address,
      signerPath,
      keccak256(serializedTx)
    );
    await chainSignatures.write.respond(
      [[{ requestId, signature: txSignature }]],
      { account: responder.account }
    );

    // User leg: reconstruct the signed tx from the vault-built RLP and
    // broadcast it for real.
    const signedTx = serializeTransaction(
      parseUnsignedEip1559(serializedTx),
      signatureStructToRsv(txSignature)
    );
    const destTxHash = await destPublic.sendRawTransaction({
      serializedTransaction: signedTx,
    });
    const destReceipt = await destPublic.waitForTransactionReceipt({
      hash: destTxHash,
    });
    assert.equal(destReceipt.status, 'success');
    assert.equal(destReceipt.from.toLowerCase(), expectedFrom.toLowerCase());

    // MPC leg 2: extract the return data by re-simulating at the parent block.
    const unsigned = parseUnsignedEip1559(serializedTx);
    const { data: returnData } = await destPublic.call({
      account: expectedFrom,
      to: unsigned.to,
      data: unsigned.data,
      blockNumber: destReceipt.blockNumber - 1n,
    });
    const serializedOutput = (returnData ?? '0x') as Hex;

    // MPC leg 3: publish the signed outcome on the source chain.
    const outcomeSignature = mpcSignDigest(
      vault.address,
      RESPONSE_KEY_PATH,
      computeResponseHash(requestId, serializedOutput)
    );
    await chainSignatures.write.respondBidirectional(
      [requestId, serializedOutput, outcomeSignature],
      { account: responder.account }
    );

    return { requestId, serializedOutput };
  }

  /** Complete a claim/withdrawal on the source chain with the observed outcome. */
  function outcomeSignatureFor(requestId: Hex, serializedOutput: Hex) {
    return mpcSignDigest(
      vault.address,
      RESPONSE_KEY_PATH,
      computeResponseHash(requestId, serializedOutput)
    );
  }

  void it('connects two independent chains', async () => {
    assert.equal(await sourcePublic.getChainId(), 31337);
    assert.equal(await destPublic.getChainId(), DESTINATION_CHAIN_ID);
  });

  void it('deposits: the MPC-signed transfer executes on the destination chain', async () => {
    // Fund the user's derived deposit address: gas ETH + tokens to deposit.
    await fundGas(depositAddress);
    const seedHash = await token.write.transfer([
      depositAddress,
      DEPOSIT_AMOUNT,
    ]);
    await destPublic.waitForTransactionReceipt({ hash: seedHash });
    assert.equal(await tokenBalance(depositAddress), DEPOSIT_AMOUNT);

    // Request the deposit on the source chain.
    const txHash = await vault.write.depositErc20(
      [token.address, DEPOSIT_AMOUNT, await destTxParams(depositAddress)],
      { value: SIGNATURE_DEPOSIT, account: requester.account }
    );

    const { requestId, serializedOutput } = await signBroadcastAndObserve(
      txHash,
      userPath,
      depositAddress
    );

    // Real token movement on the destination chain.
    assert.equal(await tokenBalance(depositAddress), 0n);
    assert.equal(await tokenBalance(vaultEvmAddress), DEPOSIT_AMOUNT);
    // The re-simulated return data is the ABI-encoded `true`.
    assert.equal(serializedOutput, ABI_BOOL_TRUE);

    // Claim on the source chain with the observed outcome.
    await vault.write.claimErc20(
      [
        requestId,
        serializedOutput,
        outcomeSignatureFor(requestId, serializedOutput),
      ],
      { account: requester.account }
    );
    assert.equal(
      await vault.read.userBalances([requester.account.address, token.address]),
      DEPOSIT_AMOUNT
    );
  });

  void it('withdraws: the vault key transfers to the recipient on the destination chain', async () => {
    await fundGas(vaultEvmAddress);
    const recipient = deriveChildAddress(vault.address, 'e2e-recipient');
    assert.equal(await tokenBalance(recipient), 0n);

    const txHash = await vault.write.withdrawErc20(
      [
        token.address,
        WITHDRAW_AMOUNT,
        recipient,
        await destTxParams(vaultEvmAddress),
      ],
      { value: SIGNATURE_DEPOSIT, account: requester.account }
    );

    const { requestId, serializedOutput } = await signBroadcastAndObserve(
      txHash,
      ROOT_PATH,
      vaultEvmAddress
    );

    // Real token movement: vault -> recipient on the destination chain.
    assert.equal(await tokenBalance(recipient), WITHDRAW_AMOUNT);
    assert.equal(
      await tokenBalance(vaultEvmAddress),
      DEPOSIT_AMOUNT - WITHDRAW_AMOUNT
    );
    assert.equal(serializedOutput, ABI_BOOL_TRUE);

    await vault.write.completeWithdrawErc20(
      [
        requestId,
        serializedOutput,
        outcomeSignatureFor(requestId, serializedOutput),
      ],
      { account: requester.account }
    );
    // No refund: the source-chain balance reflects the withdrawal.
    assert.equal(
      await vault.read.userBalances([requester.account.address, token.address]),
      DEPOSIT_AMOUNT - WITHDRAW_AMOUNT
    );
  });

  void it('refunds: a transfer that returns false on-chain restores the balance', async () => {
    // Make the destination token return false (without reverting).
    const setHash = await token.write.setReturnFalseOnTransfer([true]);
    await destPublic.waitForTransactionReceipt({ hash: setHash });

    const recipient = deriveChildAddress(vault.address, 'e2e-refund-recipient');
    const vaultBalanceBefore = await tokenBalance(vaultEvmAddress);

    const txHash = await vault.write.withdrawErc20(
      [
        token.address,
        REFUND_AMOUNT,
        recipient,
        await destTxParams(vaultEvmAddress),
      ],
      { value: SIGNATURE_DEPOSIT, account: requester.account }
    );
    // Optimistically debited.
    assert.equal(
      await vault.read.userBalances([requester.account.address, token.address]),
      0n
    );

    const { requestId, serializedOutput } = await signBroadcastAndObserve(
      txHash,
      ROOT_PATH,
      vaultEvmAddress
    );

    // The transfer executed but moved nothing and returned false.
    assert.equal(await tokenBalance(recipient), 0n);
    assert.equal(await tokenBalance(vaultEvmAddress), vaultBalanceBefore);
    assert.equal(serializedOutput, ABI_BOOL_FALSE);

    // Completing with the observed `false` outcome refunds the debit.
    await vault.write.completeWithdrawErc20(
      [
        requestId,
        serializedOutput,
        outcomeSignatureFor(requestId, serializedOutput),
      ],
      { account: requester.account }
    );
    assert.equal(
      await vault.read.userBalances([requester.account.address, token.address]),
      REFUND_AMOUNT
    );

    const resetHash = await token.write.setReturnFalseOnTransfer([false]);
    await destPublic.waitForTransactionReceipt({ hash: resetHash });
  });
});

/**
 * Decode the unsigned EIP-1559 fields from the vault-emitted RLP so the
 * signed transaction can be reconstructed. viem's parseTransaction handles
 * the typed envelope.
 */
function parseUnsignedEip1559(serializedTx: Hex) {
  const parsed = parseTransaction(serializedTx);
  if (parsed.type !== 'eip1559') {
    throw new Error(`Expected an EIP-1559 transaction, got ${parsed.type}`);
  }
  return parsed;
}
