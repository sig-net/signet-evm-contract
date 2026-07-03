import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { network } from 'hardhat';
import {
  concatHex,
  encodeFunctionData,
  getAddress,
  keccak256,
  parseAbi,
  parseEventLogs,
  parseGwei,
  recoverTransactionAddress,
  serializeTransaction,
  zeroAddress,
  type Address,
  type Hex,
} from 'viem';
import {
  generateBidirectionalRequestId,
  deriveChildAddress,
  mpcSignDigest,
  signatureStructToRsv,
  computeResponseHash,
  ABI_BOOL_TRUE,
  ERROR_PREFIX,
  RESPONSE_KEY_PATH,
  KEY_VERSION,
  type BidirectionalArgs,
} from '../../test-utils/signingUtils.js';

const SIGNATURE_DEPOSIT = parseGwei('50000');
const DESTINATION_CHAIN_ID = 11155111; // Sepolia
const ERC20_ADDRESS: Address = '0xB4F1737Af37711e9A5890D9510c9bB60e170CB0D';
const DEPOSIT_AMOUNT = 1_000_000_000_000_000n; // 0.001 token (18 decimals)
const ROOT_PATH = 'root';
const ALGO = 'ECDSA';
const DEST = 'ethereum';

const erc20Abi = parseAbi([
  'function transfer(address to, uint256 amount) returns (bool)',
]);

/** Destination-chain EIP-1559 params for the vault's EvmTransactionParams struct. */
function buildTxParams(nonce: bigint) {
  return {
    chainId: BigInt(DESTINATION_CHAIN_ID),
    nonce,
    value: 0n,
    gasLimit: 100_000n,
    maxFeePerGas: 20_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  };
}

/** The viem-serialized unsigned tx the vault must produce for transfer(to, amount). */
function expectedTransferTx(
  to: Address,
  amount: bigint,
  txParams: ReturnType<typeof buildTxParams>
) {
  return {
    type: 'eip1559' as const,
    chainId: DESTINATION_CHAIN_ID,
    nonce: Number(txParams.nonce),
    to: ERC20_ADDRESS,
    value: 0n,
    data: encodeFunctionData({
      abi: erc20Abi,
      functionName: 'transfer',
      args: [to, amount],
    }),
    gas: txParams.gasLimit,
    maxFeePerGas: txParams.maxFeePerGas,
    maxPriorityFeePerGas: txParams.maxPriorityFeePerGas,
    accessList: [],
  };
}

/** Bidirectional request-id args as the vault fills them. */
function vaultRequestArgs(
  serializedTransaction: Hex,
  path: string
): BidirectionalArgs {
  return {
    serializedTransaction,
    // The vault pins caip2 to "eip155:1" (TEST MODE — see Erc20Vault._caip2Id).
    caip2Id: 'eip155:1',
    keyVersion: KEY_VERSION,
    path,
    algo: ALGO,
    dest: DEST,
    params: '',
    // Schemas are not part of the request id.
    outputDeserializationSchema: '0x',
    respondSerializationSchema: '0x',
  };
}

async function deployVault() {
  const { viem } = await network.getOrCreate();
  const publicClient = await viem.getPublicClient();
  const [admin, requester, responder] = await viem.getWalletClients();

  const chainSignatures = await viem.deployContract('ChainSignatures', [
    admin.account.address,
    SIGNATURE_DEPOSIT,
  ]);
  const vault = await viem.deployContract('Erc20Vault', [
    chainSignatures.address,
    admin.account.address,
  ]);

  // The MPC child addresses are derived off-chain with the vault contract's
  // address as KDF predecessor, then pinned on-chain once.
  const vaultEvmAddress = deriveChildAddress(vault.address, ROOT_PATH);
  const responseSigner = deriveChildAddress(vault.address, RESPONSE_KEY_PATH);
  await vault.write.initialize([vaultEvmAddress, responseSigner]);

  return {
    viem,
    publicClient,
    admin,
    requester,
    responder,
    chainSignatures,
    vault,
    vaultEvmAddress,
    responseSigner,
  };
}

type VaultDeployment = Awaited<ReturnType<typeof deployVault>>;

const ABI_BOOL_FALSE: Hex = `0x${'0'.repeat(64)}`;

/** MPC outcome signature over keccak256(requestId || serializedOutput). */
function outcomeSignature(
  d: VaultDeployment,
  requestId: Hex,
  serializedOutput: Hex
) {
  return mpcSignDigest(
    d.vault.address,
    RESPONSE_KEY_PATH,
    computeResponseHash(requestId, serializedOutput)
  );
}

/** Initiate a deposit (without claiming) and return its request id. */
async function initiateDeposit(d: VaultDeployment): Promise<Hex> {
  const txHash = await d.vault.write.depositErc20(
    [ERC20_ADDRESS, DEPOSIT_AMOUNT, buildTxParams(0n)],
    { value: SIGNATURE_DEPOSIT, account: d.requester.account }
  );
  const receipt = await d.publicClient.waitForTransactionReceipt({
    hash: txHash,
  });
  const [initiated] = parseEventLogs({
    abi: d.vault.abi,
    logs: receipt.logs,
    eventName: 'DepositInitiated',
  });
  return initiated.args.requestId;
}

/**
 * Run a full deposit lifecycle: request, MPC tx signature, outcome, claim.
 * Returns the deposit request id.
 */
async function depositAndClaim(d: VaultDeployment): Promise<Hex> {
  const userPath = d.requester.account.address.toLowerCase();
  const txHash = await d.vault.write.depositErc20(
    [ERC20_ADDRESS, DEPOSIT_AMOUNT, buildTxParams(0n)],
    { value: SIGNATURE_DEPOSIT, account: d.requester.account }
  );
  const receipt = await d.publicClient.waitForTransactionReceipt({
    hash: txHash,
  });
  const [initiated] = parseEventLogs({
    abi: d.vault.abi,
    logs: receipt.logs,
    eventName: 'DepositInitiated',
  });
  assert.equal(initiated.args.path, userPath);
  const requestId = initiated.args.requestId;

  const serializedOutput = ABI_BOOL_TRUE;
  const outcomeSignature = mpcSignDigest(
    d.vault.address,
    RESPONSE_KEY_PATH,
    computeResponseHash(requestId, serializedOutput)
  );
  await d.vault.write.claimErc20(
    [requestId, serializedOutput, outcomeSignature],
    { account: d.responder.account }
  );
  return requestId;
}

void describe('ERC20 Vault example (EVM <-> EVM)', () => {
  void it('Rejects requests before initialization', async () => {
    const { viem } = await network.getOrCreate();
    const [admin, requester] = await viem.getWalletClients();
    const chainSignatures = await viem.deployContract('ChainSignatures', [
      admin.account.address,
      SIGNATURE_DEPOSIT,
    ]);
    const vault = await viem.deployContract('Erc20Vault', [
      chainSignatures.address,
      admin.account.address,
    ]);

    await viem.assertions.revertWithCustomError(
      vault.write.depositErc20(
        [ERC20_ADDRESS, DEPOSIT_AMOUNT, buildTxParams(0n)],
        { value: SIGNATURE_DEPOSIT, account: requester.account }
      ),
      vault,
      'NotInitialized'
    );
  });

  void it('Deposits: builds the destination tx on-chain, signs, claims', async () => {
    const d = await deployVault();
    const userPath = d.requester.account.address.toLowerCase();
    const txParams = buildTxParams(0n);

    // 1. Request the deposit.
    const txHash = await d.vault.write.depositErc20(
      [ERC20_ADDRESS, DEPOSIT_AMOUNT, txParams],
      { value: SIGNATURE_DEPOSIT, account: d.requester.account }
    );
    const receipt = await d.publicClient.waitForTransactionReceipt({
      hash: txHash,
    });

    const [initiated] = parseEventLogs({
      abi: d.vault.abi,
      logs: receipt.logs,
      eventName: 'DepositInitiated',
    });
    const [signEvent] = parseEventLogs({
      abi: d.chainSignatures.abi,
      logs: receipt.logs,
      eventName: 'SignBidirectional',
    });

    // The vault contract is the sender/predecessor; the user address is the path.
    assert.equal(
      getAddress(signEvent.args.sender),
      getAddress(d.vault.address)
    );
    assert.equal(signEvent.args.path, userPath);
    assert.equal(signEvent.args.caip2Id, 'eip155:1');

    // The on-chain EVMTransactionLib RLP must match viem's serialization exactly,
    // transferring to the vault's destination-chain address.
    const destinationTx = expectedTransferTx(
      d.vaultEvmAddress,
      DEPOSIT_AMOUNT,
      txParams
    );
    assert.equal(
      signEvent.args.serializedTransaction,
      serializeTransaction(destinationTx)
    );

    // The on-chain request id must match the ecosystem formula.
    assert.equal(
      initiated.args.requestId,
      generateBidirectionalRequestId(
        d.vault.address,
        vaultRequestArgs(signEvent.args.serializedTransaction, userPath)
      )
    );
    const requestId = initiated.args.requestId;

    // 2. The mock MPC signs the destination tx with the user's deposit key.
    const txSignature = mpcSignDigest(
      d.vault.address,
      userPath,
      keccak256(signEvent.args.serializedTransaction)
    );
    await d.chainSignatures.write.respond(
      [[{ requestId, signature: txSignature }]],
      { account: d.responder.account }
    );

    // 3. The reconstructed signed tx broadcasts from the derived deposit address.
    const depositAddress = deriveChildAddress(d.vault.address, userPath);
    const signedTx = serializeTransaction(
      destinationTx,
      signatureStructToRsv(txSignature)
    );
    assert.equal(
      await recoverTransactionAddress({ serializedTransaction: signedTx }),
      depositAddress
    );

    // 4. The MPC reports the outcome; the user claims and is credited.
    const serializedOutput = ABI_BOOL_TRUE;
    const outcomeSignature = mpcSignDigest(
      d.vault.address,
      RESPONSE_KEY_PATH,
      computeResponseHash(requestId, serializedOutput)
    );
    await d.viem.assertions.emitWithArgs(
      d.vault.write.claimErc20(
        [requestId, serializedOutput, outcomeSignature],
        {
          account: d.responder.account,
        }
      ),
      d.vault,
      'DepositClaimed',
      [
        requestId,
        getAddress(d.requester.account.address),
        ERC20_ADDRESS,
        DEPOSIT_AMOUNT,
      ]
    );

    assert.equal(
      await d.vault.read.userBalances([
        d.requester.account.address,
        ERC20_ADDRESS,
      ]),
      DEPOSIT_AMOUNT
    );

    // 5. The pending entry is single-use: a second claim is rejected.
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.claimErc20(
        [requestId, serializedOutput, outcomeSignature],
        {
          account: d.responder.account,
        }
      ),
      d.vault,
      'UnknownRequest'
    );
  });

  void it('Rejects a claim whose outcome is signed by the wrong key', async () => {
    const d = await deployVault();
    const txHash = await d.vault.write.depositErc20(
      [ERC20_ADDRESS, DEPOSIT_AMOUNT, buildTxParams(0n)],
      { value: SIGNATURE_DEPOSIT, account: d.requester.account }
    );
    const receipt = await d.publicClient.waitForTransactionReceipt({
      hash: txHash,
    });
    const [initiated] = parseEventLogs({
      abi: d.vault.abi,
      logs: receipt.logs,
      eventName: 'DepositInitiated',
    });
    const requestId = initiated.args.requestId;

    // Signed with the user's deposit key instead of the response key.
    const forged = mpcSignDigest(
      d.vault.address,
      d.requester.account.address.toLowerCase(),
      computeResponseHash(requestId, ABI_BOOL_TRUE)
    );
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.claimErc20([requestId, ABI_BOOL_TRUE, forged], {
        account: d.responder.account,
      }),
      d.vault,
      'InvalidSignature'
    );
  });

  void it('Withdraws: debits optimistically, signs from the vault root key, completes', async () => {
    const d = await deployVault();
    await depositAndClaim(d);

    const recipient = d.responder.account.address;
    const txParams = buildTxParams(0n); // vault address nonce
    const txHash = await d.vault.write.withdrawErc20(
      [ERC20_ADDRESS, DEPOSIT_AMOUNT, recipient, txParams],
      { value: SIGNATURE_DEPOSIT, account: d.requester.account }
    );
    const receipt = await d.publicClient.waitForTransactionReceipt({
      hash: txHash,
    });

    // Optimistic debit.
    assert.equal(
      await d.vault.read.userBalances([
        d.requester.account.address,
        ERC20_ADDRESS,
      ]),
      0n
    );

    const [initiated] = parseEventLogs({
      abi: d.vault.abi,
      logs: receipt.logs,
      eventName: 'WithdrawalInitiated',
    });
    const [signEvent] = parseEventLogs({
      abi: d.chainSignatures.abi,
      logs: receipt.logs,
      eventName: 'SignBidirectional',
    });

    // Withdrawals sign from the vault's own key: path = "root".
    assert.equal(signEvent.args.path, ROOT_PATH);
    const destinationTx = expectedTransferTx(
      recipient,
      DEPOSIT_AMOUNT,
      txParams
    );
    assert.equal(
      signEvent.args.serializedTransaction,
      serializeTransaction(destinationTx)
    );
    assert.equal(
      initiated.args.requestId,
      generateBidirectionalRequestId(
        d.vault.address,
        vaultRequestArgs(signEvent.args.serializedTransaction, ROOT_PATH)
      )
    );
    const requestId = initiated.args.requestId;

    // The MPC signs with the vault root key; the signed tx broadcasts from
    // the vault's destination-chain address.
    const txSignature = mpcSignDigest(
      d.vault.address,
      ROOT_PATH,
      keccak256(signEvent.args.serializedTransaction)
    );
    const signedTx = serializeTransaction(
      destinationTx,
      signatureStructToRsv(txSignature)
    );
    assert.equal(
      await recoverTransactionAddress({ serializedTransaction: signedTx }),
      d.vaultEvmAddress
    );

    // Successful outcome: no refund.
    const serializedOutput = ABI_BOOL_TRUE;
    const outcomeSignature = mpcSignDigest(
      d.vault.address,
      RESPONSE_KEY_PATH,
      computeResponseHash(requestId, serializedOutput)
    );
    await d.viem.assertions.emitWithArgs(
      d.vault.write.completeWithdrawErc20(
        [requestId, serializedOutput, outcomeSignature],
        { account: d.responder.account }
      ),
      d.vault,
      'WithdrawalCompleted',
      [requestId, getAddress(d.requester.account.address), false]
    );
    assert.equal(
      await d.vault.read.userBalances([
        d.requester.account.address,
        ERC20_ADDRESS,
      ]),
      0n
    );
  });

  void it('Refunds a withdrawal when the destination transaction fails', async () => {
    const d = await deployVault();
    await depositAndClaim(d);

    const txHash = await d.vault.write.withdrawErc20(
      [
        ERC20_ADDRESS,
        DEPOSIT_AMOUNT,
        d.responder.account.address,
        buildTxParams(0n),
      ],
      { value: SIGNATURE_DEPOSIT, account: d.requester.account }
    );
    const receipt = await d.publicClient.waitForTransactionReceipt({
      hash: txHash,
    });
    const [initiated] = parseEventLogs({
      abi: d.vault.abi,
      logs: receipt.logs,
      eventName: 'WithdrawalInitiated',
    });
    const requestId = initiated.args.requestId;

    // Failed destination tx: 0xdeadbeef prefix (mirrors the MPC node's
    // process_failed_tx encoding).
    const serializedOutput = concatHex([ERROR_PREFIX, ABI_BOOL_TRUE]);
    const outcomeSignature = mpcSignDigest(
      d.vault.address,
      RESPONSE_KEY_PATH,
      computeResponseHash(requestId, serializedOutput)
    );
    await d.viem.assertions.emitWithArgs(
      d.vault.write.completeWithdrawErc20(
        [requestId, serializedOutput, outcomeSignature],
        { account: d.responder.account }
      ),
      d.vault,
      'WithdrawalCompleted',
      [requestId, getAddress(d.requester.account.address), true]
    );

    // The optimistically debited balance is restored.
    assert.equal(
      await d.vault.read.userBalances([
        d.requester.account.address,
        ERC20_ADDRESS,
      ]),
      DEPOSIT_AMOUNT
    );
  });

  void it('Rejects withdrawals exceeding the vault balance', async () => {
    const d = await deployVault();
    await depositAndClaim(d);

    await d.viem.assertions.revertWithCustomError(
      d.vault.write.withdrawErc20(
        [
          ERC20_ADDRESS,
          DEPOSIT_AMOUNT + 1n,
          d.responder.account.address,
          buildTxParams(0n),
        ],
        { value: SIGNATURE_DEPOSIT, account: d.requester.account }
      ),
      d.vault,
      'InsufficientBalance'
    );
  });

  void it('Guards initialization: owner-only, non-zero addresses, one-time', async () => {
    const { viem } = await network.getOrCreate();
    const [admin, requester] = await viem.getWalletClients();
    const chainSignatures = await viem.deployContract('ChainSignatures', [
      admin.account.address,
      SIGNATURE_DEPOSIT,
    ]);
    const vault = await viem.deployContract('Erc20Vault', [
      chainSignatures.address,
      admin.account.address,
    ]);
    const vaultEvmAddress = deriveChildAddress(vault.address, ROOT_PATH);
    const responseSigner = deriveChildAddress(vault.address, RESPONSE_KEY_PATH);

    // Only the owner may pin the derived addresses.
    await viem.assertions.revertWithCustomError(
      vault.write.initialize([vaultEvmAddress, responseSigner], {
        account: requester.account,
      }),
      vault,
      'OwnableUnauthorizedAccount'
    );

    // Zero addresses are rejected for both keys.
    await viem.assertions.revertWithCustomError(
      vault.write.initialize([zeroAddress, responseSigner]),
      vault,
      'InvalidAddress'
    );
    await viem.assertions.revertWithCustomError(
      vault.write.initialize([vaultEvmAddress, zeroAddress]),
      vault,
      'InvalidAddress'
    );

    // Pinning is one-time.
    await vault.write.initialize([vaultEvmAddress, responseSigner]);
    await viem.assertions.revertWithCustomError(
      vault.write.initialize([vaultEvmAddress, responseSigner]),
      vault,
      'AlreadyInitialized'
    );
  });

  void it('Rejects deposits of the zero token address', async () => {
    const d = await deployVault();

    // EVMTransactionLib encodes to == 0 as contract creation, which must not
    // be expressible through the vault.
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.depositErc20(
        [zeroAddress, DEPOSIT_AMOUNT, buildTxParams(0n)],
        { value: SIGNATURE_DEPOSIT, account: d.requester.account }
      ),
      d.vault,
      'InvalidAddress'
    );
  });

  void it('Rejects duplicate requests while the identical request is pending', async () => {
    const d = await deployVault();

    // Identical deposit params (same nonce) produce the same request id.
    await initiateDeposit(d);
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.depositErc20(
        [ERC20_ADDRESS, DEPOSIT_AMOUNT, buildTxParams(0n)],
        { value: SIGNATURE_DEPOSIT, account: d.requester.account }
      ),
      d.vault,
      'DuplicateRequest'
    );
  });

  void it('Rejects duplicate withdrawal requests (balance debit is rolled back)', async () => {
    const d = await deployVault();
    await depositAndClaim(d);

    // Two half-balance withdrawals with identical destination params collide
    // on the same request id; the second reverts and its debit unwinds.
    const half = DEPOSIT_AMOUNT / 2n;
    await d.vault.write.withdrawErc20(
      [ERC20_ADDRESS, half, d.responder.account.address, buildTxParams(0n)],
      { value: SIGNATURE_DEPOSIT, account: d.requester.account }
    );
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.withdrawErc20(
        [ERC20_ADDRESS, half, d.responder.account.address, buildTxParams(0n)],
        { value: SIGNATURE_DEPOSIT, account: d.requester.account }
      ),
      d.vault,
      'DuplicateRequest'
    );
    assert.equal(
      await d.vault.read.userBalances([
        d.requester.account.address,
        ERC20_ADDRESS,
      ]),
      DEPOSIT_AMOUNT - half
    );
  });

  void it('Rejects withdrawals to the zero recipient', async () => {
    const d = await deployVault();

    await d.viem.assertions.revertWithCustomError(
      d.vault.write.withdrawErc20(
        [ERC20_ADDRESS, DEPOSIT_AMOUNT, zeroAddress, buildTxParams(0n)],
        { value: SIGNATURE_DEPOSIT, account: d.requester.account }
      ),
      d.vault,
      'InvalidAddress'
    );
  });

  void it('Rejects claims of failed deposits, keeping the pending entry intact', async () => {
    const d = await deployVault();
    const requestId = await initiateDeposit(d);

    // Failed destination transaction: 0xdeadbeef prefix.
    const failedOutput = concatHex([ERROR_PREFIX, ABI_BOOL_TRUE]);
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.claimErc20(
        [requestId, failedOutput, outcomeSignature(d, requestId, failedOutput)],
        { account: d.responder.account }
      ),
      d.vault,
      'DepositFailed'
    );

    // Transfer executed but returned false.
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.claimErc20(
        [
          requestId,
          ABI_BOOL_FALSE,
          outcomeSignature(d, requestId, ABI_BOOL_FALSE),
        ],
        { account: d.responder.account }
      ),
      d.vault,
      'TransferReturnedFalse'
    );

    // Malformed outputs: wrong length, and a word that is neither 0 nor 1.
    const shortOutput: Hex = `0x${'00'.repeat(31)}`;
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.claimErc20(
        [requestId, shortOutput, outcomeSignature(d, requestId, shortOutput)],
        { account: d.responder.account }
      ),
      d.vault,
      'InvalidOutput'
    );
    const twoOutput: Hex = `0x${'2'.padStart(64, '0')}`;
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.claimErc20(
        [requestId, twoOutput, outcomeSignature(d, requestId, twoOutput)],
        { account: d.responder.account }
      ),
      d.vault,
      'InvalidOutput'
    );

    // A recovery id outside {0, 1} is rejected before ecrecover.
    const badRecovery = {
      ...outcomeSignature(d, requestId, ABI_BOOL_TRUE),
      recoveryId: 2,
    };
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.claimErc20([requestId, ABI_BOOL_TRUE, badRecovery], {
        account: d.responder.account,
      }),
      d.vault,
      'InvalidSignature'
    );

    // Every rejected claim rolled back, so the pending entry survives and a
    // genuine success outcome still credits the balance.
    await d.vault.write.claimErc20(
      [requestId, ABI_BOOL_TRUE, outcomeSignature(d, requestId, ABI_BOOL_TRUE)],
      { account: d.responder.account }
    );
    assert.equal(
      await d.vault.read.userBalances([
        d.requester.account.address,
        ERC20_ADDRESS,
      ]),
      DEPOSIT_AMOUNT
    );
  });

  void it('Rejects withdrawal completions with forged signatures or replayed outcomes', async () => {
    const d = await deployVault();
    await depositAndClaim(d);

    const txHash = await d.vault.write.withdrawErc20(
      [
        ERC20_ADDRESS,
        DEPOSIT_AMOUNT,
        d.responder.account.address,
        buildTxParams(0n),
      ],
      { value: SIGNATURE_DEPOSIT, account: d.requester.account }
    );
    const receipt = await d.publicClient.waitForTransactionReceipt({
      hash: txHash,
    });
    const [initiated] = parseEventLogs({
      abi: d.vault.abi,
      logs: receipt.logs,
      eventName: 'WithdrawalInitiated',
    });
    const requestId = initiated.args.requestId;

    // Outcome signed with the vault root key instead of the response key.
    const forged = mpcSignDigest(
      d.vault.address,
      ROOT_PATH,
      computeResponseHash(requestId, ABI_BOOL_TRUE)
    );
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.completeWithdrawErc20([requestId, ABI_BOOL_TRUE, forged], {
        account: d.responder.account,
      }),
      d.vault,
      'InvalidSignature'
    );

    // Genuine outcome completes; the pending entry is single-use.
    await d.vault.write.completeWithdrawErc20(
      [requestId, ABI_BOOL_TRUE, outcomeSignature(d, requestId, ABI_BOOL_TRUE)],
      { account: d.responder.account }
    );
    await d.viem.assertions.revertWithCustomError(
      d.vault.write.completeWithdrawErc20(
        [
          requestId,
          ABI_BOOL_TRUE,
          outcomeSignature(d, requestId, ABI_BOOL_TRUE),
        ],
        { account: d.responder.account }
      ),
      d.vault,
      'UnknownRequest'
    );
  });

  void it('Refunds a withdrawal whose transfer returned false', async () => {
    const d = await deployVault();
    await depositAndClaim(d);

    const txHash = await d.vault.write.withdrawErc20(
      [
        ERC20_ADDRESS,
        DEPOSIT_AMOUNT,
        d.responder.account.address,
        buildTxParams(0n),
      ],
      { value: SIGNATURE_DEPOSIT, account: d.requester.account }
    );
    const receipt = await d.publicClient.waitForTransactionReceipt({
      hash: txHash,
    });
    const [initiated] = parseEventLogs({
      abi: d.vault.abi,
      logs: receipt.logs,
      eventName: 'WithdrawalInitiated',
    });
    const requestId = initiated.args.requestId;

    // The destination transfer executed but returned false: refund.
    await d.viem.assertions.emitWithArgs(
      d.vault.write.completeWithdrawErc20(
        [
          requestId,
          ABI_BOOL_FALSE,
          outcomeSignature(d, requestId, ABI_BOOL_FALSE),
        ],
        { account: d.responder.account }
      ),
      d.vault,
      'WithdrawalCompleted',
      [requestId, getAddress(d.requester.account.address), true]
    );
    assert.equal(
      await d.vault.read.userBalances([
        d.requester.account.address,
        ERC20_ADDRESS,
      ]),
      DEPOSIT_AMOUNT
    );
  });
});
